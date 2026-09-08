"""Owner-scoped watch rules, deduplicated inbox, Atom feeds, and retryable delivery."""
from __future__ import annotations
import hashlib
import hmac
import json
import re
import secrets
import smtplib
import ssl
import time
import uuid
from datetime import datetime,timedelta,timezone
from email.message import EmailMessage
from xml.sax.saxutils import escape
from accounts import AccessError,token_hash
from config import setting
from core import now,safe_url
from prioritization import priority
from safe_http import request,validate_url
from workspace import encoded,identity


class Alerts:
    def __init__(self,workspace):
        self.workspace,self.accounts,self.catalog = workspace,workspace.accounts,workspace.catalog
        self.last_evaluation = 0
        with self.accounts.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS watch_rules (
                    id TEXT PRIMARY KEY,owner INTEGER NOT NULL REFERENCES users(id),name TEXT NOT NULL,
                    scope TEXT NOT NULL,selector TEXT NOT NULL,trigger TEXT NOT NULL,threshold INTEGER NOT NULL,
                    channel TEXT NOT NULL,target TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,
                    created TEXT NOT NULL,last_evaluated TEXT,error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_watch_rules_owner ON watch_rules(owner,enabled);
                CREATE TABLE IF NOT EXISTS watch_state (
                    rule_id TEXT NOT NULL REFERENCES watch_rules(id) ON DELETE CASCADE,item_key TEXT NOT NULL,
                    payload TEXT NOT NULL,episode INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(rule_id,item_key)
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,owner INTEGER NOT NULL REFERENCES users(id),rule_id TEXT,
                    dedupe TEXT NOT NULL UNIQUE,title TEXT NOT NULL,payload TEXT NOT NULL,created TEXT NOT NULL,read INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_owner_time ON alerts(owner,created);
                CREATE TABLE IF NOT EXISTS deliveries (
                    id INTEGER PRIMARY KEY,alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    channel TEXT NOT NULL,target TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,next_attempt REAL NOT NULL DEFAULT 0,error TEXT,delivered TEXT,
                    UNIQUE(alert_id,channel)
                );
                CREATE INDEX IF NOT EXISTS idx_deliveries_queue ON deliveries(status,next_attempt);
                CREATE TABLE IF NOT EXISTS atom_tokens (owner INTEGER PRIMARY KEY REFERENCES users(id),digest TEXT NOT NULL UNIQUE);
            """)

    def rules(self,owner):
        with self.accounts.connection() as db:
            rows = [dict(r) for r in db.execute("SELECT * FROM watch_rules WHERE owner=? ORDER BY created DESC",(owner,))]
        for row in rows:
            if row["channel"]=="webhook":
                from urllib.parse import urlsplit
                row["target"] = urlsplit(row["target"]).hostname or "Configured webhook"
        return rows

    def create(self,owner,data):
        if not isinstance(data,dict):
            raise ValueError("Invalid watch rule.")
        scope,selector = data.get("scope","inventory"),str(data.get("selector","")).strip()
        trigger,channel = data.get("trigger","either"),data.get("channel","inapp")
        threshold,name,target = data.get("threshold",70),data.get("name",""),data.get("target","")
        if scope not in {"inventory","vendor","product","package","cve"} or trigger not in {"kev","priority","either"}:
            raise ValueError("Choose a supported watch scope and trigger.")
        if scope!="inventory" and not 2<=len(selector)<=200:
            raise ValueError("Enter a vendor, product, package, or CVE to follow.")
        if channel not in {"inapp","webhook","email"} or type(threshold) is not int or not 0<=threshold<=100:
            raise ValueError("Choose a delivery channel and a priority threshold from 0 to 100.")
        if not isinstance(name,str) or not 1<=len(name.strip())<=100:
            raise ValueError("Give the watch rule a name.")
        if channel=="webhook":
            validate_url(target)
        elif channel=="email":
            if not isinstance(target,str) or not re.fullmatch(r"[^\s<>@\r\n]+@[^\s<>@\r\n]+\.[^\s<>@\r\n]+",target) or len(target)>254:
                raise ValueError("Enter one valid recipient email address.")
            if not setting("SMTP_HOST") or not setting("SMTP_FROM"):
                raise ValueError("Configure SMTP_HOST and SMTP_FROM on the server before enabling email delivery.")
        else:
            target = ""
        identifier = uuid.uuid4().hex
        with self.accounts.connection() as db:
            if scope=="inventory" and selector:
                self.workspace.owned(db,owner,selector)
            if db.execute("SELECT COUNT(*) FROM watch_rules WHERE owner=?",(owner,)).fetchone()[0]>=30:
                raise ValueError("An account can have up to 30 watch rules.")
            db.execute("INSERT INTO watch_rules(id,owner,name,scope,selector,trigger,threshold,channel,target,created) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (identifier,owner,name.strip(),scope,selector,trigger,threshold,channel,target,now()))
            rule = dict(db.execute("SELECT * FROM watch_rules WHERE id=?",(identifier,)).fetchone())
        # Establish a baseline immediately. Existing catalog entries do not cause a launch-time flood.
        self.evaluate_rule(rule,baseline=True)
        return {"id":identifier,"baselineEstablished":True}

    def configure(self,owner,identifier,action):
        with self.accounts.connection() as db:
            row = db.execute("SELECT * FROM watch_rules WHERE id=? AND owner=?",(identifier,owner)).fetchone()
            if not row:
                raise AccessError("Watch rule not found.",404)
            if action=="delete":
                db.execute("DELETE FROM watch_rules WHERE id=?",(identifier,))
            elif action in {"pause","resume"}:
                db.execute("UPDATE watch_rules SET enabled=?,error=NULL WHERE id=?",(int(action=="resume"),identifier))
            else:
                raise ValueError("Choose pause, resume, or delete.")
        return {"updated":True}

    def candidates(self,rule):
        if rule["scope"]=="inventory":
            offset = 0
            while True:
                result = self.workspace.findings(rule["owner"],rule["selector"] or None,True,offset,1000)
                for finding in result["findings"]:
                    yield {"key":finding["id"],"id":finding["recordId"],"title":finding["title"],"kev":finding["kev"],
                           "score":finding["priority"]["score"],"profile":finding["priority"]["profile"],
                           "present":bool(finding["present"]) and finding["status"]!="resolved", "url":finding["url"],
                           "inventory":finding["inventory_name"],"package":finding["component"]["name"],"version":finding["component"]["version"]}
                offset += len(result["findings"])
                if offset>=result["total"] or not result["findings"]:
                    break
        else:
            selector = rule["selector"].casefold()
            weights = self.workspace.profile(rule["owner"])["weights"]
            # Stream records; no materialized full-catalog copy per watch.
            for record in self.catalog.iter_records():
                scope = rule["scope"]
                match = selector in str(record.get(scope,"")).casefold() if scope in {"vendor","product"} else (
                    record["id"].casefold()==selector or selector in [a.casefold() for a in record.get("aliases",[])] if scope=="cve" else
                    any(selector in p.get("name","").casefold() for p in record.get("packages",[])))
                if not match:
                    continue
                score = priority(record,weights)
                yield {"key":record["id"],"id":record["id"],"title":record["title"],"kev":record["kev"],
                       "score":score["score"],"profile":score["profile"],"present":not record["withdrawn"],
                       "url":next((s["url"] for s in record["sources"] if safe_url(s["url"])),""),"vendor":record["vendor"]}

    def evaluate_rule(self,rule,baseline=False):
        stamp = now()
        for item in self.candidates(rule):
            eligible_kev = item["present"] and item["kev"] and rule["trigger"] in {"kev","either"}
            eligible_priority = item["present"] and item["score"]>=rule["threshold"] and rule["trigger"] in {"priority","either"}
            current = {"kev":bool(eligible_kev),"priority":bool(eligible_priority),"profile":item["profile"]}
            with self.accounts.connection() as db:
                previous = db.execute("SELECT * FROM watch_state WHERE rule_id=? AND item_key=?",(rule["id"],item["key"])).fetchone()
                before = json.loads(previous["payload"]) if previous else {}
                episode = previous["episode"] if previous else 0
                reasons = []
                if not baseline:
                    if eligible_kev and not before.get("kev"):
                        reasons.append("Known exploitation matches this watch")
                    if eligible_priority and not before.get("priority") and (not before or before.get("profile")==current["profile"]):
                        reasons.append("Priority reached the configured threshold")
                if reasons:
                    cutoff = (datetime.now(timezone.utc)-timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00","Z")
                    if db.execute("SELECT COUNT(*) FROM alerts WHERE owner=? AND created>=?",(rule["owner"],cutoff)).fetchone()[0]>=200:
                        raise ValueError("The daily 200-alert limit was reached. Narrow this watch or review it tomorrow.")
                    episode += 1
                    notification,dedupe = uuid.uuid4().hex,identity(rule["id"],item["key"],episode)
                    title = item["id"]+" · "+reasons[0]
                    payload = {**item,"reasons":reasons,"watch":rule["name"],"observedAt":stamp}
                    db.execute("INSERT OR IGNORE INTO alerts(id,owner,rule_id,dedupe,title,payload,created) VALUES(?,?,?,?,?,?,?)",
                               (notification,rule["owner"],rule["id"],dedupe,title,encoded(payload),stamp))
                    if rule["channel"]!="inapp":
                        db.execute("INSERT OR IGNORE INTO deliveries(alert_id,channel,target) VALUES(?,?,?)",(notification,rule["channel"],rule["target"]))
                db.execute("INSERT INTO watch_state VALUES(?,?,?,?) ON CONFLICT(rule_id,item_key) DO UPDATE SET payload=excluded.payload,episode=excluded.episode",
                           (rule["id"],item["key"],encoded(current),episode))
        with self.accounts.connection() as db:
            db.execute("UPDATE watch_rules SET last_evaluated=?,error=NULL WHERE id=?",(stamp,rule["id"]))

    def evaluate(self,force=False):
        if not force and time.monotonic()-self.last_evaluation<60:
            return False
        self.last_evaluation = time.monotonic()
        with self.accounts.connection() as db:
            rules = [dict(r) for r in db.execute("SELECT r.* FROM watch_rules r JOIN users u ON u.id=r.owner WHERE r.enabled=1 AND u.disabled=0")]
        for rule in rules:
            try:
                self.evaluate_rule(rule)
            except Exception as exc:
                with self.accounts.connection() as db:
                    db.execute("UPDATE watch_rules SET error=? WHERE id=?",(str(exc)[:300],rule["id"]))
        return True

    def inbox(self,owner,offset=0):
        with self.accounts.connection() as db:
            rows = [dict(r) for r in db.execute("SELECT * FROM alerts WHERE owner=? ORDER BY created DESC,id LIMIT 100 OFFSET ?",(owner,max(0,int(offset))))]
            unread = db.execute("SELECT COUNT(*) FROM alerts WHERE owner=? AND read=0",(owner,)).fetchone()[0]
            total = db.execute("SELECT COUNT(*) FROM alerts WHERE owner=?",(owner,)).fetchone()[0]
            for row in rows:
                row["payload"] = json.loads(row["payload"])
                row["delivery"] = [dict(r) for r in db.execute("SELECT id,channel,status,attempts,error,delivered FROM deliveries WHERE alert_id=?",(row["id"],))]
        return {"alerts":rows,"unread":unread,"total":total}

    def mark_read(self,owner,identifier=None):
        with self.accounts.connection() as db:
            if identifier:
                db.execute("UPDATE alerts SET read=1 WHERE owner=? AND id=?",(owner,identifier))
            else:
                db.execute("UPDATE alerts SET read=1 WHERE owner=?",(owner,))
        return {"updated":True}

    def issue_feed(self,owner):
        raw = secrets.token_urlsafe(32)
        with self.accounts.connection() as db:
            db.execute("INSERT INTO atom_tokens VALUES(?,?) ON CONFLICT(owner) DO UPDATE SET digest=excluded.digest",(owner,token_hash(raw)))
        return {"path":"/feeds/"+raw+".atom"}

    def atom(self,raw):
        with self.accounts.connection() as db:
            user = db.execute("SELECT t.owner FROM atom_tokens t JOIN users u ON u.id=t.owner WHERE t.digest=? AND u.disabled=0",(token_hash(raw),)).fetchone()
        if not user:
            raise AccessError("Feed not found.",404)
        rows = self.inbox(user[0])["alerts"]
        entries = []
        for row in rows:
            item = row["payload"]
            url = item.get("url")
            link = '<link href="'+escape(url,{'"':'&quot;'})+'"/>' if safe_url(url) else ''
            entries.append('<entry><id>urn:mastermonk:'+row["id"]+'</id><title>'+escape(row["title"])+
                           '</title><updated>'+row["created"]+'</updated>'+link+'<content type="text">'+
                           escape(item.get("title","")+" — "+"; ".join(item.get("reasons",[])))+'</content></entry>')
        return '<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom"><id>urn:mastermonk:watch-feed</id><title>MasterMonk watch updates</title><updated>'+(
            rows[0]["created"] if rows else now())+'</updated><author><name>MasterMonk</name></author>'+''.join(entries)+'</feed>'

    def deliver_one(self,sender=None):
        with self.accounts.connection() as db:
            row = db.execute("SELECT d.*,a.title,a.payload,a.owner FROM deliveries d JOIN alerts a ON a.id=d.alert_id JOIN users u ON u.id=a.owner WHERE u.disabled=0 AND d.status='pending' AND d.next_attempt<=? ORDER BY d.id LIMIT 1",(time.time(),)).fetchone()
            if not row:
                return False
            row = dict(row)
            # A durable delay prevents another process claiming this delivery immediately.
            db.execute("UPDATE deliveries SET next_attempt=? WHERE id=?",(time.time()+120,row["id"]))
        try:
            (sender or self._send)(row)
            with self.accounts.connection() as db:
                db.execute("UPDATE deliveries SET status='delivered',attempts=attempts+1,error=NULL,delivered=? WHERE id=?",(now(),row["id"]))
        except Exception as exc:
            attempts = row["attempts"]+1
            with self.accounts.connection() as db:
                db.execute("UPDATE deliveries SET status=?,attempts=?,error=?,next_attempt=? WHERE id=?",
                           ("failed" if attempts>=6 else "pending",attempts,type(exc).__name__+": delivery failed",time.time()+min(3600,60*2**attempts),row["id"]))
        return True

    def _send(self,row):
        item = json.loads(row["payload"])
        text = row["title"]+"\n"+item.get("title","")+"\n"+item.get("url","")
        if row["channel"]=="webhook":
            body = encoded({"id":row["alert_id"],"type":"mastermonk.watch","text":text,"event":item}).encode()
            headers = {"Content-Type":"application/json","X-MasterMonk-Event-ID":row["alert_id"]}
            secret = setting("WEBHOOK_SECRET")
            if secret:
                headers["X-MasterMonk-Signature"] = "sha256="+hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()
            request(row["target"],body,headers,max_bytes=65536)
        elif row["channel"]=="email":
            message = EmailMessage()
            message["Subject"],message["From"],message["To"] = row["title"],setting("SMTP_FROM"),row["target"]
            message["Message-ID"] = "<"+row["alert_id"]+"@mastermonk>"
            message.set_content(text)
            host,port = setting("SMTP_HOST"),int(setting("SMTP_PORT","587"))
            context = ssl.create_default_context()
            implicit_tls = port==465 or setting("SMTP_SSL","0")=="1"
            connection = smtplib.SMTP_SSL(host,port,timeout=15,context=context) if implicit_tls else smtplib.SMTP(host,port,timeout=15)
            with connection:
                if not implicit_tls:
                    connection.starttls(context=context)
                if setting("SMTP_USER"):
                    connection.login(setting("SMTP_USER"),setting("SMTP_PASSWORD"))
                connection.send_message(message)
