"""Private inventories and remediation state over a shared public catalog."""
from __future__ import annotations
import hashlib
import json
import math
import time
import uuid
from accounts import AccessError
from core import now
from prioritization import priority, validate_weights


def encoded(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False)


def identity(*parts):
    return hashlib.sha256(encoded(parts).encode()).hexdigest()[:32]


class Workspace:
    def __init__(self,accounts,catalog):
        self.accounts,self.catalog = accounts,catalog
        with accounts.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS inventories (
                    id TEXT PRIMARY KEY,owner INTEGER NOT NULL REFERENCES users(id),name TEXT NOT NULL,
                    source_kind TEXT NOT NULL,fingerprint TEXT NOT NULL,metadata TEXT NOT NULL,
                    exposed INTEGER NOT NULL DEFAULT 0,criticality INTEGER NOT NULL DEFAULT 3,
                    created TEXT NOT NULL,updated TEXT NOT NULL,scan_state TEXT NOT NULL DEFAULT 'idle',
                    generation TEXT,last_scan TEXT,last_complete TEXT,auto_refresh INTEGER NOT NULL DEFAULT 1,
                    paused INTEGER NOT NULL DEFAULT 0,error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_inventories_owner ON inventories(owner,updated);
                CREATE TABLE IF NOT EXISTS inventory_components (
                    id TEXT PRIMARY KEY,inventory_id TEXT NOT NULL REFERENCES inventories(id) ON DELETE CASCADE,
                    payload TEXT NOT NULL,status TEXT NOT NULL,page_token TEXT,pending_matches TEXT NOT NULL DEFAULT '[]',
                    checked TEXT,error TEXT,page_count INTEGER NOT NULL DEFAULT 0,active INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_inventory_components_status ON inventory_components(inventory_id,status);
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,inventory_id TEXT NOT NULL REFERENCES inventories(id) ON DELETE CASCADE,
                    started TEXT NOT NULL,completed TEXT,status TEXT NOT NULL,summary TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_scans_inventory ON scans(inventory_id,started);
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,inventory_id TEXT NOT NULL REFERENCES inventories(id) ON DELETE CASCADE,
                    component_id TEXT NOT NULL REFERENCES inventory_components(id) ON DELETE CASCADE,
                    advisory_id TEXT NOT NULL,payload TEXT NOT NULL,present INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'open',note TEXT NOT NULL DEFAULT '',first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,
                    last_scan TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_inventory ON findings(inventory_id,present,status);
                CREATE TABLE IF NOT EXISTS finding_events (
                    id INTEGER PRIMARY KEY,owner INTEGER NOT NULL REFERENCES users(id),finding_id TEXT NOT NULL,
                    kind TEXT NOT NULL,observed_at TEXT NOT NULL,payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_finding_events_owner_time ON finding_events(owner,observed_at);
                CREATE TABLE IF NOT EXISTS advisory_cache (id TEXT PRIMARY KEY,payload TEXT NOT NULL,modified TEXT,fetched REAL NOT NULL);
            """)

            if "active" not in {r[1] for r in db.execute("PRAGMA table_info(inventory_components)")}:
                db.execute("ALTER TABLE inventory_components ADD COLUMN active INTEGER NOT NULL DEFAULT 1")

    def owned(self,db,owner,identifier):
        row = db.execute("SELECT * FROM inventories WHERE id=? AND owner=?",(identifier,owner)).fetchone()
        if not row:
            raise AccessError("Inventory not found.",404)
        return dict(row)

    @staticmethod
    def asset_settings(exposed,criticality):
        if type(exposed) is not bool or type(criticality) is not int or not 1<=criticality<=5:
            raise ValueError("Choose internet exposure and an asset importance from 1 to 5.")

    def add(self,owner,name,parsed,exposed=False,criticality=3):
        self.asset_settings(exposed,criticality)
        if not isinstance(name,str) or not 1<=len(name.strip())<=100:
            raise ValueError("Give the inventory a name of 1–100 characters.")
        identifier,stamp = uuid.uuid4().hex,now()
        metadata = {k:v for k,v in parsed.items() if k not in {"components","fingerprint"}}
        with self.accounts.connection() as db:
            if db.execute("SELECT COUNT(*) FROM inventories WHERE owner=?",(owner,)).fetchone()[0]>=100:
                raise ValueError("An account can hold up to 100 inventories.")
            db.execute("INSERT INTO inventories(id,owner,name,source_kind,fingerprint,metadata,exposed,criticality,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (identifier,owner,name.strip(),parsed["kind"],parsed["fingerprint"],encoded(metadata),int(exposed),criticality,stamp,stamp))
            for component in parsed["components"]:
                cid = identity(identifier,component["ecosystem"],component["name"],component["version"],component.get("purl"))
                db.execute("INSERT INTO inventory_components(id,inventory_id,payload,status) VALUES(?,?,?,?)",
                           (cid,identifier,encoded(component),"skipped" if component.get("skipReason") else "unchecked"))
        return self.detail(owner,identifier)

    def replace(self,owner,identifier,parsed):
        stamp = now()
        with self.accounts.connection() as db:
            inventory = self.owned(db,owner,identifier)
            if inventory["scan_state"] in {"queued","running"}:
                raise AccessError("Wait for the current scan to finish before replacing its manifest.",409)
            db.execute("UPDATE inventory_components SET active=0 WHERE inventory_id=?",(identifier,))
            for component in parsed["components"]:
                cid = identity(identifier,component["ecosystem"],component["name"],component["version"],component.get("purl"))
                db.execute("""INSERT INTO inventory_components(id,inventory_id,payload,status) VALUES(?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,status=excluded.status,active=1""",
                    (cid,identifier,encoded(component),"skipped" if component.get("skipReason") else "unchecked"))
            removed = db.execute("""SELECT f.id FROM findings f JOIN inventory_components c ON c.id=f.component_id
                WHERE f.inventory_id=? AND c.active=0 AND f.present=1""",(identifier,)).fetchall()
            for finding in removed:
                db.execute("UPDATE findings SET present=0,status='resolved',last_seen=? WHERE id=?",(stamp,finding[0]))
                db.execute("INSERT INTO finding_events(owner,finding_id,kind,observed_at,payload) VALUES(?,?,?,?,?)",
                           (owner,finding[0],"component_removed",stamp,encoded({"inventory":identifier})))
            metadata = {k:v for k,v in parsed.items() if k not in {"components","fingerprint"}}
            db.execute("UPDATE inventories SET metadata=?,fingerprint=?,source_kind=?,updated=?,scan_state='idle' WHERE id=?",
                       (encoded(metadata),parsed["fingerprint"],parsed["kind"],stamp,identifier))
        self.configure(owner,identifier,"scan")
        return self.detail(owner,identifier)

    def _summary(self,db,row):
        counts = dict(db.execute("""SELECT COUNT(*) components,
            COALESCE(SUM(status='checked'),0) checked,COALESCE(SUM(status='pending'),0) pending,
            COALESCE(SUM(status='skipped'),0) skipped,COALESCE(SUM(status='error'),0) errors
            FROM inventory_components WHERE inventory_id=? AND active=1""",(row["id"],)).fetchone())
        findings = dict(db.execute("SELECT COUNT(*) findings,COALESCE(SUM(status!='resolved'),0) open FROM findings WHERE inventory_id=? AND present=1",(row["id"],)).fetchone())
        result = {**dict(row),**counts,**findings,"metadata":json.loads(row["metadata"])}
        result["exposed"] = bool(result["exposed"])
        return result

    def list(self,owner):
        with self.accounts.connection() as db:
            return [self._summary(db,row) for row in db.execute("SELECT * FROM inventories WHERE owner=? ORDER BY updated DESC",(owner,)).fetchall()]

    def detail(self,owner,identifier,offset=0,limit=100):
        offset,limit = max(0,int(offset)),max(1,min(500,int(limit)))
        with self.accounts.connection() as db:
            row = self.owned(db,owner,identifier)
            components = [{**json.loads(r["payload"]),**{k:r[k] for k in ("id","status","checked","error")}}
                          for r in db.execute("SELECT * FROM inventory_components WHERE inventory_id=? AND active=1 ORDER BY id LIMIT ? OFFSET ?",(identifier,limit,offset))]
            scans = [dict(r) for r in db.execute("SELECT id,started,completed,status,summary FROM scans WHERE inventory_id=? ORDER BY started DESC LIMIT 12",(identifier,))]
            return {"inventory":self._summary(db,row),"components":components,"scans":scans,"offset":offset,"limit":limit}

    def configure(self,owner,identifier,action,values=None):
        values = values or {}
        with self.accounts.connection() as db:
            row = self.owned(db,owner,identifier)
            if action=="delete":
                db.execute("DELETE FROM inventories WHERE id=?",(identifier,))
                return {"deleted":True}
            if action=="settings":
                self.asset_settings(values.get("exposed"),values.get("criticality"))
                db.execute("UPDATE inventories SET exposed=?,criticality=?,auto_refresh=?,updated=? WHERE id=?",
                           (int(values["exposed"]),values["criticality"],int(values.get("auto_refresh",True) is True),now(),identifier))
            elif action=="pause":
                db.execute("UPDATE inventories SET paused=1 WHERE id=?",(identifier,))
            elif action=="resume":
                db.execute("UPDATE inventories SET paused=0 WHERE id=?",(identifier,))
            elif action=="scan":
                if row["scan_state"] in {"queued","running"}:
                    return {"queued":True,"scan":row["generation"]}
                scan,stamp = uuid.uuid4().hex,now()
                db.execute("UPDATE inventories SET scan_state='queued',generation=?,paused=0,error=NULL,updated=? WHERE id=?",(scan,stamp,identifier))
                db.execute("UPDATE inventory_components SET status='pending',page_token=NULL,pending_matches='[]',page_count=0,error=NULL WHERE inventory_id=? AND active=1 AND status!='skipped'",(identifier,))
                db.execute("INSERT INTO scans(id,inventory_id,started,status) VALUES(?,?,?,'queued')",(scan,identifier,stamp))
                return {"queued":True,"scan":scan}
            else:
                raise ValueError("Unknown inventory action.")
        return self.detail(owner,identifier)

    def queue_due(self):
        cutoff = time.time()-86400
        with self.accounts.connection() as db:
            rows = [dict(r) for r in db.execute("SELECT i.* FROM inventories i JOIN users u ON u.id=i.owner WHERE u.disabled=0 AND auto_refresh=1 AND paused=0 AND scan_state NOT IN ('queued','running') AND last_scan IS NOT NULL")]
        from datetime import datetime
        for row in rows:
            if datetime.fromisoformat(row["last_scan"].replace("Z","+00:00")).timestamp()<cutoff:
                self.configure(row["owner"],row["id"],"scan")

    def next_batch(self,limit=100):
        with self.accounts.connection() as db:
            row = db.execute("SELECT i.* FROM inventories i JOIN users u ON u.id=i.owner WHERE u.disabled=0 AND i.paused=0 AND i.scan_state IN ('queued','running') ORDER BY i.updated LIMIT 1").fetchone()
            if not row:
                return None,[]
            inventory = dict(row)
            db.execute("UPDATE inventories SET scan_state='running' WHERE id=?",(row["id"],))
            db.execute("UPDATE scans SET status='running' WHERE id=?",(row["generation"],))
            rows = [{**dict(r),"component":json.loads(r["payload"])} for r in db.execute("SELECT * FROM inventory_components WHERE inventory_id=? AND status='pending' ORDER BY id LIMIT ?",(row["id"],limit))]
            return inventory,rows

    def cache_get(self,identifier,modified=None):
        with self.accounts.connection() as db:
            row = db.execute("SELECT * FROM advisory_cache WHERE id=?",(identifier,)).fetchone()
        if row and time.time()-row["fetched"]<21600 and (not modified or (row["modified"] or "")>=modified):
            return json.loads(row["payload"])
        return None

    def cache_put(self,document):
        with self.accounts.connection() as db:
            db.execute("INSERT INTO advisory_cache VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,modified=excluded.modified,fetched=excluded.fetched",
                       (document["id"],encoded(document),document.get("modified"),time.time()))

    def commit_component(self,inventory,row,matches,findings,next_page=None,error=None):
        stamp = now()
        with self.accounts.connection() as db:
            current = db.execute("SELECT generation FROM inventories WHERE id=?",(inventory["id"],)).fetchone()
            if not current or current[0]!=inventory["generation"]:
                return
            if error:
                db.execute("UPDATE inventory_components SET status='error',error=? WHERE id=?",(str(error)[:300],row["id"]))
                return
            db.execute("UPDATE inventory_components SET pending_matches=?,page_token=?,page_count=page_count+1,status=?,checked=?,error=NULL WHERE id=?",
                       (encoded(matches),next_page,"pending" if next_page else "checked",stamp,row["id"]))
            if next_page:
                return
            seen = set()
            for finding in findings:
                fid = identity(inventory["id"],row["id"],finding["advisoryId"])
                seen.add(fid)
                previous = db.execute("SELECT * FROM findings WHERE id=?",(fid,)).fetchone()
                reopened = previous and (not previous["present"] or previous["status"]=="resolved")
                status = "open" if not previous or reopened else previous["status"]
                db.execute("""INSERT INTO findings(id,inventory_id,component_id,advisory_id,payload,status,first_seen,last_seen,last_scan)
                    VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,present=1,status=excluded.status,last_seen=excluded.last_seen,last_scan=excluded.last_scan""",
                    (fid,inventory["id"],row["id"],finding["advisoryId"],encoded(finding),status,stamp,stamp,inventory["generation"]))
                if not previous or reopened:
                    db.execute("INSERT INTO finding_events(owner,finding_id,kind,observed_at,payload) VALUES(?,?,?,?,?)",
                               (inventory["owner"],fid,"reopened" if reopened else "detected",stamp,encoded({"inventory":inventory["id"],"advisory":finding["advisoryId"]})))
            previous = db.execute("SELECT id FROM findings WHERE component_id=? AND present=1",(row["id"],)).fetchall()
            for old in previous:
                if old[0] not in seen:
                    db.execute("UPDATE findings SET present=0,status='resolved',last_seen=?,last_scan=? WHERE id=?",(stamp,inventory["generation"],old[0]))
                    db.execute("INSERT INTO finding_events(owner,finding_id,kind,observed_at,payload) VALUES(?,?,?,?,?)",
                               (inventory["owner"],old[0],"resolved",stamp,encoded({"inventory":inventory["id"]})))

    def finish_scan(self,inventory):
        with self.accounts.connection() as db:
            current = db.execute("SELECT * FROM inventories WHERE id=?",(inventory["id"],)).fetchone()
            if not current or current["generation"]!=inventory["generation"]:
                return False
            summary = self._summary(db,current)
            if summary["pending"]:
                return False
            complete = not summary["errors"] and not summary["skipped"] and summary["metadata"].get("complete",False)
            state = "complete" if complete else "partial"
            stamp = now()
            payload = {k:summary[k] for k in ("components","checked","skipped","errors","findings","open")}
            payload["complete"] = complete
            db.execute("UPDATE inventories SET scan_state=?,last_scan=?,last_complete=CASE WHEN ? THEN ? ELSE last_complete END,updated=? WHERE id=?",
                       (state,stamp,complete,stamp,stamp,inventory["id"]))
            db.execute("UPDATE scans SET status=?,completed=?,summary=? WHERE id=?",(state,stamp,encoded(payload),inventory["generation"]))
            return True

    def findings(self,owner,inventory_id=None,include_resolved=False,offset=0,limit=250):
        offset,limit = max(0,int(offset)),max(1,min(5000,int(limit)))
        weights = validate_weights(self.accounts.preferences(owner).get("weights"))
        condition = "i.owner=?"
        args = [owner]
        if inventory_id:
            condition += " AND i.id=?";args.append(inventory_id)
        if not include_resolved:
            condition += " AND f.present=1 AND f.status!='resolved'"
        def merged(payload,canonical):
            value,record = json.loads(payload),json.loads(canonical or "{}")
            for key in ("cvss","cvssSource","epss","epssDate","ransomware","vendor","product"):
                if record.get(key) is not None:
                    value[key] = record[key]
            if record.get("severity") not in (None,"Unknown"):
                value["severity"] = record["severity"]
            if record:
                value["kev"] = bool(record.get("kev"))
                value["sourceIds"] = sorted({source["id"] for source in record.get("sources",[])})
                value["references"] = value.get("references",[])+record.get("references",[])
            return value
        with self.accounts.connection() as db:
            if inventory_id:
                self.owned(db,owner,inventory_id)
            total = db.execute("SELECT COUNT(*) FROM findings f JOIN inventories i ON i.id=f.inventory_id WHERE "+condition,args).fetchone()[0]
            # Rank the whole matching set before pagination. The attached catalog contains
            # public records only; owner checks stay in the workspace query.
            db.execute("ATTACH DATABASE ? AS public_catalog",(self.catalog.path,))
            db.create_function("finding_rank",4,lambda payload,canonical,exposed,criticality:
                priority(merged(payload,canonical),weights,{"internet_exposed":bool(exposed),"criticality":criticality})["score"])
            query = """WITH enriched AS (
                SELECT f.*,i.name inventory_name,i.exposed,i.criticality,c.payload component,
                COALESCE((SELECT r.payload FROM public_catalog.records r
                    JOIN json_each(f.payload,'$.aliases') a ON r.id=a.value
                    ORDER BY r.is_kev DESC,r.priority DESC,r.id LIMIT 1),'{}') canonical
                FROM findings f JOIN inventories i ON i.id=f.inventory_id
                JOIN inventory_components c ON c.id=f.component_id WHERE """+condition+""")
                SELECT * FROM enriched ORDER BY finding_rank(payload,canonical,exposed,criticality) DESC,id LIMIT ? OFFSET ?"""
            rows = [dict(r) for r in db.execute(query,(*args,limit,offset))]
        result = []
        for row in rows:
            payload = merged(row.pop("payload"),row.pop("canonical"))
            component = json.loads(row.pop("component"))
            row.update(payload)
            row.update(component=component,priority=priority(payload,weights,{"internet_exposed":bool(row["exposed"]),"criticality":row["criticality"]}))
            result.append(row)
        return {"findings":result,"total":total,"offset":offset,"limit":limit}

    def remediate(self,owner,identifier,status,note=""):
        if status not in {"open","acknowledged","mitigating","resolved"} or not isinstance(note,str) or len(note)>2000:
            raise ValueError("Choose a valid remediation status and a note of at most 2,000 characters.")
        with self.accounts.connection() as db:
            row = db.execute("SELECT f.* FROM findings f JOIN inventories i ON i.id=f.inventory_id WHERE f.id=? AND i.owner=?",(identifier,owner)).fetchone()
            if not row:
                raise AccessError("Finding not found.",404)
            db.execute("UPDATE findings SET status=?,note=? WHERE id=?",(status,note,identifier))
            db.execute("INSERT INTO finding_events(owner,finding_id,kind,observed_at,payload) VALUES(?,?,?,?,?)",
                       (owner,identifier,"status_changed",now(),encoded({"before":row["status"],"after":status})))
        return {"updated":True}

    def export(self,owner,inventory_id):
        from manifests import cyclone_document
        with self.accounts.connection() as db:
            self.owned(db,owner,inventory_id)
            components = [json.loads(r[0]) for r in db.execute("SELECT payload FROM inventory_components WHERE inventory_id=? AND active=1 ORDER BY id",(inventory_id,))]
        return cyclone_document(components)

    def profile(self,owner,values=None):
        data = self.accounts.preferences(owner)
        if values is not None:
            if not isinstance(values,dict):
                raise ValueError("Invalid profile.")
            if "weights" in values:
                data["weights"] = validate_weights(values["weights"])
            if "filters" in values:
                filters = values["filters"]
                if not isinstance(filters,list) or len(filters)>30 or any(not isinstance(x,dict) or len(encoded(x))>1000 for x in filters):
                    raise ValueError("Save at most 30 compact filters.")
                data["filters"] = filters
            self.accounts.preferences(owner,data)
        return {"weights":validate_weights(data.get("weights")),"filters":data.get("filters",[])}
