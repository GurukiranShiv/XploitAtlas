"""CSAF 2.0/2.1 and OpenVEX assertions, retained with issuer and product context."""
from __future__ import annotations
import csv
import hashlib
import io
import json
import re
import time
import urllib.parse
import uuid
from accounts import AccessError
from core import CVE_RE, now, timestamp, safe_url
from manifests import from_purl,make_purl
from safe_http import get_json,request,validate_url
from workspace import encoded,identity

STATES = {"affected","not_affected","fixed","under_investigation"}
CSAF_STATES = {"known_affected":"affected","known_not_affected":"not_affected","fixed":"fixed","first_fixed":"fixed","under_investigation":"under_investigation","first_affected":"affected","last_affected":"affected"}
JUSTIFICATIONS = {"component_not_present","vulnerable_code_not_present","vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary","inline_mitigations_already_exist"}


def clean(value,limit=2000):
    return value[:limit] if isinstance(value,str) else ""


def purl_of(value):
    if not isinstance(value,dict):
        return ""
    identifiers = value.get("identifiers") or {}
    return clean(identifiers.get("purl") if isinstance(identifiers,dict) else "",1000) or (
        clean(value.get("@id"),1000) if str(value.get("@id","")).startswith("pkg:") else "")

def purl_identity(value):
    identity = from_purl(value)
    if not identity or not identity["version"]:
        return None
    parsed = urllib.parse.urlsplit(value)
    qualifiers = tuple(sorted(urllib.parse.parse_qsl(parsed.query,keep_blank_values=True)))
    return (identity["ecosystem"],identity["name"],identity["version"],qualifiers,urllib.parse.unquote(parsed.fragment))


def parse_document(document,source_url=""):
    if not isinstance(document,dict):
        raise ValueError("Upload a CSAF or OpenVEX JSON object.")
    if len(encoded(document))>8*1024*1024:
        raise ValueError("Vendor advisory exceeds 8 MiB.")
    statements = []
    if isinstance(document.get("document"),dict) and document["document"].get("csaf_version") in {"2.0","2.1"}:
        meta = document["document"]
        tracking = meta.get("tracking",{})
        publisher = meta.get("publisher",{})
        doc_id = clean(tracking.get("id"),500)
        published = timestamp(tracking.get("current_release_date"))
        if not doc_id or not published or not isinstance(document.get("vulnerabilities",[]),list):
            raise ValueError("CSAF requires a tracking identifier, release date and vulnerability array.")
        issuer = clean(publisher.get("name"),200)
        if not issuer:
            raise ValueError("CSAF publisher identity is missing.")
        products = {}
        def visit(node,depth=0):
            if depth>50:
                raise ValueError("CSAF product tree exceeds the depth limit.")
            if isinstance(node,dict):
                if node.get("product_id") and isinstance(node.get("name"),str):
                    helper = node.get("product_identification_helper",{})
                    products[clean(node["product_id"],500)] = {"name":clean(node["name"],500),
                        "purl":clean(helper.get("purl"),1000),"cpe":clean(helper.get("cpe"),1000)}
                for value in node.values():
                    if isinstance(value,(dict,list)):
                        visit(value,depth+1)
            elif isinstance(node,list):
                for value in node:
                    visit(value,depth+1)
        tree = document.get("product_tree",{})
        visit(tree)
        relationships = {r.get("full_product_name",{}).get("product_id"):r for r in tree.get("relationships",[]) if isinstance(r,dict)}
        for vuln in document.get("vulnerabilities",[]):
            if not isinstance(vuln,dict):
                raise ValueError("Malformed CSAF vulnerability.")
            cve = clean(vuln.get("cve"),100)
            if not CVE_RE.fullmatch(cve):
                continue
            remediations = vuln.get("remediations",[])
            for source_status,ids in vuln.get("product_status",{}).items():
                if source_status not in CSAF_STATES:
                    continue
                if not isinstance(ids,list):
                    raise ValueError("CSAF product statuses must contain product-ID arrays.")
                for product_id in ids:
                    if product_id not in products:
                        raise ValueError("CSAF status references an unknown product.")
                    product = products[product_id]
                    context = ""
                    if product_id in relationships:
                        relationship = relationships[product_id]
                        component = products.get(relationship.get("product_reference"),{})
                        parent = products.get(relationship.get("relates_to_product_reference"),{})
                        if component.get("purl"):
                            product = component
                            context = parent.get("purl") or "context:"+str(relationship.get("relates_to_product_reference"))
                    actions = [{"category":clean(r.get("category"),80),"details":clean(r.get("details"),4000),"url":clean(r.get("url"),3000)}
                               for r in remediations if isinstance(r,dict) and (not r.get("product_ids") or product_id in r["product_ids"])]
                    statements.append({"vulnerability":cve,"product":product["name"],"productId":clean(product_id,500),
                        "purl":product.get("purl",""),"contextPurl":context,"status":CSAF_STATES[source_status],
                        "justification":"", "impact":clean(vuln.get("title"),1000),"actions":actions,
                        "issued":published,"sourceUrl":source_url,"issuer":issuer})
        info = {"id":doc_id,"format":"CSAF "+meta["csaf_version"],"issuer":issuer,"issued":published,
                "version":str(tracking.get("version","")),"title":clean(meta.get("title"),500),
                "distribution":meta.get("distribution",{})}
    elif isinstance(document.get("statements"),list) and document.get("author"):
        context = document.get("@context","")
        if not isinstance(context,str) or not context.startswith("https://openvex.dev/ns/"):
            raise ValueError("Unsupported OpenVEX context.")
        doc_id,issuer = clean(document.get("@id"),500),clean(document.get("author"),500)
        issued = timestamp(document.get("timestamp"))
        if not doc_id or not issued:
            raise ValueError("OpenVEX requires an identifier and timestamp.")
        for statement in document["statements"]:
            if not isinstance(statement,dict) or statement.get("status") not in STATES:
                raise ValueError("Invalid OpenVEX statement status.")
            status = statement["status"]
            justification = clean(statement.get("justification"),200)
            impact = clean(statement.get("impact_statement"),4000)
            if justification and justification not in JUSTIFICATIONS:
                raise ValueError("Unsupported OpenVEX justification.")
            if status=="not_affected" and justification not in JUSTIFICATIONS and not impact:
                raise ValueError("A not_affected statement requires justification or an impact statement.")
            if status=="affected" and not clean(statement.get("action_statement"),4000):
                raise ValueError("An affected OpenVEX statement requires an action statement.")
            vuln = statement.get("vulnerability",{})
            if not isinstance(vuln,dict):
                raise ValueError("Invalid OpenVEX vulnerability object.")
            identifier = clean(vuln.get("name"),120) or clean(vuln.get("@id"),1000).rstrip("/").rsplit("/",1)[-1]
            if not CVE_RE.fullmatch(identifier) and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{3,119}",identifier):
                raise ValueError("Invalid OpenVEX vulnerability identifier.")
            products = statement.get("products",[])
            if not isinstance(products,list) or not products:
                raise ValueError("OpenVEX statement requires product identities.")
            for product in products:
                if not isinstance(product,dict):
                    raise ValueError("Invalid OpenVEX product.")
                parent_purl = purl_of(product)
                children = product.get("subcomponents",[])
                if not isinstance(children,list) or any(not isinstance(child,dict) for child in children):
                    raise ValueError("OpenVEX subcomponents must be product objects.")
                targets = children or [product]
                for target in targets:
                    statements.append({"vulnerability":identifier,"product":clean(target.get("@id"),1000),
                        "productId":clean(target.get("@id"),1000),"purl":purl_of(target),
                        "contextPurl":parent_purl or clean(product.get("@id"),1000) if children else "",
                        "status":status,"justification":justification,"impact":impact,
                        "actions":[{"category":"action","details":clean(statement.get("action_statement"),4000),"url":""}] if statement.get("action_statement") else [],
                        "issued":timestamp(statement.get("timestamp")) or issued,"sourceUrl":source_url,"issuer":issuer})
        info = {"id":doc_id,"format":"OpenVEX","issuer":issuer,"issued":issued,"version":str(document.get("version","")),"title":doc_id,"distribution":{}}
    else:
        raise ValueError("Supported documents: CSAF 2.0/2.1 or OpenVEX.")
    if len(statements)>20000:
        raise ValueError("The advisory contains too many product statements.")
    canonical = next((r.get("url") for r in document.get("document",{}).get("references",[])
                      if isinstance(r,dict) and r.get("category")=="self" and safe_url(r.get("url"))),None)
    info["url"] = source_url or canonical or (doc_id if safe_url(doc_id) else "")
    if info["format"]=="OpenVEX":
        if type(document.get("version")) is not int or document["version"]<1:
            raise ValueError("OpenVEX requires a positive integer document version.")
        info["issued"] = timestamp(document.get("last_updated")) or info["issued"]
    return {"document":info,"statements":statements,"fingerprint":hashlib.sha256(encoded(document).encode()).hexdigest()}


class VendorSources:
    def __init__(self,accounts):
        self.accounts = accounts
        with accounts.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS vendor_sources (
                    id TEXT PRIMARY KEY,owner INTEGER NOT NULL REFERENCES users(id),name TEXT NOT NULL,url TEXT,
                    kind TEXT NOT NULL,trusted INTEGER NOT NULL DEFAULT 0,enabled INTEGER NOT NULL DEFAULT 1,
                    last_fetch TEXT,next_fetch REAL NOT NULL DEFAULT 0,error TEXT,cursor TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_vendor_sources_owner ON vendor_sources(owner);
                CREATE TABLE IF NOT EXISTS vendor_documents (
                    id TEXT PRIMARY KEY,source_id TEXT NOT NULL REFERENCES vendor_sources(id) ON DELETE CASCADE,
                    document_key TEXT NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,issued TEXT NOT NULL,
                    fetched TEXT NOT NULL,UNIQUE(source_id,document_key)
                );
                CREATE TABLE IF NOT EXISTS vendor_statements (
                    id TEXT PRIMARY KEY,document_id TEXT NOT NULL REFERENCES vendor_documents(id) ON DELETE CASCADE,
                    vulnerability TEXT NOT NULL,purl TEXT NOT NULL,payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_vendor_statements_match ON vendor_statements(vulnerability,purl);
                CREATE TABLE IF NOT EXISTS vendor_history (
                    id INTEGER PRIMARY KEY,source_id TEXT NOT NULL REFERENCES vendor_sources(id) ON DELETE CASCADE,
                    document_key TEXT NOT NULL,issued TEXT NOT NULL,fingerprint TEXT NOT NULL,observed TEXT NOT NULL
                );
            """)

    def list(self,owner):
        with self.accounts.connection() as db:
            return [{**dict(r),"documents":db.execute("SELECT COUNT(*) FROM vendor_documents WHERE source_id=?",(r["id"],)).fetchone()[0]}
                    for r in db.execute("SELECT * FROM vendor_sources WHERE owner=? ORDER BY name",(owner,)).fetchall()]

    def create(self,owner,name,url=None,document=None,trusted=False):
        if not isinstance(name,str) or not 1<=len(name.strip())<=100:
            raise ValueError("Give this advisory source a name.")
        if bool(url)==(document is not None):
            raise ValueError("Supply either an advisory URL or a JSON document.")
        if url:
            validate_url(url)
        parsed = parse_document(document) if document is not None else None
        identifier = uuid.uuid4().hex
        with self.accounts.connection() as db:
            if db.execute("SELECT COUNT(*) FROM vendor_sources WHERE owner=?",(owner,)).fetchone()[0]>=50:
                raise ValueError("An account can configure up to 50 advisory sources.")
            db.execute("INSERT INTO vendor_sources(id,owner,name,url,kind,trusted) VALUES(?,?,?,?,?,?)",
                       (identifier,owner,name.strip(),url,"url" if url else "upload",int(trusted is True)))
        if parsed:
            self.store_document(identifier,parsed)
        return {"id":identifier,"queued":bool(url)}

    def configure(self,owner,identifier,action):
        with self.accounts.connection() as db:
            row = db.execute("SELECT * FROM vendor_sources WHERE id=? AND owner=?",(identifier,owner)).fetchone()
            if not row:
                raise AccessError("Advisory source not found.",404)
            if action=="delete":
                db.execute("DELETE FROM vendor_sources WHERE id=?",(identifier,))
            elif action in {"pause","resume"}:
                db.execute("UPDATE vendor_sources SET enabled=? WHERE id=?",(int(action=="resume"),identifier))
            elif action=="refresh":
                db.execute("UPDATE vendor_sources SET next_fetch=0 WHERE id=?",(identifier,))
            else:
                raise ValueError("Unknown source action.")
        return {"updated":True}

    def store_document(self,source_id,parsed):
        info = parsed["document"]
        identifier = identity(source_id,info["id"])
        with self.accounts.connection() as db:
            previous = db.execute("SELECT issued,fingerprint,payload FROM vendor_documents WHERE id=?",(identifier,)).fetchone()
            if previous and (previous["issued"]>info["issued"] or previous["fingerprint"]==parsed["fingerprint"]):
                return False
            if previous and info["format"]=="OpenVEX" and int(json.loads(previous["payload"]).get("version") or 0)>int(info["version"]):
                return False
            db.execute("INSERT INTO vendor_documents VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,fingerprint=excluded.fingerprint,issued=excluded.issued,fetched=excluded.fetched",
                       (identifier,source_id,info["id"],encoded(info),parsed["fingerprint"],info["issued"],now()))
            db.execute("DELETE FROM vendor_statements WHERE document_id=?",(identifier,))
            for i,statement in enumerate(parsed["statements"]):
                db.execute("INSERT INTO vendor_statements VALUES(?,?,?,?,?)",(identity(identifier,i),identifier,statement["vulnerability"],statement["purl"],encoded(statement)))
            db.execute("INSERT INTO vendor_history(source_id,document_key,issued,fingerprint,observed) VALUES(?,?,?,?,?)",
                       (source_id,info["id"],info["issued"],parsed["fingerprint"],now()))
        return True

    def step(self):
        with self.accounts.connection() as db:
            source = db.execute("SELECT s.* FROM vendor_sources s JOIN users u ON u.id=s.owner WHERE u.disabled=0 AND s.enabled=1 AND s.kind='url' AND s.next_fetch<=? ORDER BY s.next_fetch LIMIT 1",(time.time(),)).fetchone()
        if not source:
            return False
        source = dict(source)
        try:
            document = get_json(source["url"])
            # CSAF provider metadata: consume explicit directory distributions only.
            if isinstance(document,dict) and "distributions" in document and "document" not in document:
                cursor = json.loads(source["cursor"])
                seen = cursor.get("seen",{})
                processed = 0
                for distribution in document.get("distributions",[])[:20]:
                    directory = distribution.get("directory_url") if isinstance(distribution,dict) else None
                    if not directory:
                        continue
                    validate_url(directory)
                    payload,_ = request(urllib.parse.urljoin(directory.rstrip("/")+"/","changes.csv"),max_bytes=4*1024*1024)
                    rows = list(csv.reader(io.StringIO(payload.decode("utf-8-sig"))))
                    for row in reversed(rows):
                        if len(row)<2:
                            continue
                        name,modified = row[0],row[1]
                        url = urllib.parse.urljoin(directory.rstrip("/")+"/",name)
                        if urllib.parse.urlsplit(url).netloc!=urllib.parse.urlsplit(directory).netloc or not name.endswith(".json"):
                            continue
                        if seen.get(url)==modified:
                            continue
                        self.store_document(source["id"],parse_document(get_json(url),url))
                        seen[url] = modified;processed += 1
                        if processed>=10:
                            break
                    if processed>=10:
                        break
                if not any(isinstance(d,dict) and d.get("directory_url") for d in document.get("distributions",[])):
                    raise ValueError("This CSAF provider does not expose a directory distribution. Configure document URLs instead.")
                if len(seen)>20000:
                    seen = dict(list(seen.items())[-20000:])
                cursor = encoded({"seen":seen})
                delay = 60 if processed>=10 else 3600
            else:
                self.store_document(source["id"],parse_document(document,source["url"]))
                cursor,delay = source["cursor"],3600
            with self.accounts.connection() as db:
                db.execute("UPDATE vendor_sources SET last_fetch=?,next_fetch=?,error=NULL,cursor=? WHERE id=?",(now(),time.time()+delay,cursor,source["id"]))
        except Exception as exc:
            with self.accounts.connection() as db:
                db.execute("UPDATE vendor_sources SET next_fetch=?,error=? WHERE id=?",(time.time()+900,str(exc)[:300],source["id"]))
        return True

    def statements(self,owner,vulnerability=None,purl=None,context_purl="",source_id=None):
        condition,args = "s.owner=?",[owner]
        if vulnerability:
            condition += " AND v.vulnerability=?";args.append(vulnerability)
        if source_id:
            condition += " AND s.id=?";args.append(source_id)
        result = []
        target = purl_identity(purl) if purl else None
        with self.accounts.connection() as db:
            rows = db.execute("SELECT v.payload,s.id source_id,s.name source_name,s.trusted,d.payload document FROM vendor_statements v JOIN vendor_documents d ON d.id=v.document_id JOIN vendor_sources s ON s.id=d.source_id WHERE "+condition+" ORDER BY d.issued DESC",args)
            for row in rows:
                item = json.loads(row["payload"])
                if purl and (not target or purl_identity(item["purl"])!=target):
                    continue
                item.update(sourceId=row["source_id"],sourceName=row["source_name"],trusted=bool(row["trusted"]),document=json.loads(row["document"]))
                item["contextMatches"] = not item["contextPurl"] or bool(purl_identity(context_purl) and purl_identity(item["contextPurl"])==purl_identity(context_purl))
                item["effect"] = "annotation"
                result.append(item)
                if len(result)>=500:
                    break
        return result
