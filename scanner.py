"""Batched OSV queries, full advisory evidence, and durable inventory checks."""
from __future__ import annotations
import json
import re
import threading
import urllib.parse
from datetime import datetime,timezone
import adapters
from core import CVE_RE, now, severity
from feeds import FeedError
from manifests import normalize_component
from prioritization import priority

ADVISORY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,119}\Z")


def name_key(ecosystem,name):
    return re.sub(r"[-_.]+","-",name).lower() if ecosystem=="PyPI" else name


def validate_result(result):
    if not isinstance(result,dict) or result.get("error") or not isinstance(result.get("vulns",[]),list):
        raise FeedError("OSV could not complete this package query.")
    entries = []
    for item in result.get("vulns",[]):
        if not isinstance(item,dict) or not isinstance(item.get("id"),str) or not ADVISORY_ID.fullmatch(item["id"]):
            raise FeedError("OSV returned an invalid advisory identifier.")
        modified = item.get("modified")
        if modified is not None and (not isinstance(modified,str) or len(modified)>80):
            raise FeedError("OSV returned an invalid modification timestamp.")
        entries.append({"id":item["id"],"modified":modified})
    token = result.get("next_page_token")
    if token is not None and (not isinstance(token,str) or len(token)>4096):
        raise FeedError("OSV returned an invalid continuation token.")
    return entries,token or None


def fetch_advisory(client,identifier,modified=None,workspace=None):
    cached = workspace.cache_get(identifier,modified) if workspace else None
    if cached:
        return cached
    response = client.get("https://api.osv.dev/v1/vulns/"+urllib.parse.quote(identifier,safe=""),"osv")
    doc = response.data
    if not isinstance(doc,dict) or doc.get("id")!=identifier or not isinstance(doc.get("affected",[]),list):
        raise FeedError("OSV returned an inconsistent advisory document.")
    if len(json.dumps(doc))>2*1024*1024:
        raise FeedError("The OSV advisory exceeded its document limit.")
    client.store.ingest("osv",adapters.osv(doc,response.observed_at,response.url))
    if workspace:
        workspace.cache_put(doc)
    return doc


def finding_from_document(component,document,catalog):
    if document.get("withdrawn"):
        return None
    matching = [entry for entry in document.get("affected",[]) if isinstance(entry,dict)
                and entry.get("package",{}).get("ecosystem")==component["ecosystem"]
                and name_key(component["ecosystem"],entry.get("package",{}).get("name",""))==name_key(component["ecosystem"],component["name"])]
    if not matching:
        raise FeedError("The advisory did not contain the queried package identity.")
    aliases = [a for a in document.get("aliases",[]) if isinstance(a,str) and ADVISORY_ID.fullmatch(a)]
    aliases = sorted(set(aliases+[document["id"]]))
    cves = sorted(a for a in aliases if CVE_RE.fullmatch(a))
    records = [r for identifier in cves if (r:=catalog.record(identifier))]
    records.sort(key=lambda r:(bool(r.get("kev")),r.get("priority",{}).get("score",0)),reverse=True)
    canonical = records[0] if records else {}
    fixed,ranges = [],[]
    for entry in matching:
        for scope in entry.get("ranges",[]):
            if not isinstance(scope,dict):
                continue
            ranges.append(scope)
            for event in scope.get("events",[]):
                if isinstance(event,dict) and isinstance(event.get("fixed"),str):
                    fixed.append(event["fixed"][:120])
    raw_severity = str(document.get("database_specific",{}).get("severity","")).upper()
    level = {"CRITICAL":"Critical","HIGH":"High","MODERATE":"Medium","MEDIUM":"Medium","LOW":"Low"}.get(raw_severity,"Unknown")
    if canonical.get("severity") not in (None,"Unknown"):
        level = canonical["severity"]
    result = {"advisoryId":document["id"],"recordId":canonical.get("id") or (cves[0] if cves else document["id"]),
              "aliases":sorted(set(aliases+[document["id"]])),"title":str(document.get("summary") or document["id"])[:500],
              "description":str(document.get("details") or "")[:12000],"severity":level,
              "cvss":canonical.get("cvss"),"epss":canonical.get("epss"),"epssDate":canonical.get("epssDate"),
              "kev":any(r.get("kev") for r in records),"ransomware":canonical.get("ransomware"),
              "url":"https://osv.dev/vulnerability/"+urllib.parse.quote(document["id"],safe=""),
              "fixedVersions":list(dict.fromkeys(fixed)),"affectedRanges":ranges,"modified":document.get("modified"),
              "references":[{"url":r["url"],"kind":"patch" if r.get("type")=="FIX" else "reference","source":"osv"}
                            for r in document.get("references",[]) if isinstance(r,dict) and isinstance(r.get("url"),str)],
              "matchBasis":"OSV exact package/version response","observedAt":now()}
    result["priority"] = priority(result)
    return result


class Scanner:
    def __init__(self,workspace,client):
        self.workspace,self.client = workspace,client
        self.lock = threading.Lock()

    def step(self):
        if not self.lock.acquire(blocking=False):
            return False
        try:
            inventory,rows = self.workspace.next_batch()
            if not inventory:
                return False
            if not rows:
                self.workspace.finish_scan(inventory)
                return False
            queries = [{"package":{"ecosystem":r["component"]["ecosystem"],"name":r["component"]["name"]},
                        "version":r["component"]["version"],**({"page_token":r["page_token"]} if r["page_token"] else {})} for r in rows]
            try:
                response = self.client.get("https://api.osv.dev/v1/querybatch","osv",body={"queries":queries},capture=False)
                results = response.data.get("results") if isinstance(response.data,dict) else None
                if not isinstance(results,list) or len(results)!=len(rows):
                    raise FeedError("OSV returned an incomplete batch response.")
                self.client.store.health("osv",state="ok",lastSuccess=response.observed_at,lastAttempt=response.observed_at,retryAt=None,
                                         message="Batched package queries are responding.")
            except (FeedError,ValueError,OSError) as exc:
                for row in rows:
                    self.workspace.commit_component(inventory,row,[],[],error=exc)
                self.workspace.finish_scan(inventory)
                return True
            for row,result in zip(rows,results):
                try:
                    entries,token = validate_result(result)
                    all_entries = {e["id"]:e for e in json.loads(row["pending_matches"])}
                    all_entries.update({e["id"]:e for e in entries})
                    if len(all_entries)>10000 or (token and (token==row["page_token"] or row["page_count"]>=99)):
                        raise FeedError("OSV pagination could not be completed.")
                    findings = []
                    if not token:
                        for entry in all_entries.values():
                            document = fetch_advisory(self.client,entry["id"],entry.get("modified"),self.workspace)
                            finding = finding_from_document(row["component"],document,self.workspace.catalog)
                            if finding:
                                findings.append(finding)
                    self.workspace.commit_component(inventory,row,list(all_entries.values()),findings,next_page=token)
                except (FeedError,ValueError,TypeError,KeyError,OSError) as exc:
                    self.workspace.commit_component(inventory,row,[],[],error=exc)
            self.workspace.finish_scan(inventory)
            return True
        finally:
            self.lock.release()


def check_components(client,components,catalog):
    """CI uses the same batch endpoint and evidence normalizer without creating an account."""
    results,cache = [],{}
    for offset in range(0,len(components),100):
        group = components[offset:offset+100]
        statuses = [{"component":c,"complete":False,"findings":[],"error":c.get("skipReason")} for c in group]
        active = [i for i,c in enumerate(group) if not c.get("skipReason")]
        tokens,seen = {},{i:{} for i in active}
        for page in range(100):
            if not active:
                break
            queries = [{"package":{"ecosystem":group[i]["ecosystem"],"name":group[i]["name"]},"version":group[i]["version"],
                        **({"page_token":tokens[i]} if tokens.get(i) else {})} for i in active]
            try:
                response = client.get("https://api.osv.dev/v1/querybatch","osv",body={"queries":queries},capture=False)
                data = response.data
                if not isinstance(data,dict) or not isinstance(data.get("results"),list) or len(data["results"])!=len(active):
                    raise FeedError("OSV batch response is incomplete.")
                catalog.health("osv",state="ok",lastSuccess=response.observed_at,lastAttempt=response.observed_at,retryAt=None,
                               message="Batched package queries are responding.")
            except (FeedError,OSError,ValueError) as exc:
                for i in active:
                    statuses[i]["error"] = str(exc)
                active = [];break
            next_active = []
            for i,result in zip(active,data["results"]):
                try:
                    entries,token = validate_result(result)
                    seen[i].update({e["id"]:e for e in entries})
                    if len(seen[i])>10000 or (token and (token==tokens.get(i) or page==99)):
                        raise FeedError("OSV pagination could not be completed.")
                    if token:
                        tokens[i] = token;next_active.append(i);continue
                    for entry in seen[i].values():
                        identifier = entry["id"]
                        if identifier not in cache:
                            cache[identifier] = fetch_advisory(client,identifier,entry.get("modified"))
                        finding = finding_from_document(group[i],cache[identifier],catalog)
                        if finding:
                            statuses[i]["findings"].append(finding)
                    statuses[i]["complete"] = True
                except (FeedError,OSError,ValueError,KeyError,TypeError) as exc:
                    statuses[i]["error"] = str(exc)
            active = next_active
        results.extend(statuses)
    return results


def evaluate_policy(checks,catalog,fail_on="kev",threshold=70,coverage_complete=True):
    if fail_on not in {"kev","high","critical","priority"}:
        raise ValueError("Choose kev, high, critical, or priority.")
    violations = []
    incomplete = not coverage_complete or any(not c["complete"] for c in checks)
    if fail_on=="kev":
        health = next((s for s in catalog.sources() if s["id"]=="cisa"),{})
        try:
            fetched = datetime.fromisoformat(health["lastSuccess"].replace("Z","+00:00"))
            incomplete |= (datetime.now(timezone.utc)-fetched).total_seconds()>86400
        except (ValueError,TypeError,KeyError):
            incomplete = True
    for check in checks:
        for finding in check["findings"]:
            breach = (fail_on=="kev" and finding["kev"]) or (fail_on=="critical" and finding["severity"]=="Critical") or (
                fail_on=="high" and finding["severity"] in {"High","Critical"}) or (fail_on=="priority" and finding["priority"]["score"]>=threshold)
            if fail_on in {"high","critical"} and finding["severity"]=="Unknown":
                incomplete = True
            if breach:
                violations.append({"package":check["component"],"advisory":finding["advisoryId"],"recordId":finding["recordId"],"url":finding["url"]})
    return {"policy":fail_on,"threshold":threshold if fail_on=="priority" else None,"violations":violations,
            "complete":not incomplete,"passed":not incomplete and not violations,
            "exitCode":2 if incomplete else 1 if violations else 0}
