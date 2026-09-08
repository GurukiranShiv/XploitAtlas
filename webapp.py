"""WSGI API with session authentication, CSRF checks and owner-scoped resources."""
from __future__ import annotations
import csv
import hashlib
import hmac
import html
import io
import json
import logging
import mimetypes
import re
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.cookies import SimpleCookie,CookieError
from pathlib import Path
from accounts import AccessError
from config import ROOT,VERSION,environment
from core import now,safe_url,CVE_RE,GHSA_RE
from feeds import FeedError
from manifests import parse_document,normalize_component,make_purl
from prioritization import priority

LOG = logging.getLogger("mastermonk")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{3,119}\Z")
COOKIE = "mastermonk_session"
JSON_TYPE = "application/json; charset=utf-8"
CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"


class Response:
    def __init__(self,body=b"",status=200,content_type=JSON_TYPE,headers=None):
        self.status,self.content_type,self.headers = status,content_type,headers or []
        self.body = body.encode("utf-8") if isinstance(body,str) else body


def json_response(value,status=200,headers=None):
    return Response(json.dumps(value,ensure_ascii=False,allow_nan=False),status,headers=headers)


class Request:
    def __init__(self,environ):
        self.environ,self.method,self.path = environ,environ.get("REQUEST_METHOD","GET"),environ.get("PATH_INFO","/")
        self.query = urllib.parse.parse_qs(environ.get("QUERY_STRING",""),max_num_fields=32)
        self.host = environ.get("HTTP_HOST","")
        self.origin = environ.get("HTTP_ORIGIN","")
        self.user,self.token = None,""

    def arg(self,key,default=""):
        return self.query.get(key,[default])[0]

    def body(self):
        length = int(self.environ.get("CONTENT_LENGTH") or "0")
        if not 0<=length<=9*1024*1024:
            raise ValueError("The request exceeds 9 MiB.")
        content_type = self.environ.get("CONTENT_TYPE","").split(";",1)[0].lower()
        if content_type!="application/json":
            raise ValueError("Send an application/json request.")
        raw = self.environ["wsgi.input"].read(length)
        value = json.loads(raw or b"{}",parse_constant=lambda _:(_ for _ in ()).throw(ValueError("Non-finite JSON number.")))
        if not isinstance(value,dict):
            raise ValueError("Send a JSON object.")
        return value


class Application:
    def __init__(self,services,config=None):
        self.services,self.config = services,config or environment()
        self.lock,self.limits = threading.Lock(),{}
        self.lookup_slots = threading.BoundedSemaphore(2)
        self.component_slots = threading.BoundedSemaphore(2)
        self.ai_slots = threading.BoundedSemaphore(1)
        self.setup_code = None
        if services.accounts.needs_setup():
            self.setup_code = services.accounts.issue_setup_code()
            path = services.path/"setup-code.txt"
            path.write_text(self.setup_code+"\n")
            try:
                path.chmod(0o600)
            except OSError:
                pass

    def cookie(self,token=""):
        return (COOKIE+"="+token+"; Path=/; HttpOnly; SameSite=Strict; Max-Age="+("43200" if token else "0")+
                ("; Secure" if self.config["secure"] else ""))

    def rate(self,key,limit=180,seconds=60):
        stamp = time.monotonic()
        with self.lock:
            count,expires = self.limits.get(key,(0,stamp+seconds))
            if expires<=stamp:
                count,expires = 0,stamp+seconds
            if count>=limit:
                raise AccessError("Request limit reached. Try again shortly.",429)
            if len(self.limits)>10000:
                self.limits = {k:v for k,v in self.limits.items() if v[1]>stamp}
                if len(self.limits)>10000:
                    raise AccessError("The service is temporarily busy.",503)
            self.limits[key] = count+1,expires

    def authenticate(self,request,required=True,scope="read"):
        header = request.environ.get("HTTP_AUTHORIZATION","")
        if header.startswith("Bearer "):
            request.user = self.services.accounts.authenticate_api_token(header[7:])
            if scope not in request.user["scopes"]:
                raise AccessError("This API token does not grant the required scope.",403)
            return request.user
        try:
            cookies = SimpleCookie(request.environ.get("HTTP_COOKIE",""))
            request.token = cookies[COOKIE].value if COOKIE in cookies else ""
        except CookieError:
            request.token = ""
        try:
            request.user = self.services.accounts.authenticate(request.token)
        except AccessError:
            if required:
                raise
        return request.user

    def origin_check(self,request):
        expected = self.config["origin"] or (request.environ.get("wsgi.url_scheme","http")+"://"+request.host)
        if request.origin:
            if request.origin!=expected:
                raise AccessError("The request origin does not match this instance.",403)
        elif request.environ.get("HTTP_X_MASTERMONK_CLIENT")!="cli":
            raise AccessError("An Origin header is required.",403)

    def mutation(self,request,scope="scan",admin=False):
        user = self.authenticate(request,scope=scope)
        if user.get("api_token"):
            if admin:
                raise AccessError("Administrator actions require an interactive session.",403)
            return user
        self.origin_check(request)
        provided = request.environ.get("HTTP_X_CSRF_TOKEN","")
        if not provided or not hmac.compare_digest(provided,user["csrf"]):
            raise AccessError("The session verification token is missing or expired. Reload the page.",403)
        if admin and user["role"]!="admin":
            raise AccessError("Administrator access required.",403)
        return user

    def admin(self,request):
        user = self.authenticate(request)
        if user["role"]!="admin" or user.get("api_token"):
            raise AccessError("Administrator access required.",403)
        return user

    def __call__(self,environ,start_response):
        request = None
        try:
            request = Request(environ)
            parsed_host = urllib.parse.urlsplit("//"+request.host)
            if parsed_host.hostname not in self.config["hosts"] or parsed_host.username or parsed_host.password:
                raise AccessError("This hostname is not configured for MasterMonk.",403)
            if request.method not in {"GET","HEAD","POST"}:
                raise AccessError("Method not allowed.",405)
            self.rate((environ.get("REMOTE_ADDR","unknown"),"requests"),600)
            response = self.route(request)
        except AccessError as exc:
            response = json_response({"error":str(exc)},exc.status)
        except FeedError as exc:
            response = json_response({"error":str(exc)},502)
        except (ValueError,TypeError,KeyError,UnicodeError,RecursionError) as exc:
            response = json_response({"error":str(exc)[:300] or "Invalid request."},400)
        except Exception:
            LOG.exception("Request failed")
            response = json_response({"error":"The request could not be completed. Existing records are preserved."},500)
        headers = [("Content-Type",response.content_type),("X-Content-Type-Options","nosniff"),("Referrer-Policy","no-referrer"),
                   ("Content-Security-Policy",CSP),("X-Frame-Options","DENY"),
                   ("Permissions-Policy","camera=(), microphone=(), geolocation=()")]
        if not any(name.lower()=="cache-control" for name,_value in response.headers):
            headers.append(("Cache-Control","no-store"))
        headers += response.headers
        if self.config["secure"]:
            headers.append(("Strict-Transport-Security","max-age=31536000"))
        if isinstance(response.body,bytes):
            headers.append(("Content-Length",str(len(response.body))))
            iterable = [response.body]
        else:
            iterable = response.body
        start_response(f"{response.status} {HTTPStatus(response.status).phrase}",headers)
        if request and request.method=="HEAD":
            if hasattr(iterable,"close"):
                iterable.close()
            return [b""]
        return iterable

    def route(self,request):
        s,path = self.services,request.path
        if request.method in {"GET","HEAD"}:
            if path=="/":
                return Response((ROOT/"static/index.html").read_bytes(),content_type="text/html; charset=utf-8")
            if path=="/manifest.webmanifest":
                return Response((ROOT/"static/manifest.webmanifest").read_bytes(),content_type="application/manifest+json")
            if path=="/service-worker.js":
                return Response((ROOT/"static/sw.js").read_bytes(),content_type="text/javascript; charset=utf-8",headers=[("Service-Worker-Allowed","/")])
            if path.startswith("/static/"):
                relative = urllib.parse.unquote(path[8:])
                file = (ROOT/"static"/relative).resolve()
                if not file.is_relative_to((ROOT/"static").resolve()) or not file.is_file() or any(p.startswith(".") for p in Path(relative).parts):
                    raise AccessError("File not found.",404)
                content_type = {".js":"text/javascript",".css":"text/css",".woff2":"font/woff2",".svg":"image/svg+xml",".png":"image/png",".webp":"image/webp",".webmanifest":"application/manifest+json"}.get(file.suffix,mimetypes.guess_type(str(file))[0] or "application/octet-stream")
                return Response(file.read_bytes(),content_type=content_type)
            if path=="/api/health":
                return json_response({"status":"ok","version":VERSION})
            if path=="/api/session":
                user = self.authenticate(request,required=False)
                return json_response({"user":user,"needsSetup":s.accounts.needs_setup(),"publicCatalog":self.config["public_catalog"],"version":VERSION,
                                      "syncMode":self.config["sync_mode"],"ai":s.ai.status()})
            if path.startswith("/feeds/") and path.endswith(".atom"):
                self.rate((request.environ.get("REMOTE_ADDR"),"feed"),30)
                raw = path.removeprefix("/feeds/").removesuffix(".atom")
                if not re.fullmatch(r"[A-Za-z0-9_-]{32,64}",raw):
                    raise AccessError("Feed not found.",404)
                return Response(s.alerts.atom(raw),content_type="application/atom+xml; charset=utf-8")
            if path=="/robots.txt":
                body = "User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /feeds/\n" if self.config["public_catalog"] else "User-agent: *\nDisallow: /\n"
                if self.config["public_catalog"] and self.config["origin"]:
                    body += "Sitemap: "+self.config["origin"]+"/sitemap.xml\n"
                return Response(body,content_type="text/plain; charset=utf-8")
            public = path in {"/api/catalog","/api/universe","/api/record","/api/events","/api/trends","/api/trend-records",
                "/api/compare","/api/component-compare","/api/taxonomy","/api/highlight","/api/sources","/api/status","/sitemap.xml"} or path.startswith(("/vulnerability/","/sitemaps/","/badge/"))
            user = self.authenticate(request,required=not(public and self.config["public_catalog"]))
            owner = user["id"] if user else None
            if path=="/api/status":
                return json_response({"revision":s.catalog.state("catalog_revision",0),"sources":s.catalog.sources(),
                                      "sync":s.catalog.state("sync",{}),"lastSuccess":s.catalog.state("last_success"),
                                      "workerHeartbeat":s.catalog.state("worker_heartbeat")})
            if path in {"/api/catalog","/api/universe"}:
                limit,offset,days = int(request.arg("limit","100")),int(request.arg("offset","0")),int(request.arg("days","0"))
                level = request.arg("severity","all")
                if not 1<=limit<=10000 or not 0<=offset<=1000000 or days not in {0,1,7,30,90,365} or level not in {"all","Critical","High","Medium","Low","None","Unknown"}:
                    raise ValueError("Invalid catalog filter.")
                weights = s.workspace.profile(owner)["weights"] if owner else None
                values = s.catalog.catalog(request.arg("q")[:200],level,request.arg("kev")=="1",days,request.arg("sort","priority"),limit,offset,weights)
                values.update(sources=s.catalog.sources(),sync=s.catalog.state("sync",{}),lastSuccess=s.catalog.state("last_success"),baseline=s.catalog.state("created_at"),
                              epss=s.catalog.state("epss_bulk",{}),workerHeartbeat=s.catalog.state("worker_heartbeat"),revision=s.catalog.state("catalog_revision",0))
                return json_response(values)
            if path=="/api/record":
                identifier = request.arg("id")
                if not IDENTIFIER.fullmatch(identifier):
                    raise ValueError("Enter a valid vulnerability identifier.")
                record = s.catalog.record(identifier)
                if not record:
                    raise AccessError("This record has not been imported.",404)
                if owner:
                    record["priority"] = priority(record,s.workspace.profile(owner)["weights"])
                return json_response({"record":record,"statements":s.vendors.statements(owner,identifier) if owner else []})
            if path=="/api/events":
                return json_response({"events":s.catalog.events(request.arg("id") or None,before=int(request.arg("before")) if request.arg("before") else None),"baseline":s.catalog.state("created_at")})
            if path=="/api/trends":
                return json_response(s.catalog.trends(int(request.arg("days","30")),request.arg("basis","source")))
            if path=="/api/trend-records":
                return json_response(s.catalog.trend_records(request.arg("basis","source"),request.arg("metric"),
                    request.arg("start"),request.arg("end"),int(request.arg("limit","100"))))
            if path=="/api/compare":
                return json_response(s.catalog.compare(request.arg("from"),request.arg("to"),int(request.arg("limit","200"))))
            if path=="/api/component-compare":
                self.rate((request.environ.get("REMOTE_ADDR"),"component-compare"),12,60)
                self.rate(("instance","component-evidence"),60,60)
                if not self.component_slots.acquire(blocking=False):
                    raise AccessError("Package evidence queries are busy. Try again shortly.",429)
                try:
                    return json_response(s.components.compare(
                        {"ecosystem":request.arg("left_ecosystem"),"name":request.arg("left_name"),"version":request.arg("left_version")},
                        {"ecosystem":request.arg("right_ecosystem"),"name":request.arg("right_name"),"version":request.arg("right_version")}))
                finally:
                    self.component_slots.release()
            if path=="/badge/component.svg":
                from components import badge_svg,exact_component
                component = exact_component({"ecosystem":request.arg("ecosystem"),"name":request.arg("name"),"version":request.arg("version")})
                self.rate((request.environ.get("REMOTE_ADDR"),"component-badge"),60,60)
                self.rate(("instance","component-evidence"),60,60)
                if not self.component_slots.acquire(blocking=False):
                    return Response(badge_svg(component,unavailable=True),content_type="image/svg+xml; charset=utf-8",headers=[
                        ("Cache-Control","public, max-age=30"),("Access-Control-Allow-Origin","*"),
                        ("Cross-Origin-Resource-Policy","cross-origin")])
                try:
                    try:
                        body = badge_svg(component,s.components.query(component))
                        seconds = "300"
                    except (FeedError,ValueError,TypeError,KeyError):
                        body = badge_svg(component,unavailable=True)
                        seconds = "60"
                    return Response(body,content_type="image/svg+xml; charset=utf-8",headers=[
                        ("Cache-Control","public, max-age="+seconds),("Access-Control-Allow-Origin","*"),
                        ("Cross-Origin-Resource-Policy","cross-origin")])
                finally:
                    self.component_slots.release()
            if path=="/api/taxonomy":
                identifier = request.arg("id")
                if not IDENTIFIER.fullmatch(identifier):
                    raise ValueError("Enter a valid vulnerability identifier.")
                record = s.catalog.record(identifier)
                if not record:
                    raise AccessError("This record has not been imported.",404)
                self.rate((request.environ.get("REMOTE_ADDR"),"taxonomy"),20,60)
                return json_response(s.taxonomy.for_record(record))
            if path=="/api/highlight":
                return json_response(s.highlights.public(request.arg("token")))
            if path=="/api/highlights":
                return json_response({"highlights":s.highlights.list(owner)})
            if path=="/api/ai/status":
                return json_response(s.ai.status())
            if path=="/api/sources":
                return json_response({"sources":s.catalog.sources(),"epss":s.catalog.state("epss_bulk",{}),"backfill":s.backfill.status(),
                                      "vendorSources":s.vendors.list(owner) if owner else [],"workerHeartbeat":s.catalog.state("worker_heartbeat")})
            if path=="/api/inventories":
                if request.arg("id"):
                    return json_response(s.workspace.detail(owner,request.arg("id"),int(request.arg("offset","0"))))
                return json_response({"inventories":s.workspace.list(owner)})
            if path=="/api/findings":
                return json_response(s.workspace.findings(owner,request.arg("inventory") or None,request.arg("resolved")=="1",int(request.arg("offset","0")),int(request.arg("limit","250"))))
            if path=="/api/inventory-export":
                return json_response(s.workspace.export(owner,request.arg("id")),headers=[("Content-Disposition",'attachment; filename="MasterMonk-inventory.cdx.json"')])
            if path=="/api/evidence":
                with s.accounts.connection() as db:
                    row = db.execute("SELECT f.*,c.payload component,i.metadata,i.name inventory_name,i.exposed,i.criticality FROM findings f JOIN inventory_components c ON c.id=f.component_id JOIN inventories i ON i.id=f.inventory_id WHERE f.id=? AND i.owner=?",(request.arg("id"),owner)).fetchone()
                if not row:
                    raise AccessError("Finding not found.",404)
                finding,component,metadata = json.loads(row["payload"]),json.loads(row["component"]),json.loads(row["metadata"])
                record = s.catalog.record(finding["recordId"])
                combined = dict(finding)
                if record:
                    for key in ("kev","ransomware","references","epss","epssDate","cvss"):
                        if record.get(key) is not None:
                            combined[key] = record[key]
                finding["priority"] = priority(combined,s.workspace.profile(owner)["weights"],{"internet_exposed":bool(row["exposed"]),"criticality":row["criticality"]})
                statements = []
                for identifier in finding.get("aliases",[]):
                    statements.extend(s.vendors.statements(owner,identifier,make_purl(component),metadata.get("rootPurl","")))
                return json_response({"finding":{**finding,"id":row["id"],"status":row["status"],"note":row["note"]},"component":component,"statements":statements,
                                      "record":record,"inventory":row["inventory_name"],
                                      "dependencies":[edge for edge in metadata.get("dependencyEdges",[]) if edge.get("to") in component.get("locations",[])]})
            if path=="/api/alerts":
                return json_response(s.alerts.inbox(owner,int(request.arg("offset","0"))))
            if path=="/api/watch-rules":
                return json_response({"rules":s.alerts.rules(owner)})
            if path=="/api/profile":
                return json_response(s.workspace.profile(owner))
            if path=="/api/tokens":
                return json_response({"tokens":s.accounts.tokens(owner)})
            if path=="/api/users":
                self.admin(request)
                return json_response({"users":s.accounts.users()})
            if path=="/api/vendor-sources":
                return json_response({"sources":s.vendors.list(owner),"statements":s.vendors.statements(owner,request.arg("id") or None,source_id=request.arg("source") or None)})
            if path=="/api/export":
                self.rate((owner,"export"),3,60)
                return self.export(request.arg("format","json"))
            if path=="/api/source":
                self.rate((owner,"source"),2,60)
                from source_package import build_source_archive
                return Response(build_source_archive(ROOT),content_type="application/zip",headers=[("Content-Disposition",'attachment; filename="MasterMonk-source.zip"')])
            if path.startswith("/vulnerability/"):
                identifier = path.removeprefix("/vulnerability/")
                record = s.catalog.record(identifier) if IDENTIFIER.fullmatch(identifier) else None
                if not record:
                    raise AccessError("Record not found.",404)
                return Response(record_page(record),content_type="text/html; charset=utf-8")
            if path=="/sitemap.xml" or path.startswith("/sitemaps/"):
                return self.sitemap(path)
            raise AccessError("Endpoint not found.",404)
        data = request.body()
        if path in {"/api/auth/login","/api/auth/setup"}:
            self.origin_check(request)
            if path.endswith("setup"):
                self.rate((request.environ.get("REMOTE_ADDR"),"setup"),8,900)
                if not s.accounts.needs_setup():
                    raise AccessError("Initial setup is already complete.",409)
                user = s.accounts.create_user(data.get("username"),data.get("password"),setup_code=data.get("setupCode") or "")
                session = s.accounts.new_session(user["id"])
                (s.path/"setup-code.txt").unlink(missing_ok=True)
                self.setup_code = None
            else:
                session = s.accounts.login(data.get("username"),data.get("password"),request.environ.get("REMOTE_ADDR","unknown"))
            return json_response({"user":{**session["user"],"csrf":session["csrf"]}},headers=[("Set-Cookie",self.cookie(session["token"]))])
        if path=="/api/lookup":
            # A narrowly scoped read-through of allowlisted public publisher data.
            # Account, inventory, source configuration, and collector controls stay protected.
            if self.config["public_catalog"]:
                self.origin_check(request)
            else:
                self.mutation(request,scope="scan")
            identifier = data.get("id","")
            if not isinstance(identifier,str) or len(identifier)>120 or not (CVE_RE.fullmatch(identifier) or GHSA_RE.fullmatch(identifier)):
                raise ValueError("Enter a complete CVE or GHSA identifier.")
            self.rate((request.environ.get("REMOTE_ADDR"),"public-lookup"),6,60)
            self.rate(("instance","public-lookup"),20,60)
            if not self.lookup_slots.acquire(blocking=False):
                raise AccessError("Publisher lookups are busy. Try again shortly.",429)
            try:
                record = s.ingestor.enrich(identifier)
            finally:
                self.lookup_slots.release()
            if not record:
                raise AccessError("No publisher record could be retrieved for this identifier. Check the identifier and source status.",404)
            return json_response({"record":record})
        scope = "inventory:write" if path in {"/api/inventories","/api/inventories/replace"} else "scan"
        if path=="/api/inventories/action" and data.get("action")!="scan":
            scope = "inventory:write"
        admin = path in {"/api/users","/api/users/disable","/api/sync","/api/backfill"}
        user = self.mutation(request,scope=scope,admin=admin)
        if user.get("api_token"):
            permitted = path in {"/api/inventories","/api/inventories/replace","/api/inventories/action","/api/package","/api/enrich"}
            if not permitted:
                raise AccessError("This action requires an interactive session.",403)
            if path in {"/api/inventories","/api/inventories/replace"} and (path=="/api/inventories/replace" or data.get("scan",True)) and "scan" not in user["scopes"]:
                raise AccessError("Importing and checking requires both inventory:write and scan scopes. Use scan:false to save without checking.",403)
            if path=="/api/inventories/action" and data.get("action")!="scan" and "inventory:write" not in user["scopes"]:
                raise AccessError("The token cannot modify inventories.",403)
        owner = user["id"]
        self.rate((owner,"mutations"),90)
        if path=="/api/auth/logout":
            if user.get("api_token"):
                raise AccessError("Use token revocation for API credentials.",400)
            s.accounts.logout(request.token)
            return json_response({"signedOut":True},headers=[("Set-Cookie",self.cookie())])
        if path=="/api/auth/password":
            s.accounts.change_password(owner,data.get("current"),data.get("password"))
            return json_response({"changed":True},headers=[("Set-Cookie",self.cookie())])
        if path=="/api/inventories":
            self.rate((owner,"upload"),10,60)
            parsed = parse_document(data.get("filename",""),data.get("content"))
            result = s.workspace.add(owner,data.get("name"),parsed,data.get("exposed",False),data.get("criticality",3))
            if data.get("scan",True) is True:
                s.workspace.configure(owner,result["inventory"]["id"],"scan")
                s.wake.set()
            return json_response(result,201)
        if path=="/api/inventories/replace":
            self.rate((owner,"upload"),10,60)
            result = s.workspace.replace(owner,data.get("id"),parse_document(data.get("filename",""),data.get("content")))
            s.wake.set()
            return json_response(result)
        if path=="/api/inventories/action":
            if data.get("action") in {"delete","settings"} and user.get("api_token") and "inventory:write" not in user["scopes"]:
                raise AccessError("The token cannot modify inventories.",403)
            result = s.workspace.configure(owner,data.get("id"),data.get("action"),data)
            s.wake.set()
            return json_response(result)
        if path=="/api/findings/status":
            return json_response(s.workspace.remediate(owner,data.get("id"),data.get("status"),data.get("note","")))
        if path=="/api/profile":
            return json_response(s.workspace.profile(owner,data))
        if path=="/api/highlights":
            self.rate((owner,"highlights"),12,60)
            return json_response(s.highlights.create(owner,data),201)
        if path=="/api/highlights/action":
            return json_response(s.highlights.configure(owner,data.get("id"),data.get("action")))
        if path=="/api/ai/explain":
            self.rate((owner,"ai-explain"),6,3600)
            identifier = data.get("id","")
            if not isinstance(identifier,str) or not IDENTIFIER.fullmatch(identifier):
                raise ValueError("Enter a valid collected vulnerability identifier.")
            record = s.catalog.record(identifier)
            if not record:
                raise AccessError("This record has not been imported.",404)
            if not self.ai_slots.acquire(blocking=False):
                raise AccessError("An AI explanation is already running. Try again shortly.",429)
            try:
                return json_response(s.ai.explain(record))
            finally:
                self.ai_slots.release()
        if path=="/api/watch-rules":
            result = s.alerts.create(owner,data);s.wake.set();return json_response(result,201)
        if path=="/api/watch-rules/action":
            return json_response(s.alerts.configure(owner,data.get("id"),data.get("action")))
        if path=="/api/alerts/read":
            return json_response(s.alerts.mark_read(owner,data.get("id")))
        if path=="/api/alerts/feed":
            return json_response(s.alerts.issue_feed(owner))
        if path in {"/api/tokens","/api/tokens/revoke"}:
            if user.get("api_token"):
                raise AccessError("Manage tokens from an interactive session.",403)
            if path.endswith("revoke"):
                s.accounts.revoke_token(owner,data.get("digest"));return json_response({"revoked":True})
            return json_response(s.accounts.issue_api_token(owner,data.get("name"),data.get("scopes")),201)
        if path=="/api/users":
            return json_response(s.accounts.create_user(data.get("username"),data.get("password"),data.get("role","member")),201)
        if path=="/api/users/disable":
            s.accounts.disable(owner,int(data.get("id")));return json_response({"disabled":True})
        if path=="/api/sync":
            if self.config["sync_mode"]!="embedded":
                return json_response({"message":"This instance uses an external collector. Run the configured sync job."},409)
            return json_response(s.ingestor.request(),202)
        if path=="/api/backfill":
            return json_response(s.backfill.configure(data.get("action")))
        if path=="/api/vendor-sources":
            result = s.vendors.create(owner,data.get("name"),data.get("url"),data.get("document"),data.get("trusted",False));s.wake.set()
            return json_response(result,201)
        if path=="/api/vendor-sources/action":
            return json_response(s.vendors.configure(owner,data.get("id"),data.get("action")))
        if path=="/api/enrich":
            self.rate((owner,"enrich"),6,60)
            identifier = data.get("id","")
            if not isinstance(identifier,str) or not IDENTIFIER.fullmatch(identifier):
                raise ValueError("Invalid vulnerability identifier.")
            return json_response({"record":s.ingestor.enrich(identifier,data.get("osv"))})
        if path=="/api/package":
            self.rate((owner,"package"),12,60)
            component = normalize_component(data)
            if not component or component["skipReason"]:
                raise ValueError("Supply a supported ecosystem, package name and exact version.")
            return json_response(s.ingestor.package(component["ecosystem"],component["name"],component["version"]))
        raise AccessError("Endpoint not found.",404)

    def export(self,kind):
        if kind not in {"json","csv"}:
            raise ValueError("Choose JSON or CSV.")
        def body():
            if kind=="json":
                yield ('{"exportedAt":'+json.dumps(now())+',"records":[').encode()
                first = True
                for record in self.services.catalog.iter_records():
                    yield (("" if first else ",")+json.dumps(record,ensure_ascii=False,allow_nan=False)).encode()
                    first = False
                yield b"]}"
            else:
                buffer = io.StringIO(newline="")
                writer = csv.writer(buffer)
                fields = ["id","title","vendor","product","cvss","epss","epssDate","kev","published"]
                writer.writerow(fields);yield buffer.getvalue().encode("utf-8-sig")
                for record in self.services.catalog.iter_records():
                    buffer.seek(0);buffer.truncate(0)
                    row = [str(record.get(k) if record.get(k) is not None else "") for k in fields]
                    writer.writerow(["'"+v if v.lstrip().startswith(("=","+","-","@")) else v for v in row])
                    yield buffer.getvalue().encode()
        return Response(body(),content_type=JSON_TYPE if kind=="json" else "text/csv; charset=utf-8",headers=[("Content-Disposition",f'attachment; filename="MasterMonk-intelligence.{kind}"')])

    def sitemap(self,path):
        origin = self.config["origin"]
        if not self.config["public_catalog"] or not origin:
            raise AccessError("Public indexing is disabled.",404)
        with self.services.catalog.connection() as db:
            total = db.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            if path=="/sitemap.xml":
                pages = max(1,(total+9999)//10000)
                xml = '<?xml version="1.0" encoding="UTF-8"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+''.join(
                    '<sitemap><loc>'+html.escape(origin)+f'/sitemaps/catalog-{i}.xml</loc></sitemap>' for i in range(pages))+'</sitemapindex>'
            else:
                match = re.fullmatch(r"/sitemaps/catalog-(\d+)\.xml",path)
                if not match or int(match[1])*10000>total:
                    raise AccessError("Sitemap not found.",404)
                rows = db.execute("SELECT id FROM records ORDER BY id LIMIT 10000 OFFSET ?",(int(match[1])*10000,)).fetchall()
                xml = '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+''.join(
                    '<url><loc>'+html.escape(origin+'/vulnerability/'+urllib.parse.quote(r[0],safe=""))+'</loc></url>' for r in rows)+'</urlset>'
        return Response(xml,content_type="application/xml; charset=utf-8")


def record_page(record,home="/"):
    esc = html.escape
    references = ''.join('<li><a rel="noopener noreferrer" href="'+esc(s["url"],quote=True)+'">'+esc(s["id"])+"</a></li>" for s in record["sources"] if safe_url(s["url"]))
    body = f'<h1>{esc(record["id"])}</h1><h2>{esc(record["title"])}</h2><p>{esc(record["description"])}</p><dl><dt>Severity</dt><dd>{esc(record["severity"])}</dd><dt>Known exploitation</dt><dd>{"CISA KEV" if record["kev"] else "Not in the imported KEV catalog"}</dd><dt>CVSS</dt><dd>{esc(str(record.get("cvss") if record.get("cvss") is not None else "Unknown"))}</dd></dl><h2>Sources</h2><ul>{references}</ul>'
    asset_root = esc(home,quote=True)+'static/'
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>'+esc(record["id"]+' · MasterMonk')+'</title><meta name="description" content="'+esc(record["title"][:160],quote=True)+'"><link rel="icon" href="'+asset_root+'icons/favicon-64.png"><link rel="stylesheet" href="'+asset_root+'style.css"><link rel="stylesheet" href="'+asset_root+'cosmos.css"></head><body><main class="public-record"><a class="brand" href="'+esc(home,quote=True)+'"><img src="'+asset_root+'media/mastermonk-logo.png" width="66" height="38" alt="">MasterMonk</a>'+body+'</main></body></html>'
