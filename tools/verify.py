"""Verify the actual distribution and an empty first run. No fixtures or seeded data."""
from __future__ import annotations
import argparse,ast,hashlib,json,os,re,shutil,socket,sqlite3,subprocess,sys,tempfile,time,urllib.error,urllib.request,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

def run(command,cwd=ROOT):
    result=subprocess.run(command,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120)
    if result.returncode:
        raise RuntimeError(result.stdout[-2000:])
    return result.stdout.strip()

def startup(root):
    with tempfile.TemporaryDirectory(prefix="mastermonk-first-run-") as directory:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
        with tempfile.TemporaryFile() as log:
            process=subprocess.Popen([sys.executable,"-E",str(root/"start.py"),"--no-sync","--host","127.0.0.1",
                                      "--port",str(port),"--data-dir",directory],cwd=root,stdout=log,stderr=log)
            try:
                base="http://127.0.0.1:"+str(port)
                for _ in range(150):
                    if process.poll() is not None:
                        raise RuntimeError("The application exited before becoming ready.")
                    try:
                        with urllib.request.urlopen(base+"/api/health",timeout=1) as response:
                            health=json.load(response)
                        break
                    except OSError:
                        time.sleep(.2)
                else:
                    raise RuntimeError("First-run readiness timed out.")
                if health.get("status")!="ok":
                    raise RuntimeError("Unexpected health response.")
                with urllib.request.urlopen(base+"/api/session",timeout=5) as response:
                    session=json.load(response)
                if not session["needsSetup"] or session["user"] is not None:
                    raise RuntimeError("A fresh download unexpectedly contains an account.")
                if session["publicCatalog"]:
                    today=time.strftime("%Y-%m-%d",time.gmtime())
                    for endpoint in ("/api/catalog","/api/universe?severity=High","/api/universe?severity=Unknown","/api/events",
                                     "/api/trends?days=90&basis=source","/api/trends?days=90&basis=observed",
                                     "/api/trend-records?basis=source&metric=published&start="+today+"&end="+today,
                                     "/api/compare?from="+today+"&to="+today,
                                     "/api/sources","/api/status"):
                        with urllib.request.urlopen(base+endpoint,timeout=5) as response:
                            value=json.load(response)
                        if "records" in value and value["records"]:
                            raise RuntimeError("A fresh download unexpectedly contains catalog records.")
                        if "groups" in value and (any(g["records"] or g["total"] for g in value["groups"].values()) or value["differences"]):
                            raise RuntimeError("An empty comparison contains observations.")
                    for endpoint in ("/api/component-compare","/badge/component.svg"):
                        try:
                            with urllib.request.urlopen(base+endpoint,timeout=5):
                                raise RuntimeError("An exact-component endpoint accepted missing input: "+endpoint)
                        except urllib.error.HTTPError as error:
                            if error.code!=400:
                                raise
                for endpoint in ("/api/inventories","/api/findings","/api/users","/api/tokens","/api/highlights","/api/ai/status"):
                    try:
                        with urllib.request.urlopen(base+endpoint,timeout=5):
                            raise RuntimeError("A private resource is available without authentication: "+endpoint)
                    except urllib.error.HTTPError as error:
                        if error.code!=401:
                            raise
                with urllib.request.urlopen(base+"/static/index.html",timeout=5) as response:
                    interface=response.read()
                    if any(marker not in interface for marker in (b"MasterMonk",b"manifest.webmanifest",b"install-app-button",b'href="#components"',b"universe-fullscreen",b"universe-control-panel",b"cosmos-evidence-drawer",b"universe-live-state",b"cosmos-warp",b"3D \xc2\xb7 Deep field")):
                        raise RuntimeError("Application assets were not served.")
                with urllib.request.urlopen(base+"/manifest.webmanifest",timeout=5) as response:
                    manifest=json.load(response)
                if manifest.get("name")!="MasterMonk" or manifest.get("display")!="standalone" or len(manifest.get("icons",[]))<2:
                    raise RuntimeError("The cross-platform application manifest is incomplete.")
                with urllib.request.urlopen(base+"/service-worker.js",timeout=5) as response:
                    worker=response.read()
                    if response.headers.get("Service-Worker-Allowed")!="/":
                        raise RuntimeError("The service worker is not allowed to control the application root.")
                if b"/api/" not in worker or b"cache.addAll(SHELL)" not in worker or b"vulnerability data" not in worker:
                    raise RuntimeError("The application-shell cache policy is incomplete.")
                for asset in re.findall(r"['\"](/static/[^'\"]+)['\"]",worker.decode()):
                    if not (root/asset.lstrip("/")).is_file():
                        raise RuntimeError("An installable-app asset is missing: "+asset)
                for asset,mime in (("/static/media/mastermonk-logo.png","image/png"),("/static/media/deep-field.webp","image/webp"),
                                   ("/static/icons/favicon-64.png","image/png"),("/static/cosmos.css","text/css"),
                                   ("/static/briefing.js","text/javascript"),("/static/space-geometry.js","text/javascript")):
                    with urllib.request.urlopen(base+asset,timeout=5) as response:
                        if response.headers.get("Content-Type","").split(";")[0]!=mime or not response.read():
                            raise RuntimeError("An Evidence Cosmos asset was not served correctly: "+asset)
                with urllib.request.urlopen(base+"/static/osint.js",timeout=5) as response:
                    if b"REAL-RECORD INVESTIGATION LAB" not in response.read():
                        raise RuntimeError("The investigation lab asset was not served.")
                with sqlite3.connect(Path(directory)/"mastermonk.sqlite3") as db:
                    if db.execute("SELECT COUNT(*) FROM records").fetchone()[0]:
                        raise RuntimeError("A fresh download unexpectedly contains vulnerability records.")
                with sqlite3.connect(Path(directory)/"workspace.sqlite3") as db:
                    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                        raise RuntimeError("A fresh download unexpectedly contains accounts.")
                    if db.execute("SELECT COUNT(*) FROM highlights").fetchone()[0] or db.execute("SELECT COUNT(*) FROM highlight_items").fetchone()[0]:
                        raise RuntimeError("A fresh download unexpectedly contains curated pages.")
                return {"health":"ok","publicCatalog":session["publicCatalog"],"privateResources":"authentication required","initialAccounts":0,"initialRecords":0,"initialHighlights":0,"comparison":"empty date queries pass","componentRoutes":"public input validation passed","evidenceCosmosAssets":"served"}
            finally:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill();process.wait(timeout=5)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live",action="store_true",help="Check this project's actual dependency manifest against live CISA and OSV.")
    args=parser.parse_args()
    from source_package import source_paths,build_source_archive
    unit_output=run([sys.executable,"-E","-m","unittest","discover","-s","tests","-q"])
    files=source_paths()
    for relative,path in files:
        if path.suffix==".py": ast.parse(path.read_text(encoding="utf-8"),filename=relative)
        if path.suffix not in {".png",".webp",".woff2"} and relative!="static/vendor/three.js":
            branding=path.read_text(encoding="utf-8",errors="ignore").lower()
            if "xploit"+"atlas" in branding or "vuln"+"orbit" in branding:
                raise RuntimeError("Previous product identity remains in "+relative)
        if relative.startswith("tests/") and re.search(r"CVE-\d{4}-\d{4,}",path.read_text(encoding="utf-8",errors="ignore"),re.IGNORECASE):
            raise RuntimeError("Unit tests contain a synthetic-looking CVE identifier: "+relative)
    node=shutil.which("node");javascript=0
    if node:
        for relative,path in files:
            if path.suffix in {".js",".mjs"}:
                run([node,"--check",str(path)]);javascript+=1
        run([node,"--input-type=module","-e", """
            import * as T from './static/vendor/three.js';
            import {componentComparisonView} from './static/briefing.js';
            import {readFileSync,readdirSync} from 'node:fs';
            for(const f of readdirSync('static').filter(f=>f.endsWith('.js'))){
              if(['app.js','site.js','sw.js'].includes(f))continue;
              await import('./static/'+f);
              for(const match of readFileSync('static/'+f,'utf8').matchAll(/\\bT\\.(\\w+)/g))
                if(!(match[1] in T))throw Error(f+': missing graphics export '+match[1]);
            }
            const componentUI=componentComparisonView({left:{ecosystem:'npm',name:'',version:''},right:{ecosystem:'npm',name:'',version:''},result:null},'http://127.0.0.1:8787');
            for(const marker of ['component-compare-form','left_ecosystem','right_version','component-results'])
              if(!componentUI.includes(marker))throw Error('component comparison UI is missing '+marker);
        """])
    from html.parser import HTMLParser
    shipped = {relative for relative,_ in files}
    class AssetParser(HTMLParser):
        def handle_starttag(self,tag,attrs):
            for key,value in attrs:
                if key in {"src","href"} and value and value.startswith(("/static/","./static/")):
                    path = value.removeprefix("./").lstrip("/")
                    if path not in shipped:
                        raise RuntimeError("An HTML asset is absent from the download: "+path)
    for relative,path in files:
        if path.suffix==".html": AssetParser().feed(path.read_text(encoding="utf-8"))
    metadata=json.loads((ROOT/"static/vendor/BUILD.json").read_text())
    if hashlib.sha256((ROOT/"static/vendor/three.js").read_bytes()).hexdigest()!=metadata["sha256"]:
        raise RuntimeError("The graphics library does not match its provenance record.")
    renderer=(ROOT/"static/universe-webgl.js").read_text(encoding="utf-8")
    if "RingGeometry" in renderer or "TorusGeometry" not in renderer:
        raise RuntimeError("The WebGL KEV orbit does not match the bundled graphics exports.")
    run([sys.executable,"-E","start.py","--help"])
    run([sys.executable,"-E","mastermonk.py","--help"])
    if os.name=="nt":
        run([os.environ.get("COMSPEC","cmd.exe"),"/d","/c","START_WINDOWS.bat","--check-python"])
    else:
        run(["sh","START.sh","--check-python"])
        if sys.platform=="darwin": run(["sh","START_MACOS.command","--check-python"])
    source=startup(ROOT);payload=build_source_archive()
    with tempfile.TemporaryDirectory(prefix="mastermonk-download-") as directory:
        path=Path(directory)/"release.zip";path.write_bytes(payload)
        with zipfile.ZipFile(path) as archive: archive.extractall(directory)
        extracted_result=startup(Path(directory)/"MasterMonk")
    result={"sourceFiles":len(files),"pythonSyntax":"valid","unitTests":"passed","javascriptModulesChecked":javascript,
            "graphicsIntegrity":"verified","graphicsExports":"verified" if node else "not checked","pwaManifest":"verified","serviceWorker":"application shell only",
            "previousBrandNames":"absent","startup":source,"freshDownload":extracted_result}
    if args.live:
        with tempfile.TemporaryDirectory(prefix="mastermonk-live-review-") as directory:
            report=Path(directory)/"dependencies.json"
            runtime=Path(directory)/"actual-source-observations"
            process=subprocess.run([sys.executable,"-E","mastermonk.py","check","requirements.txt","--format","json","--output",str(report),"--data-dir",str(runtime)],cwd=ROOT,timeout=240)
            if not report.exists(): raise RuntimeError("The real dependency check did not produce a report.")
            outcome=json.loads(report.read_text())
            result["realDependencyCheck"]={"policy":outcome["policy"],"components":len(outcome["checks"]),"observedAt":outcome["observedAt"]}
            from store import Store
            from taxonomy import Taxonomy
            catalog=Store(runtime/"mastermonk.sqlite3")
            records=catalog.catalog(limit=10000)["records"]
            day=outcome["observedAt"][:10]
            comparison=catalog.compare(day,day)
            if not records or comparison["groups"]["indexed"]["total"]!=len(records):
                raise RuntimeError("The date comparison did not match the actual first collection.")
            if any(not record.get("firstObserved") for record in records):
                raise RuntimeError("Real collected records are missing their indexing timestamp.")
            result["liveComparison"]={"collectedRecords":len(records),"indexedInPeriod":comparison["groups"]["indexed"]["total"]}
            from components import ComponentEvidence,badge_svg
            from feeds import Ingestor
            from manifests import parse_document
            import xml.etree.ElementTree as ET
            dependency=parse_document("requirements.txt",(ROOT/"requirements.txt").read_text())["components"][0]
            component_ingestor=Ingestor(catalog,runtime)
            try:
                component_result=ComponentEvidence(component_ingestor).compare(dependency,dependency)
            finally:
                component_ingestor.close()
            if component_result["common"]["total"]!=component_result["left"]["summary"]["total"] or component_result["onlyLeft"]["total"] or component_result["onlyRight"]["total"]:
                raise RuntimeError("The actual dependency did not compare consistently with itself.")
            ET.fromstring(badge_svg(dependency,component_result["left"]))
            result["liveComponentEvidence"]={"component":dependency["name"],"version":dependency["version"],
                                              "osvMatches":component_result["left"]["summary"]["total"],
                                              "complete":component_result["complete"],"badge":"valid SVG"}
            record=next((record for record in records if record.get("cwes")),None)
            if record:
                try:
                    related=Taxonomy(runtime).for_record(record)
                    result["mitreTaxonomy"]={"available":True,"record":record["id"],"source":related["source"],"retrievedAt":related.get("retrievedAt"),"relatedPatterns":len(related["patterns"])}
                except ValueError as error:
                    result["mitreTaxonomy"]={"available":False,"reason":str(error)}
            print(json.dumps(result,indent=2));return process.returncode
    print(json.dumps(result,indent=2));return 0
if __name__=="__main__": raise SystemExit(main())
