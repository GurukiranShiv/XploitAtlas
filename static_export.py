"""Export only collected public intelligence to a standalone static website."""
from __future__ import annotations
import html
import hashlib
import json
import re
import shutil
import tempfile
import urllib.parse
from pathlib import Path
from config import ROOT,VERSION
from core import now,summary
from webapp import record_page

ASSETS=("style.css","cosmos.css","ui.js","site.js","space-geometry.js","universe.js","universe-canvas.js","universe-webgl.js","universe-layout.js","renderer-status.js")


def export_site(catalog,output,limit=10000,base_url=""):
    if not 1<=limit<=10000:
        raise ValueError("Export between 1 and 10,000 public records.")
    target=Path(output).expanduser().resolve()
    if target==ROOT or target in ROOT.parents or target==Path(catalog.path).parent:
        raise ValueError("Choose a separate, empty export folder.")
    if target.exists() and any(target.iterdir()):
        raise ValueError("The export folder must be empty. Export to a new folder before replacing a published snapshot.")
    if base_url:
        parsed=urllib.parse.urlsplit(base_url)
        if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Use the public HTTPS site URL, including its project path when applicable.")
    with catalog.connection() as db:
        total=db.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    if not total:
        raise ValueError("Collect real source records before exporting a site.")
    target.parent.mkdir(parents=True,exist_ok=True)
    stage=Path(tempfile.mkdtemp(prefix=".mastermonk-site-",dir=target.parent))
    try:
        static=stage/"static";static.mkdir()
        for name in ASSETS:
            shutil.copy2(ROOT/"static"/name,static/name)
        for directory in ("fonts","vendor","media","icons"):
            shutil.copytree(ROOT/"static"/directory,static/directory,ignore=shutil.ignore_patterns("__pycache__"))
        (stage/"vulnerability").mkdir()
        records=[]
        for record in catalog.iter_records():
            if len(records)>=limit:
                break
            filename = record["id"] if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}",record["id"]) else "record-"+hashlib.sha256(record["id"].encode()).hexdigest()[:24]
            page = "vulnerability/"+filename+".html"
            records.append({**summary(record),"pagePath":page})
            (stage/page).write_text(record_page(record,"../"),encoding="utf-8")
        snapshot={"application":"MasterMonk","version":VERSION,"exportedAt":now(),"lastSuccess":catalog.state("last_success"),
                  "totalCollected":total,"exportedRecords":len(records),"records":records,"sources":catalog.sources(),
                  "epss":catalog.state("epss_bulk",{}),"baseline":catalog.state("created_at")}
        (stage/"snapshot.json").write_text(json.dumps(snapshot,ensure_ascii=False,allow_nan=False,separators=(",",":")),encoding="utf-8")
        (stage/"index.html").write_text((ROOT/"static/site.html").read_text(encoding="utf-8"),encoding="utf-8")
        (stage/".nojekyll").touch()
        if base_url:
            base=base_url.rstrip("/")
            entries=['<url><loc>'+html.escape(base+'/')+'</loc></url>']
            entries.extend('<url><loc>'+html.escape(base+'/'+r["pagePath"])+'</loc></url>' for r in records)
            (stage/"sitemap.xml").write_text('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+''.join(entries)+'</urlset>',encoding="utf-8")
            (stage/"robots.txt").write_text("User-agent: *\nAllow: /\nSitemap: "+base+"/sitemap.xml\n",encoding="utf-8")
        if target.exists():
            target.rmdir()
        stage.replace(target)
        return {"folder":str(target),"publicRecords":len(records),"totalCollected":total,"exportedAt":snapshot["exportedAt"]}
    finally:
        if stage.exists():
            shutil.rmtree(stage)
