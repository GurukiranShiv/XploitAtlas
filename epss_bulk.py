"""Daily FIRST EPSS snapshot, streamed and applied to every tracked CVE."""
from __future__ import annotations
import csv
import gzip
import io
import json
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
import urllib.request
import urllib.error
import urllib.parse
import adapters
from core import CVE_RE, now
from feeds import FeedError

URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


class SnapshotRedirect(urllib.request.HTTPRedirectHandler):
    """FIRST's stable URL redirects only to a dated file on the same host."""
    max_repeats = 2
    max_redirections = 2

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url,newurl))
        if (target.scheme!="https" or target.hostname!="epss.empiricalsecurity.com"
                or target.port not in {None,443} or target.username or target.password
                or target.query or target.fragment
                or not re.fullmatch(r"/epss_scores-(?:current|\d{4}-\d{2}-\d{2})\.csv\.gz",target.path)):
            raise FeedError("The EPSS snapshot redirected outside its documented download location.")
        return super().redirect_request(req,fp,code,msg,headers,target.geturl())


def load_snapshot(client, cache):
    cache = Path(cache)
    cache.parent.mkdir(parents=True, exist_ok=True)
    metadata = cache.with_suffix(".json")
    cached = json.loads(metadata.read_text()) if metadata.is_file() else {}
    # Check daily publication every six hours; use the publisher's score date.
    if cache.is_file() and time.time() - cached.get("fetched",0) < 21600:
        return cached
    request = urllib.request.Request(URL, headers={"User-Agent":"MasterMonk/3.2", "Accept":"application/gzip"})
    temp = cache.with_suffix(".tmp")
    compressed = 0
    try:
        opener = urllib.request.build_opener(SnapshotRedirect())
        with opener.open(request, timeout=35) as response, temp.open("wb") as output:
            snapshot_url = response.geturl()
            while True:
                block = response.read(65536)
                if not block:
                    break
                compressed += len(block)
                if compressed > 32*1024*1024:
                    raise FeedError("The EPSS download exceeded its size limit.")
                output.write(block)
        score_date, count = validate_snapshot(temp)
        temp.replace(cache)
        result = {"date":score_date, "rows":count, "fetched":time.time(), "url":snapshot_url, "observedAt":now()}
        metadata.write_text(json.dumps(result))
        return result
    except (OSError, ValueError, EOFError, urllib.error.URLError) as exc:
        raise FeedError("EPSS daily snapshot could not be read: " + type(exc).__name__) from None
    finally:
        temp.unlink(missing_ok=True)


def snapshot_rows(path):
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        header = stream.readline(4096)
        match = re.search(r"score_date\s*:\s*(\d{4}-\d{2}-\d{2})",header)
        if not match:
            raise FeedError("The EPSS snapshot does not identify its score date.")
        score_date = match[1]
        try:
            date = datetime.strptime(score_date, "%Y-%m-%d").date()
        except ValueError:
            raise FeedError("Invalid EPSS score date.") from None
        if date > datetime.now(timezone.utc).date():
            raise FeedError("The EPSS snapshot has a future score date.")
        reader = csv.DictReader(stream)
        if reader.fieldnames != ["cve","epss","percentile"]:
            raise FeedError("Unexpected EPSS CSV columns.")
        size, count = 0, 0
        for row in reader:
            count += 1
            size += sum(len(str(v)) for v in row.values())
            if count > 2000000 or size > 128*1024*1024:
                raise FeedError("The decompressed EPSS snapshot exceeded its limit.")
            if not CVE_RE.fullmatch(row.get("cve", "")):
                raise FeedError("Invalid CVE in the EPSS snapshot.")
            for field in ("epss", "percentile"):
                value = float(row[field])
                if not 0 <= value <= 1:
                    raise FeedError("Invalid probability in the EPSS snapshot.")
            yield {**row,"date":score_date}


def validate_snapshot(path):
    count, last = 0, None
    for row in snapshot_rows(path):
        count += 1
        last = row
    if not count:
        raise FeedError("The EPSS snapshot is empty.")
    return last["date"], count


def refresh(ingestor):
    store, client = ingestor.store, ingestor.client
    with store.connection() as db:
        total = db.execute("SELECT COUNT(*) FROM records WHERE id LIKE 'CVE-%'").fetchone()[0]
    if not total:
        store.health("epss", state="pending", message="Waiting for CVEs.")
        return
    cache = client.raw_dir.parent / "cache" / "epss-current.csv.gz"
    metadata = load_snapshot(client, cache)
    with store.connection() as db:
        wanted = {row[0] for row in db.execute("SELECT id FROM records WHERE id LIKE 'CVE-%' AND COALESCE(json_extract(payload,'$.epssDate'),'')<?",(metadata["date"],))}
    observed, batch, count, matched = now(), [], 0, set()
    for row in snapshot_rows(cache):
        if ingestor.stop_event.is_set():
            raise FeedError("EPSS refresh paused before completion.")
        if row["cve"] not in wanted:
            continue
        if row["cve"] in matched:
            raise FeedError("Duplicate CVE in the EPSS snapshot.")
        matched.add(row["cve"])
        batch.append(row)
        if len(batch) >= 500:
            signals = adapters.epss({"data":batch}, observed, URL)
            store.ingest("epss",signals)
            count += len(batch)
            batch = []
    if batch:
        store.ingest("epss",adapters.epss({"data":batch}, observed, URL))
        count += len(batch)
    with store.connection() as db:
        current = db.execute("SELECT COUNT(*) FROM records WHERE id LIKE 'CVE-%' AND json_extract(payload,'$.epssDate')=?",(metadata["date"],)).fetchone()[0]
    state = {"date":metadata["date"], "updated":count, "current":current, "tracked":total,
             "notSupplied":len(wanted-matched), "completedAt":now(), "publisherRows":metadata["rows"]}
    store.set_state("epss_bulk",state)
    store.health("epss",state="ok",lastSuccess=now(),lastAttempt=now(),count=current,retryAt=None,
                 message=f"Daily snapshot applied to {current:,} tracked CVEs.",
                 coverage=f"Score date {metadata['date']}; {current:,}/{total:,} tracked CVEs have a current score.")
