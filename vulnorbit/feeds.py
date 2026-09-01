"""Bounded upstream HTTP, incremental imports, and a browser-independent scheduler."""
from __future__ import annotations
import gzip
import hashlib
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import adapters
from core import CVE_RE, GHSA_RE, SOURCE_META, now, merge

LOG = logging.getLogger("vulnorbit")
HOSTS = {"www.cisa.gov", "raw.githubusercontent.com", "services.nvd.nist.gov",
         "api.first.org", "api.github.com", "cveawg.mitre.org", "api.osv.dev"}
MAX_BYTES = 32 * 1024 * 1024

class FeedError(RuntimeError):
    def __init__(self, message, retry_seconds=900):
        super().__init__(message)
        self.retry_seconds = max(60, min(int(retry_seconds), 86400))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FeedError("Unexpected upstream redirect; source URL needs review.")

@dataclass
class Fetched:
    data: object
    url: str
    observed_at: str
    headers: dict

class Client:
    def __init__(self, store, runtime):
        self.store = store
        self.raw_dir = Path(runtime) / "raw"
        self.opener = urllib.request.build_opener(NoRedirect)
        self.host_locks = {h: threading.Lock() for h in HOSTS}
        self.last_request = {}
        self.nvd_key = os.getenv("NVD_API_KEY", "").strip()
        self.github_token = os.getenv("GITHUB_TOKEN", "").strip()

    def get(self, url, source, body=None, capture=True):
        p = urllib.parse.urlsplit(url)
        if p.scheme != "https" or p.hostname not in HOSTS or p.username or p.password:
            raise FeedError("Unsupported source address.")
        headers = {"Accept": "application/json", "User-Agent": "VulnOrbit/1.0 (open-source vulnerability observatory)"}
        if p.hostname == "services.nvd.nist.gov" and self.nvd_key:
            headers["apiKey"] = self.nvd_key
        if p.hostname == "api.github.com" and self.github_token:
            headers["Authorization"] = "Bearer " + self.github_token
        payload = None
        if body is not None:
            payload = json.dumps(body, allow_nan=False).encode()
            headers["Content-Type"] = "application/json"
        with self.host_locks[p.hostname]:
            delay = 0.7 if self.nvd_key else 6.2
            if p.hostname == "services.nvd.nist.gov":
                remaining = self.last_request.get(p.hostname, 0) + delay - time.monotonic()
                if remaining > 0:
                    time.sleep(remaining)
            self.last_request[p.hostname] = time.monotonic()
            try:
                req = urllib.request.Request(url, data=payload, headers=headers, method="POST" if body is not None else "GET")
                with self.opener.open(req, timeout=28) as response:
                    raw = response.read(MAX_BYTES + 1)
                    response_headers = dict(response.headers)
                    if len(raw) > MAX_BYTES:
                        raise FeedError("Upstream response exceeded the 32 MiB import limit.")
                data = json.loads(raw, parse_constant=lambda x: (_ for _ in ()).throw(ValueError("Invalid JSON numeric constant")))
            except urllib.error.HTTPError as exc:
                retry = exc.headers.get("Retry-After", "") if exc.headers else ""
                retry_seconds = int(retry) if retry.isdigit() else 900
                raise FeedError(f"{p.hostname} returned HTTP {exc.code}; previous observations retained.", retry_seconds) from None
            except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
                raise FeedError(f"{p.hostname}: {type(exc).__name__}; previous observations retained.") from None
        observed = now()
        if capture:
            digest = hashlib.sha256(raw).hexdigest()
            directory = self.raw_dir / source
            directory.mkdir(parents=True, exist_ok=True)
            destination = directory / (digest + ".json.gz")
            if not destination.exists():
                destination.write_bytes(gzip.compress(raw, mtime=0))
            self.store.audit_fetch(source, url, observed, raw)
        return Fetched(data, url, observed, response_headers)

    def cleanup(self, retention_days=30):
        cutoff = time.time() - retention_days * 86400
        if self.raw_dir.exists():
            for file in self.raw_dir.glob("*/*.json.gz"):
                try:
                    if file.stat().st_mtime < cutoff:
                        file.unlink()
                except OSError:
                    pass

class Ingestor:
    def __init__(self, store, runtime, interval=900):
        self.store, self.client = store, Client(store, runtime)
        self.interval = max(300, int(interval))
        self.lock = threading.Lock()
        self.stop_event, self.wake_event = threading.Event(), threading.Event()
        self.last_manual = 0.0
        self.running = False
        self.thread = None
        self.enrichment_locks = {}
        self.enrichment_guard = threading.Lock()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._loop, name="vulnorbit-scheduler", daemon=True)
        self.thread.start()

    def close(self):
        self.stop_event.set()
        self.wake_event.set()
        if self.thread:
            self.thread.join(timeout=3)

    def request(self):
        if self.running:
            return {"accepted": False, "message": "A synchronization is already running."}
        if time.monotonic() - self.last_manual < 60:
            return {"accepted": False, "message": "Please allow one minute between manual refreshes."}
        self.last_manual = time.monotonic()
        self.wake_event.set()
        return {"accepted": True, "message": "Real-source refresh queued."}

    def _loop(self):
        while not self.stop_event.is_set():
            self.wake_event.clear()
            try:
                self.sync()
            except Exception:
                LOG.exception("Synchronization failed")
            self.wake_event.wait(self.interval)

    def _source(self, source, callback):
        status = next(s for s in self.store.sources() if s["id"] == source)
        if status.get("retryAt") and status["retryAt"] > now():
            return False
        self.store.health(source, lastAttempt=now(), message="Fetching upstream records.")
        try:
            callback()
            return True
        except Exception as exc:
            retry = getattr(exc, "retry_seconds", self.interval)
            retry_at = (datetime.now(timezone.utc) + timedelta(seconds=retry)).isoformat(timespec="seconds").replace("+00:00", "Z")
            self.store.health(source, state="error", lastAttempt=now(), message=str(exc)[:350], retryAt=retry_at)
            LOG.warning("%s unavailable: %s", source, exc)
            return False

    def sync(self):
        if not self.lock.acquire(blocking=False):
            return False
        self.running = True
        started = now()
        self.store.set_state("sync", {"running": True, "startedAt": started, "completedAt": None})
        try:
            succeeded = []
            for name, callback in (("cisa", self._cisa), ("github", self._github), ("nvd", self._nvd), ("epss", self._epss)):
                if self.stop_event.is_set():
                    break
                if self._source(name, callback):
                    succeeded.append(name)
            completed = now()
            next_at = (datetime.now(timezone.utc) + timedelta(seconds=self.interval)).isoformat(timespec="seconds").replace("+00:00", "Z")
            self.store.set_state("sync", {"running": False, "startedAt": started, "completedAt": completed,
                                         "successfulSources": succeeded, "nextAt": next_at, "intervalSeconds": self.interval})
            if succeeded:
                self.store.set_state("last_success", completed)
            self.client.cleanup()
            return bool(succeeded)
        finally:
            self.running = False
            self.lock.release()

    def _cisa(self):
        urls = ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"]
        error = None
        for url in urls:
            try:
                response = self.client.get(url, "cisa")
                signals = adapters.cisa(response.data, response.observed_at, url)
                self.store.ingest("cisa", signals, complete_catalog=True)
                self.store.health("cisa", state="ok", url=url,
                                  message="Complete official catalog saved.",
                                  coverage=f"{len(signals)} catalog entries. Publisher release: {response.data.get('dateReleased', 'not supplied')}.")
                return
            except FeedError as exc:
                error = exc
        raise error or FeedError("No complete CISA catalog returned.")

    def _nvd_window(self, kind):
        key = "nvd_" + kind + "_cursor"
        cursor = self.store.state(key)
        if not cursor:
            cursor = {"start": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(timespec="seconds").replace("+00:00", "Z"),
                      "end": now(), "index": 0}
        if cursor.get("complete"):
            # NVD permits a maximum 120-day date window. Catch up in 119-day chunks
            # after an extended shutdown, preserving the last committed watermark.
            start = datetime.fromisoformat(cursor["end"].replace("Z", "+00:00")) - timedelta(minutes=5)
            end = min(datetime.now(timezone.utc), start + timedelta(days=119))
            cursor = {"start": start.isoformat(timespec="seconds").replace("+00:00", "Z"),
                      "end": end.isoformat(timespec="seconds").replace("+00:00", "Z"), "index": 0}
        prefix = "pub" if kind == "published" else "lastMod"
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({
            prefix + "StartDate": cursor["start"], prefix + "EndDate": cursor["end"],
            "startIndex": cursor["index"], "resultsPerPage": 1000})
        response = self.client.get(url, "nvd")
        signals = adapters.nvd(response.data, response.observed_at, url)
        total = int(response.data.get("totalResults", 0))
        next_index = cursor["index"] + len(response.data["vulnerabilities"])
        if total > cursor["index"] and not signals:
            raise FeedError("NVD pagination did not advance.")
        self.store.ingest("nvd", signals, checkpoint={
            key: {**cursor, "index": next_index, "complete": next_index >= total}})
        return f"{kind}: {min(next_index,total)}/{total} in {cursor['start']} to {cursor['end']}"

    def _nvd(self):
        progress = []
        if not self.store.state("nvd_kev_complete", False):
            index = self.store.state("nvd_kev_index", 0)
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({
                "hasKev": "", "resultsPerPage": 2000, "startIndex": index})
            response = self.client.get(url, "nvd")
            signals = adapters.nvd(response.data, response.observed_at, url)
            total = int(response.data.get("totalResults", 0))
            next_index = index + len(response.data["vulnerabilities"])
            if total > index and not signals:
                raise FeedError("NVD pagination did not advance.")
            self.store.ingest("nvd", signals, checkpoint={
                "nvd_kev_index": next_index, "nvd_kev_complete": next_index >= total})
            progress.append(f"KEV bootstrap: {min(next_index,total)}/{total}")
        # Published and modified windows advance independently. A large modification
        # backlog cannot block the feed of newly published records.
        progress.append(self._nvd_window("published"))
        progress.append(self._nvd_window("modified"))
        self.store.health("nvd", message="Published and modified records saved with durable cursors.",
                          coverage="; ".join(progress) + ". Pages continue on the next cycle.")

    def _github(self):
        cursor = self.store.state("github_cursor")
        if cursor and cursor.get("next"):
            url, end = cursor["next"], cursor["end"]
        else:
            end = now()
            since = self.store.state("github_watermark")
            if not since:
                since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(timespec="seconds").replace("+00:00", "Z")
            params = {"type": "reviewed", "per_page": 100, "sort": "updated", "direction": "asc", "modified": since + ".." + end}
            url = "https://api.github.com/advisories?" + urllib.parse.urlencode(params)
        response = self.client.get(url, "github")
        signals = adapters.github(response.data, response.observed_at, url)
        link = response.headers.get("Link") or response.headers.get("link") or ""
        next_url = next((m.group(1) for m in re.finditer(r'<([^>]+)>;\s*rel="next"', link)), None)
        checkpoint = {"github_cursor": {"next": next_url, "end": end}}
        if not next_url:
            checkpoint["github_watermark"] = (datetime.fromisoformat(end.replace("Z", "+00:00")) - timedelta(minutes=5)).isoformat(timespec="seconds").replace("+00:00", "Z")
        self.store.ingest("github", signals, checkpoint=checkpoint)
        self.store.health("github", message="Reviewed package advisories saved.",
                          coverage=f"{len(signals)} advisories on this page. {'More pages queued.' if next_url else 'Current modified window complete.'}")

    def _epss(self):
        ids = self.store.ids()
        if not ids:
            self.store.health("epss", state="pending", message="Waiting for real CVE records from a catalog source.")
            return
        start = self.store.state("epss_cursor", 0)
        if start >= len(ids):
            start = 0
        chosen = ids[start:start+1000]
        combined = []
        for offset in range(0, len(chosen), 100):
            group = chosen[offset:offset+100]
            url = "https://api.first.org/data/v1/epss?" + urllib.parse.urlencode({"limit": 100, "cve": ",".join(group)})
            response = self.client.get(url, "epss")
            combined.extend(adapters.epss(response.data, response.observed_at, url))
        checkpoint = {"epss_cursor": 0 if start + len(chosen) >= len(ids) else start + len(chosen)}
        self.store.ingest("epss", combined, checkpoint=checkpoint)
        self.store.health("epss", message="Daily scores saved. Missing responses are not converted to zero.",
                          coverage=f"Rotating sweep: {len(chosen)} of {len(ids)} CVEs queried this cycle, {len(combined)} scores supplied.")

    def enrich(self, identifier, osv_id=None):
        if not (CVE_RE.fullmatch(identifier) or GHSA_RE.fullmatch(identifier)):
            return self.store.record(identifier)
        with self.enrichment_guard:
            lock = self.enrichment_locks.setdefault(identifier, threading.Lock())
        if not lock.acquire(blocking=False):
            return self.store.record(identifier)
        try:
            existing = self.store.record(identifier)
            checked = self.store.state("enriched:" + identifier, {})
            has_osv = existing and any(s["id"] == "osv" for s in existing["sources"])
            if checked.get("success") and time.time() - checked["success"] < 21600 and (not osv_id or has_osv):
                return existing
            if time.time() - checked.get("attempt", 0) < 60:
                return existing
            self.store.set_state("enriched:" + identifier, {**checked, "attempt": time.time()})
            successful, resolved_id = [], identifier
            if CVE_RE.fullmatch(identifier):
                def cna():
                    response = self.client.get("https://cveawg.mitre.org/api/cve/" + identifier, "cve")
                    signals = adapters.cve(response.data, response.observed_at, response.url)
                    if any(x["id"] != identifier for x in signals):
                        raise FeedError("Publisher identity does not match the requested CVE.")
                    self.store.ingest("cve", signals)
                    self.store.health("cve", message="Publisher record verified and stored.")
                successful.append(self._source("cve", cna))
            aliases = (existing or {}).get("aliases", [])
            match = osv_id if osv_id and GHSA_RE.fullmatch(osv_id) else next(
                (a for a in aliases if GHSA_RE.fullmatch(a)), identifier if GHSA_RE.fullmatch(identifier) else None)
            if match:
                def osv_record():
                    nonlocal resolved_id
                    response = self.client.get("https://api.osv.dev/v1/vulns/" + match, "osv")
                    signals = adapters.osv(response.data, response.observed_at, response.url)
                    if CVE_RE.fullmatch(identifier) and any(x["id"] != identifier for x in signals):
                        raise FeedError("OSV alias does not match the requested CVE.")
                    if GHSA_RE.fullmatch(identifier) and any(identifier not in x.get("aliases", []) for x in signals):
                        raise FeedError("OSV record does not match the requested advisory.")
                    self.store.ingest("osv", signals)
                    resolved_id = signals[0]["id"]
                    self.store.health("osv", message="OSV package and fixed-version evidence saved.")
                successful.append(self._source("osv", osv_record))
            if successful and all(successful):
                self.store.set_state("enriched:" + identifier, {"attempt": time.time(), "success": time.time()})
            return self.store.record(resolved_id) or existing
        finally:
            lock.release()
            with self.enrichment_guard:
                # Bound cache size; retain a lock another request has already acquired.
                if len(self.enrichment_locks) > 4096:
                    self.enrichment_locks = {k: v for k, v in self.enrichment_locks.items() if v.locked()}

    def package(self, ecosystem, name, version):
        supported = {"npm", "PyPI", "Maven", "Go", "crates.io", "NuGet", "Packagist", "RubyGems"}
        if ecosystem not in supported or not isinstance(name, str) or not name.strip() or len(name) > 200 or not isinstance(version, str) or not version.strip() or len(version) > 100:
            raise ValueError("Provide a supported ecosystem, package name, and exact version.")
        if any(ord(c) < 32 for c in name + version):
            raise ValueError("Package query contains invalid control characters.")
        query = {"package": {"name": name.strip(), "ecosystem": ecosystem}, "version": version.strip()}
        grouped, token = {}, None
        checked = now()
        for _ in range(3):
            body = {**query, **({"page_token": token} if token else {})}
            response = self.client.get("https://api.osv.dev/v1/query", "osv", body=body, capture=False)
            if not isinstance(response.data, dict) or ("vulns" in response.data and not isinstance(response.data["vulns"], list)):
                raise FeedError("OSV returned an invalid package-query response.")
            for v in response.data.get("vulns", []):
                for signal in adapters.osv(v, response.observed_at, response.url):
                    grouped.setdefault(signal["id"], []).append(signal)
            token = response.data.get("next_page_token")
            if not token:
                break
        signals = [signal for group in grouped.values() for signal in group]
        self.store.ingest("osv", signals)
        self.store.health("osv", message="Published package advisories saved; query inputs are not logged.")
        records = [self.store.record(identifier) for identifier in grouped]
        return {"query": query, "records": records, "partial": bool(token), "checkedAt": checked,
                "message": "These are published advisories matching the requested package/version." if records else
                "OSV returned no matching advisories. This does not establish that the package is secure."}
