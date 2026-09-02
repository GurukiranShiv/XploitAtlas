"""Local HTTP service. Only documented upstream providers receive network requests."""
from __future__ import annotations
import argparse
import csv
import gzip
import io
import json
import logging
import mimetypes
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from core import CVE_RE, GHSA_RE, now
from feeds import FeedError, Ingestor
from store import Store
from source_package import build_source_archive

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
LOG = logging.getLogger("vulnorbit")
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
       "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")

class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    def __init__(self, address, store, ingestor, allowed_hosts):
        self.store, self.ingestor = store, ingestor
        self.allowed_hosts = allowed_hosts
        self.rate_lock, self.rates = threading.Lock(), {}
        super().__init__(address, Handler)

    def rate(self, ip, kind, interval):
        with self.rate_lock:
            stamp, key = time.monotonic(), (ip, kind)
            if stamp - self.rates.get(key, -100000) < interval:
                return False
            if len(self.rates) > 4096:
                self.rates = {k: v for k, v in self.rates.items() if stamp-v < 120}
            self.rates[key] = stamp
            return True

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "XploitAtlas"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(35)

    def log_message(self, fmt, *args):
        # Avoid logging package names, version queries, request bodies, or headers.
        LOG.info("%s %s %s", self.client_address[0], self.command,
                 urllib.parse.urlsplit(self.path).path[:240])

    def send_bytes(self, status, content, content_type, headers=None):
        data = content if isinstance(content, bytes) else content.encode("utf-8")
        compressed = len(data) > 2048 and "gzip" in self.headers.get("Accept-Encoding", "") and not content_type.startswith("application/zip")
        if compressed:
            data = gzip.compress(data, compresslevel=5)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store" if self.path.startswith("/api/") else "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Vary", "Accept-Encoding")
        if compressed:
            self.send_header("Content-Encoding", "gzip")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def json(self, status, value):
        self.send_bytes(status, json.dumps(value, ensure_ascii=False, allow_nan=False), "application/json; charset=utf-8")

    def host_allowed(self):
        try:
            host = urllib.parse.urlsplit("//" + self.headers.get("Host", "")).hostname
            return host in self.server.allowed_hosts
        except ValueError:
            return False

    def post_allowed(self):
        origin = self.headers.get("Origin")
        if origin:
            try:
                parsed = urllib.parse.urlsplit(origin)
                return parsed.scheme in ("http", "https") and parsed.netloc == self.headers.get("Host")
            except ValueError:
                return False
        # For a local non-browser caller, require an explicit custom header.
        return self.headers.get("X-VulnOrbit-Client") == "local-cli"

    def health(self):
        state = dict(self.server.store.state("sync", {}))
        state["running"] = self.server.ingestor.running
        state["schedulerActive"] = bool(self.server.ingestor.thread and self.server.ingestor.thread.is_alive())
        return {"now": now(), "sources": self.server.store.sources(), "sync": state,
                "lastSuccess": self.server.store.state("last_success"),
                "baseline": self.server.store.state("created_at"),
                "mode": "real-sources-only"}

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self.host_allowed():
            self.json(403, {"error": "Host not allowed. Configure VULNORBIT_ALLOWED_HOSTS for your deployment."})
            return
        try:
            self.get_route()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            return
        except ValueError as exc:
            self.json(400, {"error": str(exc)[:240]})
        except Exception:
            LOG.exception("GET request failed")
            self.json(500, {"error": "The request failed. Check the application log; existing intelligence is retained."})

    def get_route(self):
        path = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(path.query, max_num_fields=24)
        def arg(name, default=""):
            return params.get(name, [default])[0]
        if path.path == "/api/health":
            self.json(200, self.health())
        elif path.path == "/api/universe":
            query, severity, days = arg("q")[:200], arg("severity", "all"), int(arg("days", "0"))
            if severity not in {"all", "Critical", "High", "Medium", "Low", "None", "Unknown"} or days not in {0, 1, 7, 30, 90, 365}:
                raise ValueError("Invalid filter.")
            limit, offset = int(arg("limit", "5000")), int(arg("offset", "0"))
            if not 1 <= limit <= 10000 or offset < 0:
                raise ValueError("Invalid page.")
            result = self.server.store.catalog(query, severity, arg("kev") == "1", days, arg("sort", "priority"), limit, offset)
            result.update(self.health())
            self.json(200, result)
        elif path.path == "/api/events":
            identifier, before = arg("id"), arg("before")
            if identifier and not (CVE_RE.fullmatch(identifier) or GHSA_RE.fullmatch(identifier)):
                raise ValueError("Enter a valid CVE or GHSA identifier.")
            items = self.server.store.events(identifier or None, limit=160, before=int(before) if before else None)
            self.json(200, {"events": items, "nextBefore": items[-1]["id"] if len(items) == 160 else None,
                            "baseline": self.server.store.state("created_at")})
        elif path.path == "/api/record":
            identifier, alias = arg("id"), arg("osv")
            if not (CVE_RE.fullmatch(identifier) or GHSA_RE.fullmatch(identifier)):
                raise ValueError("Enter a valid CVE or GHSA identifier.")
            record = self.server.store.record(identifier)
            # Explicit enrichment is a POST: GET does not initiate upstream requests.
            self.json(200 if record else 404, {"record": record, "error": None if record else "This record is not yet in the local catalog."})
        elif path.path == "/api/export":
            records = self.server.store.export_records()
            if arg("format", "json") == "csv":
                output = io.StringIO(newline="")
                writer = csv.writer(output)
                fields = ["id", "title", "vendor", "product", "severity", "cvss", "epss", "epssDate", "kev", "kevAdded", "published", "priority", "sourceUrls"]
                writer.writerow(fields)
                def safe_cell(value):
                    string = "" if value is None else str(value)
                    return "'" + string if string.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else string
                for record in records:
                    row = {**record, "priority": record["priority"]["score"],
                           "sourceUrls": " | ".join(dict.fromkeys(s["url"] for s in record["sources"]))}
                    writer.writerow([safe_cell(row.get(f)) for f in fields])
                self.send_bytes(200, "\ufeff" + output.getvalue(), "text/csv; charset=utf-8",
                                {"Content-Disposition": 'attachment; filename="vulnorbit-intelligence.csv"'})
            else:
                payload = {"exportedAt": now(), "sources": self.server.store.sources(), "records": records}
                self.send_bytes(200, json.dumps(payload, ensure_ascii=False, allow_nan=False), "application/json; charset=utf-8",
                                {"Content-Disposition": 'attachment; filename="vulnorbit-intelligence.json"'})
        elif path.path == "/api/source":
            # The same explicit manifest backs the CLI and the in-app download.
            self.send_bytes(200, build_source_archive(ROOT), "application/zip",
                            {"Content-Disposition": 'attachment; filename="XploitAtlas-source.zip"'})
        else:
            relative = "index.html" if path.path == "/" else urllib.parse.unquote(path.path.removeprefix("/static/")) if path.path.startswith("/static/") else None
            if relative is None:
                self.json(404, {"error": "Not found."})
                return
            file = (STATIC / relative).resolve()
            if not file.is_relative_to(STATIC.resolve()) or not file.is_file():
                self.json(404, {"error": "Not found."})
                return
            types = {".js": "text/javascript", ".css": "text/css", ".html": "text/html", ".svg": "image/svg+xml"}
            content_type = types.get(file.suffix, mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            self.send_bytes(200, file.read_bytes(), content_type + ("; charset=utf-8" if content_type.startswith("text/") else ""))

    def do_POST(self):
        if not self.host_allowed() or not self.post_allowed():
            self.close_connection = True
            self.json(403, {"error": "Same-origin request required."})
            return
        try:
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Chunked requests are not accepted.")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 8192:
                raise ValueError("Request body is too large.")
            raw = self.rfile.read(length)
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise ValueError("A JSON object is required.")
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/sync":
                if not self.server.ingestor.thread or not self.server.ingestor.thread.is_alive():
                    self.json(409, {"error": "The scheduler is disabled in this server session."})
                else:
                    result = self.server.ingestor.request()
                    self.json(202 if result["accepted"] else 200, result)
            elif path == "/api/enrich":
                identifier = body.get("id", "")
                alias = body.get("osv")
                if not isinstance(identifier, str) or not (CVE_RE.fullmatch(identifier) or GHSA_RE.fullmatch(identifier)):
                    raise ValueError("Enter a valid CVE or GHSA identifier.")
                if alias is not None and (not isinstance(alias, str) or not GHSA_RE.fullmatch(alias)):
                    raise ValueError("Enter a valid GHSA alias.")
                if not self.server.rate(self.client_address[0], "enrich", 1):
                    self.json(429, {"error": "Please wait a moment before requesting another publisher record."})
                    return
                record = self.server.ingestor.enrich(identifier, alias)
                self.json(200 if record else 404, {"record": record, "sources": self.server.store.sources(),
                          "error": None if record else "The upstream publisher did not supply this record. Check Sources for the response status."})
            elif path == "/api/package":
                if not self.server.rate(self.client_address[0], "package", 3):
                    self.json(429, {"error": "Please wait three seconds between package checks."})
                    return
                self.json(200, self.server.ingestor.package(body.get("ecosystem"), body.get("name"), body.get("version")))
            else:
                self.json(404, {"error": "Not found."})
        except FeedError as exc:
            self.json(502, {"error": str(exc)})
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.close_connection = True
            self.json(400, {"error": str(exc)[:240]})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception:
            LOG.exception("POST request failed")
            self.json(500, {"error": "The request failed. Existing intelligence is retained."})

def main(argv=None):
    parser = argparse.ArgumentParser(description="XploitAtlas: real-source vulnerability intelligence.")
    parser.add_argument("--host", default=os.getenv("VULNORBIT_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("VULNORBIT_PORT", "8787")))
    parser.add_argument("--data-dir", default=os.getenv("VULNORBIT_DATA_DIR", str(ROOT / "runtime")))
    parser.add_argument("--interval", type=int, default=int(os.getenv("VULNORBIT_INTERVAL", "900")))
    parser.add_argument("--once", action="store_true", help="Import one bounded cycle and exit.")
    parser.add_argument("--no-sync", action="store_true", help="Serve the existing catalog without background imports.")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    runtime = Path(args.data_dir).resolve()
    runtime.mkdir(parents=True, exist_ok=True)
    store = Store(runtime / "vulnorbit.sqlite3")
    if not store.state("created_at"):
        store.set_state("created_at", now())
    ingestor = Ingestor(store, runtime, args.interval)
    if args.once:
        success = ingestor.sync()
        print(json.dumps({"stats": store.catalog(limit=1)["stats"], "sources": store.sources()}, indent=2))
        return 0 if success else 1
    allowed = {"127.0.0.1", "localhost", "::1"} | {x.strip().lower() for x in os.getenv("VULNORBIT_ALLOWED_HOSTS", "").split(",") if x.strip()}
    if args.host not in ("0.0.0.0", "::"):
        allowed.add(args.host.lower())
    server = Server((args.host, args.port), store, ingestor, allowed)
    if not args.no_sync:
        ingestor.start()
    print("\nXploitAtlas is running: http://127.0.0.1:" + str(args.port))
    print("Real sources only. Initial imports may take several minutes. Keep this process running for automatic updates.\n")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nStopping XploitAtlas.")
    finally:
        server.server_close()
        ingestor.close()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
