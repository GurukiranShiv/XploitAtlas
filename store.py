"""SQLite persistence with atomic imports, source versions, and field-level history."""
from __future__ import annotations
import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from core import SOURCE_META, differences, merge, now, summary

def dumps(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)

class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise RuntimeError("Unsupported database version. Use the application version that created it.")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS observations (
                    source TEXT NOT NULL, source_key TEXT NOT NULL, record_id TEXT NOT NULL,
                    payload TEXT NOT NULL, fingerprint TEXT NOT NULL,
                    first_seen TEXT NOT NULL, last_checked TEXT NOT NULL,
                    PRIMARY KEY(source, source_key)
                );
                CREATE INDEX IF NOT EXISTS idx_observations_record ON observations(record_id);
                CREATE TABLE IF NOT EXISTS records (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL, priority INTEGER NOT NULL,
                    vendor TEXT NOT NULL, product TEXT NOT NULL, severity TEXT NOT NULL,
                    published TEXT, modified TEXT, is_kev INTEGER NOT NULL, kev_added TEXT, cvss REAL, epss REAL
                );
                CREATE INDEX IF NOT EXISTS idx_records_priority ON records(priority DESC);
                CREATE INDEX IF NOT EXISTS idx_records_published ON records(published DESC);
                CREATE INDEX IF NOT EXISTS idx_records_modified ON records(modified DESC);
                CREATE INDEX IF NOT EXISTS idx_records_kev ON records(is_kev, kev_added DESC);
                CREATE TABLE IF NOT EXISTS changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT NOT NULL,
                    source TEXT NOT NULL, kind TEXT NOT NULL, observed_at TEXT NOT NULL,
                    source_time TEXT, payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_changes_record ON changes(record_id, id DESC);
                CREATE TABLE IF NOT EXISTS source_health (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS record_first_seen (record_id TEXT PRIMARY KEY, observed_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_first_seen_time ON record_first_seen(observed_at);
                CREATE INDEX IF NOT EXISTS idx_changes_time ON changes(observed_at,source,kind);
                CREATE TABLE IF NOT EXISTS fetches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, url TEXT NOT NULL,
                    observed_at TEXT NOT NULL, body_sha256 TEXT NOT NULL, byte_count INTEGER NOT NULL
                );
                PRAGMA user_version=1;
            """)
            db.execute("PRAGMA optimize")
            for source, meta in SOURCE_META.items():
                db.execute("INSERT OR IGNORE INTO source_health(id,payload) VALUES (?,?)",
                           (source, dumps({"id": source, **meta, "state": "pending", "lastAttempt": None,
                                          "lastSuccess": None, "count": 0, "message": "No source response yet.",
                                          "retryAt": None})))
            db.execute("INSERT OR IGNORE INTO record_first_seen SELECT record_id,MIN(first_seen) FROM observations GROUP BY record_id")

    @contextmanager
    def connection(self):
        with self.lock:
            db = sqlite3.connect(self.path, timeout=30)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA busy_timeout=30000")
            try:
                with db:
                    yield db
            finally:
                db.close()

    def state(self, key, default=None):
        with self.connection() as db:
            row = db.execute("SELECT payload FROM state WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set_state(self, key, value):
        with self.connection() as db:
            db.execute("INSERT INTO state(key,payload) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET payload=excluded.payload",
                       (key, dumps(value)))

    def health(self, source, **patch):
        with self.connection() as db:
            row = db.execute("SELECT payload FROM source_health WHERE id=?", (source,)).fetchone()
            state = json.loads(row[0])
            state.update(patch)
            db.execute("UPDATE source_health SET payload=? WHERE id=?", (dumps(state), source))

    def sources(self):
        with self.connection() as db:
            return [json.loads(r[0]) for r in db.execute("SELECT payload FROM source_health ORDER BY id")]

    def audit_fetch(self, source, url, observed, raw):
        with self.connection() as db:
            db.execute("INSERT INTO fetches(source,url,observed_at,body_sha256,byte_count) VALUES (?,?,?,?,?)",
                       (source, url, observed, hashlib.sha256(raw).hexdigest(), len(raw)))

    def signals(self, record_id):
        with self.connection() as db:
            return [dict(json.loads(r["payload"]), observedAt=r["last_checked"])
                    for r in db.execute("SELECT payload,last_checked FROM observations WHERE record_id=?", (record_id,))]

    def record(self, record_id):
        with self.connection() as db:
            row = db.execute("""SELECT r.payload,f.observed_at FROM records r
                LEFT JOIN record_first_seen f ON f.record_id=r.id WHERE r.id=?""", (record_id,)).fetchone()
            if not row:
                return None
            record = json.loads(row["payload"])
            record["firstObserved"] = row["observed_at"]
            return record

    def ids(self):
        with self.connection() as db:
            return [r[0] for r in db.execute("SELECT id FROM records WHERE id LIKE 'CVE-%' ORDER BY id")]

    def ingest(self, source, signals, complete_catalog=False, checkpoint=None):
        """Changes, observations, canonical records, and cursor advance commit together."""
        stamp = now()
        if complete_catalog and (source != "cisa" or not signals):
            raise ValueError("Only a complete validated nonempty CISA catalog can reconcile removals.")
        with self.connection() as db:
            health = json.loads(db.execute("SELECT payload FROM source_health WHERE id=?", (source,)).fetchone()[0])
            baseline = not health.get("lastSuccess")
            touched, fresh_keys = set(), set()
            for incoming in signals:
                if incoming["source"] != source:
                    raise ValueError("Source mismatch during import.")
                item = dict(incoming)
                key, identifier = item.get("key") or item["id"], item["id"]
                fresh_keys.add(key)
                row = db.execute("SELECT * FROM observations WHERE source=? AND source_key=?", (source, key)).fetchone()
                stable = {k: v for k, v in item.items() if k != "observedAt"}
                fingerprint = hashlib.sha256(dumps(stable).encode()).hexdigest()
                if row and row["record_id"] != identifier:
                    touched.add(row["record_id"])
                before = json.loads(row["payload"]) if row else None
                if (before and source in {"nvd", "cve", "github", "osv"} and before.get("modified")
                        and item.get("modified") and item["modified"] < before["modified"]):
                    continue
                changes = differences(before, item) if before else []
                if before is None and source == "cisa" and item.get("kev"):
                    changes = [{"field":"kev","before":None,"after":True}]
                if not baseline and (not before or changes):
                    kind = "first_observed" if before is None else "exploitation_changed" if any(c["field"] == "kev" for c in changes) else "remediation_changed" if any(c["field"] in ("packages", "requiredAction", "dueDate") for c in changes) else "source_updated"
                    db.execute("INSERT INTO changes(record_id,source,kind,observed_at,source_time,payload) VALUES (?,?,?,?,?,?)",
                               (identifier, source, kind, item["observedAt"], item.get("modified") or item.get("kevAdded"), dumps(changes)))
                db.execute("""INSERT INTO observations(source,source_key,record_id,payload,fingerprint,first_seen,last_checked)
                    VALUES (?,?,?,?,?,?,?) ON CONFLICT(source,source_key) DO UPDATE SET
                    record_id=excluded.record_id,payload=excluded.payload,fingerprint=excluded.fingerprint,last_checked=excluded.last_checked""",
                    (source, key, identifier, dumps(item), fingerprint, row["first_seen"] if row else stamp, item["observedAt"]))
                touched.add(identifier)
                db.execute("INSERT OR IGNORE INTO record_first_seen(record_id,observed_at) VALUES (?,?)", (identifier, stamp))
            if complete_catalog:
                previous = db.execute("SELECT source_key,record_id,payload FROM observations WHERE source='cisa'").fetchall()
                for row in previous:
                    old = json.loads(row["payload"])
                    if row["source_key"] not in fresh_keys and old.get("kev"):
                        old["kev"] = False
                        old["observedAt"] = stamp
                        db.execute("UPDATE observations SET payload=?,last_checked=? WHERE source='cisa' AND source_key=?",
                                   (dumps(old), stamp, row["source_key"]))
                        db.execute("INSERT INTO changes(record_id,source,kind,observed_at,source_time,payload) VALUES (?,?,?,?,?,?)",
                                   (row["record_id"], "cisa", "catalog_removed", stamp, None,
                                    dumps([{"field": "kev", "before": True, "after": False}])))
                        touched.add(row["record_id"])
            for identifier in touched:
                rows = db.execute("SELECT payload,last_checked FROM observations WHERE record_id=?", (identifier,)).fetchall()
                if not rows:
                    db.execute("DELETE FROM records WHERE id=?", (identifier,))
                    continue
                canonical = merge([dict(json.loads(r["payload"]), observedAt=r["last_checked"]) for r in rows])
                db.execute("""INSERT INTO records(id,payload,priority,vendor,product,severity,published,modified,is_kev,kev_added,cvss,epss)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                    payload=excluded.payload,priority=excluded.priority,vendor=excluded.vendor,product=excluded.product,
                    severity=excluded.severity,published=excluded.published,modified=excluded.modified,
                    is_kev=excluded.is_kev,kev_added=excluded.kev_added,cvss=excluded.cvss,epss=excluded.epss""",
                    (canonical["id"], dumps(canonical), canonical["priority"]["score"], canonical["vendor"], canonical["product"],
                     canonical["severity"], canonical["published"], canonical["modified"], int(canonical["kev"]),
                     canonical["kevAdded"], canonical["cvss"], canonical["epss"]))
            if checkpoint:
                for key, value in checkpoint.items():
                    db.execute("INSERT INTO state(key,payload) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET payload=excluded.payload",
                               (key, dumps(value)))
            # Baseline completion must be recorded atomically, including an empty but valid response.
            health.update(lastSuccess=stamp, lastAttempt=stamp, state="ok", count=len(signals), retryAt=None)
            db.execute("UPDATE source_health SET payload=? WHERE id=?", (dumps(health), source))
            if touched:
                db.execute("""INSERT INTO state(key,payload) VALUES ('catalog_revision','1')
                    ON CONFLICT(key) DO UPDATE SET payload=CAST(CAST(payload AS INTEGER)+1 AS TEXT)""")
        return len(touched)

    def events(self, record_id=None, limit=160, before=None):
        where, values = [], []
        if record_id:
            where.append("record_id=?")
            values.append(record_id)
        if before:
            where.append("id<?")
            values.append(int(before))
        sql = "SELECT * FROM changes" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
        with self.connection() as db:
            rows = db.execute(sql, (*values, min(limit, 500))).fetchall()
            return [{"id": r["id"], "cve": r["record_id"], "source": r["source"], "kind": r["kind"],
                     "observedAt": r["observed_at"], "sourceTime": r["source_time"], "changes": json.loads(r["payload"])} for r in rows]

    def catalog(self, query="", severity_filter="all", kev_only=False, days=None, sort="priority", limit=5000, offset=0, weights=None):
        where, values = [], []
        if query:
            pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(id LIKE ? ESCAPE '\\' OR vendor LIKE ? ESCAPE '\\' OR product LIKE ? ESCAPE '\\' OR payload LIKE ? ESCAPE '\\')")
            values.extend([pattern] * 4)
        if severity_filter != "all":
            where.append("severity=?")
            values.append(severity_filter)
        if kev_only:
            where.append("is_kev=1")
        if days:
            where.append("published >= ? AND published <= ?")
            values.extend([(datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds").replace("+00:00", "Z"), now()])
        condition = " WHERE " + " AND ".join(where) if where else ""
        ordering = {"priority": "priority DESC, kev_added DESC, id", "newest": "published DESC, id",
                    "cvss": "cvss DESC, id", "epss": "epss DESC, id"}.get(sort, "priority DESC, id")
        with self.connection() as db:
            if weights:
                from prioritization import priority,DEFAULT_WEIGHTS
                db.create_function("profile_priority",1,lambda value:priority(json.loads(value),weights)["score"],deterministic=True)
                if sort == "priority" and weights!=DEFAULT_WEIGHTS:
                    ordering = "profile_priority(payload) DESC, kev_added DESC, id"
            total = db.execute("SELECT COUNT(*) FROM records" + condition, values).fetchone()[0]
            rows = db.execute("""SELECT r.payload,f.observed_at FROM records r
                LEFT JOIN record_first_seen f ON f.record_id=r.id""" + condition + " ORDER BY " + ordering + " LIMIT ? OFFSET ?",
                (*values, min(limit, 10000), max(0, offset))).fetchall()
            cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(timespec="seconds").replace("+00:00", "Z")
            stats = dict(db.execute("""SELECT COUNT(*) AS total, COALESCE(SUM(is_kev),0) AS kev,
                COALESCE(SUM(cvss>=9),0) AS critical, COALESCE(SUM(published>=? AND published<=?),0) AS newWeek
                FROM records""", (cutoff, now())).fetchone())
            def summarized(query):
                result = []
                for row in db.execute(query):
                    record = json.loads(row["payload"])
                    record["firstObserved"] = row["observed_at"]
                    result.append(summary(record))
                return result
            recent = summarized("""SELECT r.payload,f.observed_at FROM records r LEFT JOIN record_first_seen f ON f.record_id=r.id
                WHERE r.published IS NOT NULL ORDER BY r.published DESC LIMIT 8""")
            radar = summarized("""SELECT r.payload,f.observed_at FROM records r LEFT JOIN record_first_seen f ON f.record_id=r.id
                WHERE r.is_kev=1 ORDER BY r.kev_added DESC,r.priority DESC LIMIT 6""")
            records = []
            for row in rows:
                record = json.loads(row["payload"])
                record["firstObserved"] = row["observed_at"]
                records.append(record)
            if weights:
                for record in records:
                    record["priority"] = priority(record,weights)
            return {"records": [summary(record) for record in records], "matching": total, "offset": offset,
                    "truncated": total > offset + len(rows), "stats": stats, "recent": recent, "radar": radar}

    def export_records(self):
        with self.connection() as db:
            return [json.loads(r[0]) for r in db.execute("SELECT payload FROM records ORDER BY priority DESC,id")]

    def iter_records(self, chunk=250):
        # Independent read connection: exports do not monopolize the writer lock.
        db = sqlite3.connect(self.path, timeout=30)
        try:
            cursor = db.execute("SELECT payload FROM records ORDER BY priority DESC,id")
            while True:
                rows = cursor.fetchmany(chunk)
                if not rows:
                    break
                for row in rows:
                    yield json.loads(row[0])
        finally:
            db.close()

    def rebuild_priorities(self):
        if self.state("priority_model") == "mastermonk-2":
            return
        from prioritization import priority
        with self.connection() as db:
            last = ""
            while True:
                rows = db.execute("SELECT id,payload FROM records WHERE id>? ORDER BY id LIMIT 250",(last,)).fetchall()
                if not rows:
                    break
                for row in rows:
                    value = json.loads(row["payload"])
                    value["priority"] = priority(value)
                    db.execute("UPDATE records SET priority=?,payload=? WHERE id=?", (value["priority"]["score"],dumps(value),row["id"]))
                last = rows[-1]["id"]
        self.set_state("priority_model", "mastermonk-2")

    def trends(self, days=30, basis="source"):
        days = max(7, min(int(days), 365))
        if basis not in {"source", "observed"}:
            raise ValueError("Invalid trend time basis.")
        today = datetime.now(timezone.utc).date()
        requested_first = today - timedelta(days=days-1)
        first = requested_first
        totals = {}
        with self.connection() as db:
            if basis == "source":
                end = str(today + timedelta(days=1))
                for row in db.execute("""SELECT substr(published,1,10) day,COUNT(*) published,
                        SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END) critical
                        FROM records WHERE published>=? AND published<? GROUP BY day""", (str(first), end)):
                    totals.setdefault(row["day"], {}).update(dict(row))
                for column, key, extra in (("modified", "modified", ""), ("kev_added", "kevAdded", " AND is_kev=1")):
                    sql = f"SELECT substr({column},1,10) day,COUNT(*) n FROM records WHERE {column}>=? AND {column}<?{extra} GROUP BY day"
                    for row in db.execute(sql, (str(first), end)):
                        totals.setdefault(row["day"], {})[key] = row["n"]
                available = db.execute("SELECT MIN(substr(published,1,10)) FROM records WHERE published IS NOT NULL").fetchone()[0]
                keys = ("published", "critical", "modified", "kevAdded")
            else:
                baseline = self.state("created_at")
                if baseline:
                    first = max(first, datetime.fromisoformat(baseline[:10]).date())
                end = str(today + timedelta(days=1))
                for row in db.execute("SELECT substr(observed_at,1,10) day,COUNT(*) n FROM record_first_seen WHERE observed_at>=? AND observed_at<? GROUP BY day", (str(first), end)):
                    totals[row["day"]] = {"indexed": row["n"]}
                sql = """SELECT substr(c.observed_at,1,10) day,
                    COUNT(DISTINCT CASE WHEN c.source='cisa' AND EXISTS(SELECT 1 FROM json_each(c.payload) j
                        WHERE json_extract(j.value,'$.field')='kev' AND json_extract(j.value,'$.after')=1) THEN c.record_id END) kevAdded,
                    COUNT(DISTINCT CASE WHEN c.kind='remediation_changed' THEN c.record_id END) remediation,
                    COUNT(DISTINCT c.record_id) changed FROM changes c
                    WHERE c.observed_at>=? AND c.observed_at<? GROUP BY day"""
                for row in db.execute(sql, (str(first), end)):
                    totals.setdefault(row["day"], {}).update(dict(row))
                available = baseline[:10] if baseline else None
                keys = ("indexed", "changed", "kevAdded", "remediation")
        points = []
        for offset in range(max(0, (today-first).days+1)):
            day = str(first + timedelta(days=offset))
            values = totals.get(day, {})
            points.append({"date": day, **{key: values.get(key, 0) for key in keys}})
        return {"days": points, "basis": basis, "requestedDays": days, "rangeFrom": str(first),
                "rangeTo": str(today), "availableFrom": available, "baseline": self.state("created_at"),
                "totals": {key: sum(point[key] for point in points) for key in keys}, "metrics": list(keys),
                "description": "Publisher dates reported in collected records." if basis == "source" else
                    "Dates when this MasterMonk instance saved observations. Initial indexing is separate from later evidence changes."}

    def trend_records(self, basis, metric, start, end, limit=100):
        if basis not in {"source", "observed"}:
            raise ValueError("Invalid trend time basis.")
        try:
            start_day = datetime.strptime(start, "%Y-%m-%d").date()
            end_day = datetime.strptime(end, "%Y-%m-%d").date()
        except (TypeError, ValueError) as error:
            raise ValueError("Invalid trend date.") from error
        if end_day < start_day or (end_day-start_day).days > 366:
            raise ValueError("Invalid trend date range.")
        lower, upper = str(start_day), str(end_day + timedelta(days=1))
        limit = max(1, min(int(limit), 250))
        with self.connection() as db:
            if basis == "source":
                definitions = {
                    "published": ("published", ""), "critical": ("published", " AND severity='Critical'"),
                    "modified": ("modified", ""), "kevAdded": ("kev_added", " AND is_kev=1")}
                if metric not in definitions:
                    raise ValueError("Invalid trend metric.")
                column, extra = definitions[metric]
                rows = db.execute(f"SELECT payload FROM records WHERE {column}>=? AND {column}<?{extra} ORDER BY {column} DESC,id LIMIT ?",
                                  (lower, upper, limit)).fetchall()
            else:
                if metric == "indexed":
                    rows = db.execute("""SELECT r.payload FROM record_first_seen f JOIN records r ON r.id=f.record_id
                        WHERE f.observed_at>=? AND f.observed_at<? ORDER BY f.observed_at DESC,r.id LIMIT ?""", (lower, upper, limit)).fetchall()
                else:
                    predicates = {"changed": "", "remediation": " AND c.kind='remediation_changed'",
                        "kevAdded": " AND c.source='cisa' AND EXISTS(SELECT 1 FROM json_each(c.payload) j WHERE json_extract(j.value,'$.field')='kev' AND json_extract(j.value,'$.after')=1)"}
                    if metric not in predicates:
                        raise ValueError("Invalid trend metric.")
                    rows = db.execute("""SELECT r.payload,MAX(c.observed_at) stamp FROM changes c JOIN records r ON r.id=c.record_id
                        WHERE c.observed_at>=? AND c.observed_at<?""" + predicates[metric] +
                        " GROUP BY r.id ORDER BY stamp DESC,r.id LIMIT ?", (lower, upper, limit)).fetchall()
        return {"records": [summary(json.loads(row["payload"])) for row in rows], "basis": basis,
                "metric": metric, "start": start, "end": end, "truncated": len(rows) == limit}

    def compare(self, start, end, limit=200):
        """Return only source observations saved inside an explicit UTC date range."""
        try:
            start_day = datetime.strptime(start, "%Y-%m-%d").date()
            end_day = datetime.strptime(end, "%Y-%m-%d").date()
        except (TypeError, ValueError) as error:
            raise ValueError("Choose valid comparison dates.") from error
        if end_day < start_day or (end_day-start_day).days > 366:
            raise ValueError("Compare a range of no more than 367 days.")
        lower, upper = str(start_day), str(end_day + timedelta(days=1))
        limit = max(1, min(int(limit), 250))
        baseline = self.state("created_at")
        definitions = {
            "indexed": ("""SELECT r.payload,f.observed_at stamp FROM record_first_seen f JOIN records r ON r.id=f.record_id
                WHERE f.observed_at>=? AND f.observed_at<? ORDER BY f.observed_at DESC,r.id LIMIT ?""", (lower, upper, limit)),
            "kevAdded": ("""SELECT r.payload,MAX(c.observed_at) stamp FROM changes c JOIN records r ON r.id=c.record_id
                WHERE c.observed_at>=? AND c.observed_at<? AND c.source='cisa'
                AND EXISTS(SELECT 1 FROM json_each(c.payload) j WHERE json_extract(j.value,'$.field')='kev'
                    AND json_extract(j.value,'$.after')=1)
                GROUP BY r.id ORDER BY stamp DESC,r.id LIMIT ?""", (lower, upper, limit)),
            "remediation": ("""SELECT r.payload,MAX(c.observed_at) stamp FROM changes c JOIN records r ON r.id=c.record_id
                WHERE c.observed_at>=? AND c.observed_at<? AND c.kind='remediation_changed'
                GROUP BY r.id ORDER BY stamp DESC,r.id LIMIT ?""", (lower, upper, limit)),
            "evidence": ("""SELECT r.payload,MAX(c.observed_at) stamp FROM changes c JOIN records r ON r.id=c.record_id
                WHERE c.observed_at>=? AND c.observed_at<?
                GROUP BY r.id ORDER BY stamp DESC,r.id LIMIT ?""", (lower, upper, limit)),
        }
        groups = {}
        with self.connection() as db:
            for key, (sql, parameters) in definitions.items():
                rows = db.execute(sql, parameters).fetchall()
                count_sql = sql.rsplit(" ORDER BY ", 1)[0]
                total = db.execute("SELECT COUNT(*) FROM (" + count_sql + ")", parameters[:2]).fetchone()[0]
                values = []
                for row in rows:
                    record = json.loads(row["payload"])
                    item = summary(record)
                    item["observedAt"] = row["stamp"]
                    values.append(item)
                groups[key] = {"records": values, "total": total, "truncated": total > len(rows)}
            revisions = db.execute("""SELECT record_id,source,observed_at,payload FROM changes
                WHERE observed_at>=? AND observed_at<? ORDER BY observed_at DESC,id DESC LIMIT 51""", (lower, upper)).fetchall()
            differences = [{"id": row["record_id"], "source": row["source"], "observedAt": row["observed_at"],
                            "fields": json.loads(row["payload"])} for row in revisions[:50]]
        available_from = baseline[:10] if isinstance(baseline, str) else None
        return {"from": start, "to": end, "availableFrom": available_from,
                "outsideHistory": bool(available_from and start < available_from), "groups": groups,
                "differences": differences, "differencesTruncated": len(revisions) > 50,
                "definitions": {
                    "indexed": "First indexed by this MasterMonk instance",
                    "kevAdded": "CISA KEV status newly saved by this instance",
                    "remediation": "Publisher remediation fields changed in saved evidence",
                    "evidence": "Any later source-evidence change saved by this instance"}}
