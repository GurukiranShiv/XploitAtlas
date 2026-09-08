"""Owner-scoped collections of real catalog records with capability-style public links."""
from __future__ import annotations
import re
import secrets
import time
from accounts import AccessError
from core import summary

TOKEN = re.compile(r"[A-Za-z0-9_-]{24,64}\Z")


def clean(value, limit, label):
    if not isinstance(value, str):
        raise ValueError(label + " must be text.")
    value = value.strip()
    if not 1 <= len(value) <= limit:
        raise ValueError(f"{label} must contain 1–{limit} characters.")
    return value


class Highlights:
    def __init__(self, accounts, catalog):
        self.accounts, self.catalog = accounts, catalog

    def create(self, owner, payload):
        title = clean(payload.get("title", ""), 100, "Title")
        note = clean(payload.get("note", ""), 1200, "Briefing note")
        raw_items = payload.get("items")
        if not isinstance(raw_items, list) or not 1 <= len(raw_items) <= 24:
            raise ValueError("Choose 1–24 collected records.")
        items, seen = [], set()
        for position, item in enumerate(raw_items):
            if not isinstance(item, dict):
                raise ValueError("Each highlight item must be an object.")
            identifier = item.get("id")
            if not isinstance(identifier, str) or identifier in seen or not self.catalog.record(identifier):
                raise ValueError("Every highlight must identify a unique collected record.")
            item_note = item.get("note", "")
            if not isinstance(item_note, str) or len(item_note.strip()) > 500:
                raise ValueError("A record note can contain up to 500 characters.")
            seen.add(identifier)
            items.append((identifier, item_note.strip(), position))
        identifier, token, stamp = secrets.token_hex(12), secrets.token_urlsafe(24), time.time()
        with self.accounts.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM highlights WHERE owner=?", (owner,)).fetchone()[0] >= 100:
                raise ValueError("This account has 100 highlight pages. Delete an unused page first.")
            db.execute("INSERT INTO highlights VALUES (?,?,?,?,?,?,?,0)",
                       (identifier, owner, token, title, note, stamp, stamp))
            db.executemany("INSERT INTO highlight_items VALUES (?,?,?,?)",
                           [(identifier, record_id, item_note, position) for record_id, item_note, position in items])
        return self.detail(owner, identifier)

    def list(self, owner):
        with self.accounts.connection() as db:
            rows = db.execute("""SELECT h.*,COUNT(i.record_id) item_count FROM highlights h
                LEFT JOIN highlight_items i ON i.highlight_id=h.id WHERE h.owner=?
                GROUP BY h.id ORDER BY h.updated DESC""", (owner,)).fetchall()
        return [{"id": row["id"], "token": row["public_token"], "title": row["title"],
                 "note": row["note"], "created": row["created"], "updated": row["updated"],
                 "revoked": bool(row["revoked"]), "count": row["item_count"]} for row in rows]

    def detail(self, owner, identifier):
        with self.accounts.connection() as db:
            row = db.execute("SELECT * FROM highlights WHERE id=? AND owner=?", (identifier, owner)).fetchone()
            if not row:
                raise AccessError("Highlight page not found.", 404)
            items = db.execute("SELECT * FROM highlight_items WHERE highlight_id=? ORDER BY position", (identifier,)).fetchall()
        return self._render(row, items)

    def public(self, token):
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            raise AccessError("Highlight page not found.", 404)
        with self.accounts.connection() as db:
            row = db.execute("SELECT h.* FROM highlights h JOIN users u ON u.id=h.owner WHERE h.public_token=? AND h.revoked=0 AND u.disabled=0", (token,)).fetchone()
            if not row:
                raise AccessError("This highlight link is unavailable.", 404)
            items = db.execute("SELECT * FROM highlight_items WHERE highlight_id=? ORDER BY position", (row["id"],)).fetchall()
        return self._render(row, items, public=True)

    def _render(self, row, items, public=False):
        records = []
        for item in items:
            record = self.catalog.record(item["record_id"])
            if record:
                records.append({"record": summary(record), "note": item["note"]})
        return {"id": row["id"], "token": row["public_token"], "title": row["title"],
                "note": row["note"], "created": row["created"], "updated": row["updated"],
                "revoked": bool(row["revoked"]), "items": records, "public": public,
                "evidenceUpdated": self.catalog.state("last_success")}

    def configure(self, owner, identifier, action):
        if action not in {"revoke", "restore", "delete"}:
            raise ValueError("Choose revoke, restore, or delete.")
        with self.accounts.connection() as db:
            row = db.execute("SELECT id FROM highlights WHERE id=? AND owner=?", (identifier, owner)).fetchone()
            if not row:
                raise AccessError("Highlight page not found.", 404)
            if action == "delete":
                db.execute("DELETE FROM highlights WHERE id=?", (identifier,))
            else:
                db.execute("UPDATE highlights SET revoked=?,updated=? WHERE id=?",
                           (1 if action == "revoke" else 0, time.time(), identifier))
        return {"id": identifier, "action": action}
