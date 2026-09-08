"""Local accounts and revocable sessions; no default credentials or public signup."""
from __future__ import annotations
import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

SESSION_SECONDS = 12 * 3600
IDLE_SECONDS = 60 * 60
USERNAME = re.compile(r"[a-z0-9][a-z0-9_.-]{2,39}\Z")

class AccessError(Exception):
    def __init__(self, message="Sign in required.", status=401):
        self.status = status
        super().__init__(message)

def password_hash(password, salt=None):
    if not isinstance(password, str) or not 15 <= len(password) <= 128:
        raise ValueError("Use a password or passphrase with 15–128 characters.")
    salt = salt or secrets.token_hex(16)
    value = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt),
                           n=32768, r=8, p=3, maxmem=64*1024*1024, dklen=32)
    return "scrypt-v1$" + salt + "$" + value.hex()

def password_matches(password, encoded):
    try:
        kind, salt, digest = encoded.split("$")
        return kind == "scrypt-v1" and hmac.compare_digest(password_hash(password, salt), encoded)
    except (ValueError, TypeError):
        return False

def token_hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

class Accounts:
    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        self.crypto_lock = threading.Semaphore(2)
        self.failures = {}
        self.setup_digest, self.setup_expires = None, 0
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','member')),
                    disabled INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
                    csrf TEXT NOT NULL, created REAL NOT NULL, last_seen REAL NOT NULL,
                    expires REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);
                CREATE TABLE IF NOT EXISTS api_tokens (
                    digest TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),
                    name TEXT NOT NULL,scopes TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS preferences (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id),payload TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS highlights (
                    id TEXT PRIMARY KEY, owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    public_token TEXT NOT NULL UNIQUE, title TEXT NOT NULL, note TEXT NOT NULL,
                    created REAL NOT NULL, updated REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_highlights_owner ON highlights(owner,updated DESC);
                CREATE TABLE IF NOT EXISTS highlight_items (
                    highlight_id TEXT NOT NULL REFERENCES highlights(id) ON DELETE CASCADE,
                    record_id TEXT NOT NULL, note TEXT NOT NULL, position INTEGER NOT NULL,
                    PRIMARY KEY(highlight_id,record_id)
                );
            """)
            db.execute("PRAGMA optimize")
        try:
            Path(self.path).chmod(0o600)
        except OSError:
            pass
        # Equal hashing work for unknown usernames limits account enumeration.
        # This hash is never assigned to an account or saved to the database.
        self.anti_enumeration_hash = password_hash(secrets.token_urlsafe(24))

    @contextmanager
    def connection(self):
        with self.lock:
            db = sqlite3.connect(self.path, timeout=30)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            try:
                with db:
                    yield db
            finally:
                db.close()

    def needs_setup(self):
        with self.connection() as db:
            return db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0

    def issue_setup_code(self):
        if not self.needs_setup():
            return None
        code = secrets.token_urlsafe(24)
        self.setup_digest, self.setup_expires = token_hash(code), time.time()+1800
        return code

    @staticmethod
    def clean_username(username):
        if not isinstance(username, str) or not USERNAME.fullmatch(username.strip().lower()):
            raise ValueError("Username: 3–40 letters, digits, dots, underscores, or hyphens.")
        return username.strip().lower()

    def create_user(self, username, password, role="member", setup_code=None):
        username = self.clean_username(username)
        if role not in {"admin", "member"}:
            raise ValueError("Invalid account role.")
        with self.crypto_lock:
            encoded = password_hash(password)
        with self.connection() as db:
            count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count == 0:
                if (not isinstance(setup_code, str) or not self.setup_digest or
                    time.time() > self.setup_expires or not hmac.compare_digest(token_hash(setup_code), self.setup_digest)):
                    raise AccessError("A valid first-run setup code is required.", 403)
                role = "admin"
            elif setup_code is not None:
                raise AccessError("Initial setup is already complete.", 409)
            if count >= 50:
                raise ValueError("This local workspace supports up to 50 accounts.")
            try:
                cursor = db.execute("INSERT INTO users(username,password,role,created) VALUES (?,?,?,?)",
                                    (username, encoded, role, time.time()))
            except sqlite3.IntegrityError:
                raise ValueError("That username is unavailable.") from None
            user = {"id": cursor.lastrowid, "username": username, "role": role}
        if count == 0:
            self.setup_digest, self.setup_expires = None, 0
        return user

    def throttle(self, ip, username):
        stamp = time.time()
        with self.lock:
            self.failures = {k:v for k,v in self.failures.items() if v[1] > stamp}
            for key in ("ip:"+ip, "user:"+username):
                count, until = self.failures.get(key, (0, stamp+900))
                if count >= 8:
                    raise AccessError("Too many sign-in attempts. Wait 15 minutes.", 429)
            # Count all attempts before hashing; also bounds concurrent attempts.
            if len(self.failures) > 4096:
                raise AccessError("Sign-in is temporarily rate limited.", 429)
            for key in ("ip:"+ip, "user:"+username):
                count, until = self.failures.get(key, (0, stamp+900))
                self.failures[key] = (count+1, until)

    def login(self, username, password, ip):
        username = username.strip().lower() if isinstance(username, str) else ""
        self.throttle(ip, username[:40])
        with self.connection() as db:
            row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        with self.crypto_lock:
            valid = password_matches(password, row["password"] if row else self.anti_enumeration_hash)
        if not valid or row is None or row["disabled"]:
            raise AccessError("Invalid username or password.")
        with self.lock:
            self.failures.pop("user:"+username, None)
            # A successful sign-in is not a failed attempt. Keep any earlier
            # failures from this address, but do not lock out a shared LAN.
            key = "ip:"+ip
            count, until = self.failures.get(key, (0, 0))
            if count > 1:
                self.failures[key] = (count-1, until)
            else:
                self.failures.pop(key, None)
        return self.new_session(row["id"])

    def new_session(self, user_id):
        raw, csrf, stamp = secrets.token_urlsafe(32), secrets.token_urlsafe(32), time.time()
        with self.connection() as db:
            row = db.execute("SELECT id,username,role,disabled FROM users WHERE id=?", (user_id,)).fetchone()
            if not row or row["disabled"]:
                raise AccessError()
            db.execute("DELETE FROM sessions WHERE expires<=? OR last_seen<?", (stamp, stamp-IDLE_SECONDS))
            # Keep at most five sessions per account, including this one.
            db.execute("DELETE FROM sessions WHERE token IN (SELECT token FROM sessions WHERE user_id=? ORDER BY created DESC LIMIT -1 OFFSET 4)", (user_id,))
            db.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?)", (token_hash(raw), user_id, csrf, stamp, stamp, stamp+SESSION_SECONDS))
        return {"token": raw, "csrf": csrf, "user": {k:row[k] for k in ("id","username","role")}}

    def authenticate(self, raw):
        if not isinstance(raw, str) or not 32 <= len(raw) <= 128:
            raise AccessError()
        stamp = time.time()
        with self.connection() as db:
            row = db.execute("""SELECT s.*,u.username,u.role,u.disabled FROM sessions s
                JOIN users u ON u.id=s.user_id WHERE s.token=?""", (token_hash(raw),)).fetchone()
            if not row or row["disabled"] or row["expires"] <= stamp or row["last_seen"] < stamp-IDLE_SECONDS:
                raise AccessError("Your session has expired. Sign in again.")
            db.execute("UPDATE sessions SET last_seen=? WHERE token=?", (stamp, row["token"]))
            return {"id": row["user_id"], "username": row["username"], "role": row["role"], "csrf": row["csrf"]}

    def logout(self, raw):
        with self.connection() as db:
            db.execute("DELETE FROM sessions WHERE token=?", (token_hash(raw),))

    def users(self):
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT id,username,role,disabled,created FROM users ORDER BY username")]

    def disable(self, actor_id, user_id):
        if user_id == actor_id:
            raise ValueError("You cannot disable your own active administrator account.")
        with self.connection() as db:
            if not db.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone():
                raise ValueError("Account not found.")
            db.execute("UPDATE users SET disabled=1 WHERE id=?", (user_id,))
            db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            db.execute("DELETE FROM api_tokens WHERE user_id=?", (user_id,))

    def change_password(self, user_id, old, new):
        with self.connection() as db:
            row = db.execute("SELECT password FROM users WHERE id=?", (user_id,)).fetchone()
        with self.crypto_lock:
            if not row or not password_matches(old, row[0]):
                raise AccessError("The current password is incorrect.", 403)
            encoded = password_hash(new)
        with self.connection() as db:
            db.execute("UPDATE users SET password=? WHERE id=?", (encoded, user_id))
            db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            db.execute("DELETE FROM api_tokens WHERE user_id=?", (user_id,))

    def reset_password_local(self, username, password):
        """Only the separate local CLI calls this recovery operation."""
        with self.crypto_lock:
            encoded = password_hash(password)
        with self.connection() as db:
            row = db.execute("SELECT id FROM users WHERE username=?", (self.clean_username(username),)).fetchone()
            if not row:
                raise ValueError("Account not found.")
            db.execute("UPDATE users SET password=?,disabled=0 WHERE id=?", (encoded, row[0]))
            db.execute("DELETE FROM sessions WHERE user_id=?", (row[0],))
            db.execute("DELETE FROM api_tokens WHERE user_id=?", (row[0],))

    def issue_api_token(self, user_id, name, scopes=None):
        import json
        scopes = scopes or ["read", "scan"]
        if not isinstance(scopes,list) or not scopes or set(scopes)-{"read","scan","inventory:write"}:
            raise ValueError("Choose read, scan, or inventory:write token scopes.")
        if not isinstance(name,str) or not 1 <= len(name.strip()) <= 60:
            raise ValueError("Give the token a name of 1–60 characters.")
        raw = "xpa_" + secrets.token_urlsafe(32)
        with self.connection() as db:
            if db.execute("SELECT COUNT(*) FROM api_tokens WHERE user_id=?",(user_id,)).fetchone()[0] >= 20:
                raise ValueError("Revoke an existing token before creating another.")
            db.execute("INSERT INTO api_tokens VALUES(?,?,?,?,?,?)",(token_hash(raw),user_id,name.strip(),json.dumps(scopes),time.time(),time.time()+90*86400))
        return {"token":raw,"name":name.strip(),"scopes":scopes,"expiresInDays":90}

    def authenticate_api_token(self, raw):
        import json
        if not isinstance(raw,str) or not raw.startswith("xpa_") or len(raw)>128:
            raise AccessError()
        with self.connection() as db:
            row = db.execute("SELECT t.*,u.username,u.role,u.disabled FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.digest=?",(token_hash(raw),)).fetchone()
        if not row or row["disabled"] or row["expires"] <= time.time():
            raise AccessError("Invalid or expired API token.")
        return {"id":row["user_id"],"username":row["username"],"role":row["role"],"scopes":json.loads(row["scopes"]),"api_token":True}

    def tokens(self,user_id):
        import json
        with self.connection() as db:
            return [{**dict(row),"scopes":json.loads(row["scopes"])} for row in db.execute("SELECT digest,name,scopes,created,expires FROM api_tokens WHERE user_id=? ORDER BY created DESC",(user_id,))]

    def revoke_token(self,user_id,digest):
        with self.connection() as db:
            db.execute("DELETE FROM api_tokens WHERE user_id=? AND digest=?",(user_id,digest))

    def preferences(self,user_id,value=None):
        import json
        with self.connection() as db:
            if value is not None:
                encoded = json.dumps(value,allow_nan=False)
                if not isinstance(value,dict) or len(encoded)>32768:
                    raise ValueError("Preferences exceed the supported size.")
                db.execute("INSERT INTO preferences VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET payload=excluded.payload",(user_id,encoded))
            row = db.execute("SELECT payload FROM preferences WHERE user_id=?",(user_id,)).fetchone()
            return json.loads(row[0]) if row else {}
