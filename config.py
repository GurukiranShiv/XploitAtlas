"""MasterMonk runtime configuration."""
from __future__ import annotations
import os
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
VERSION = "3.2.0"


def load_environment(path=None):
    """Read literal KEY=value settings; never evaluate shell substitutions."""
    path = Path(path or ROOT/".env")
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key,separator,value = line.partition("=")
        supported = key.startswith("MASTERMONK_") or key in {"NVD_API_KEY","GITHUB_TOKEN"}
        if not separator or not supported or not key.replace("_","").isalnum():
            raise ValueError("The .env file accepts MASTERMONK_KEY=value settings.")
        value = value.strip()
        if len(value)>=2 and value[0]==value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key,value)


def setting(name, default=""):
    key = "MASTERMONK_" + name
    return os.environ.get(key, default)


def runtime_path(value=None):
    configured = value or setting("DATA_DIR") or str(ROOT/"runtime")
    path = Path(configured).expanduser()
    if value is None and not path.is_absolute():
        path = ROOT/path
    path = path.resolve()
    path.mkdir(parents=True,exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def public_origin(value=None):
    value = (value if value is not None else setting("BASE_URL")).rstrip("/")
    if not value:
        return ""
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("MASTERMONK_BASE_URL must be an origin, for example https://atlas.example.org.")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Use HTTPS for a shared instance.")
    return value


def environment():
    origin = public_origin()
    hosts = {"localhost", "127.0.0.1", "::1"}
    hosts.update(x.strip().lower() for x in setting("ALLOWED_HOSTS").split(",") if x.strip())
    if origin:
        hosts.add(urlsplit(origin).hostname.lower())
    if os.getenv("RENDER_EXTERNAL_HOSTNAME"):
        hosts.add(os.environ["RENDER_EXTERNAL_HOSTNAME"].lower())
    return {"host": setting("HOST", "127.0.0.1"), "port": int(setting("PORT", os.getenv("PORT", "8787"))),
            "origin": origin, "hosts": hosts, "secure": origin.startswith("https://"),
            "public_catalog": setting("PUBLIC_CATALOG", "1") == "1",
            "sync_mode": setting("SYNC_MODE", "embedded"),
            "ai_endpoint": setting("AI_ENDPOINT"), "ai_model": setting("AI_MODEL"),
            "ai_api_key": setting("AI_API_KEY")}
