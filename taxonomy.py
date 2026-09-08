"""Live MITRE CAPEC relationships for collected CWE identifiers."""
from __future__ import annotations
import json
import re
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from safe_http import request

CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
MAX_AGE = 7 * 24 * 3600


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def child_text(element, name):
    for child in element.iter():
        if local_name(child.tag) == name and child.text:
            return child.text.strip()
    return ""


def normalize_cwe_id(value):
    value = str(value or "").strip()
    if value.upper().startswith("CWE-"):
        value = value[4:]
    return "CWE-" + value if value.isdigit() and int(value) > 0 else ""


def normalize_attack_id(value):
    value = str(value or "").strip().upper()
    if re.fullmatch(r"T?\d{4}(?:\.\d{3})?", value):
        return value if value.startswith("T") else "T" + value
    return ""


def is_attack_taxonomy(value):
    normalized = re.sub(r"[^A-Z]", "", str(value or "").upper())
    return "ATTACK" in normalized or "ATTCK" in normalized


class Taxonomy:
    def __init__(self, data_dir):
        self.path = Path(data_dir) / "taxonomy" / "capec.json"
        self.lock = threading.RLock()
        self.cache = None
        self.retry_after = 0

    def status(self):
        value = self._load_disk()
        return {"available": bool(value), "source": CAPEC_URL,
                "retrievedAt": value.get("retrievedAt") if value else None,
                "version": value.get("version") if value else None}

    def for_record(self, record):
        cwes = [value for value in record.get("cwes", []) if isinstance(value, str)]
        if not cwes:
            return {"available": True, "source": CAPEC_URL, "cwes": [], "patterns": [],
                    "notice": "No CWE identifier was supplied by the collected record sources."}
        data = self._ensure()
        patterns, seen = [], set()
        for cwe in cwes:
            for pattern in data["byCwe"].get(cwe, []):
                if pattern["id"] not in seen:
                    patterns.append(pattern)
                    seen.add(pattern["id"])
        return {"available": True, "source": CAPEC_URL, "retrievedAt": data["retrievedAt"],
                "version": data.get("version"), "cwes": cwes, "patterns": patterns[:24],
                "notice": "CAPEC relates attack patterns to CWE weakness classes. This is learning context, not proof that this CVE was exploited with a particular technique."}

    def _load_disk(self):
        with self.lock:
            if self.cache is not None:
                return self.cache
            try:
                value = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(value, dict) and isinstance(value.get("byCwe"), dict):
                    self.cache = value
                    return value
            except (OSError, ValueError, TypeError):
                return None
        return None

    def _ensure(self):
        # Only one shared download may run; failed refreshes back off across visitors.
        if not self.lock.acquire(blocking=False):
            if self.cache:
                return self.cache
            raise ValueError("MITRE CAPEC is being retrieved. Please try again shortly.")
        try:
            return self._refresh()
        finally:
            self.lock.release()

    def _refresh(self):
        value = self._load_disk()
        if value and time.time() - float(value.get("retrievedUnix", 0)) < MAX_AGE:
            return value
        if time.monotonic() < self.retry_after:
            if value:
                return value
            raise ValueError("MITRE CAPEC is temporarily unavailable. Try again after a few minutes.")
        try:
            raw, _headers = request(CAPEC_URL, headers={"Accept": "application/xml,text/xml"}, max_bytes=48*1024*1024)
            value = self._parse(raw)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            temporary.replace(self.path)
            with self.lock:
                self.cache = value
            return value
        except Exception:
            self.retry_after = time.monotonic() + 300
            if value:
                return value
            raise ValueError("MITRE CAPEC relationships could not be retrieved. No technique mapping was generated.") from None

    @staticmethod
    def _parse(raw):
        if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
            raise ValueError("Unexpected XML declaration in MITRE CAPEC data.")
        root = ET.fromstring(raw)
        by_cwe = {}
        for pattern in root.iter():
            if local_name(pattern.tag) != "Attack_Pattern" or pattern.attrib.get("Status") == "Deprecated":
                continue
            capec_id = str(pattern.attrib.get("ID", "")).strip()
            name = str(pattern.attrib.get("Name", "")).strip()
            if not capec_id.isdigit() or not name:
                continue
            cwes = []
            techniques = []
            for item in pattern.iter():
                tag = local_name(item.tag)
                if tag == "Related_Weakness":
                    normalized = normalize_cwe_id(item.attrib.get("CWE_ID"))
                    if normalized:
                        cwes.append(normalized)
                elif tag == "Taxonomy_Mapping" and is_attack_taxonomy(item.attrib.get("Taxonomy_Name")):
                    entry = normalize_attack_id(child_text(item, "Entry_ID"))
                    entry_name = child_text(item, "Entry_Name")
                    if entry:
                        techniques.append({"id": entry, "name": entry_name,
                            "url": "https://attack.mitre.org/techniques/" + entry.replace(".", "/") + "/"})
            value = {"id": "CAPEC-" + capec_id, "name": name,
                     "url": f"https://capec.mitre.org/data/definitions/{capec_id}.html",
                     "techniques": techniques[:8]}
            for cwe in dict.fromkeys(cwes):
                by_cwe.setdefault(cwe, []).append(value)
        if not by_cwe:
            raise ValueError("The MITRE document did not contain CWE relationships.")
        for values in by_cwe.values():
            values.sort(key=lambda item: int(item["id"].split("-")[1]))
        stamp = time.time()
        return {"source": CAPEC_URL, "retrievedUnix": stamp,
                "retrievedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp)),
                "version": root.attrib.get("Version"), "byCwe": by_cwe}
