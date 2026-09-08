"""Opt-in, restartable full NVD pagination pass. No bundled historical dataset."""
from __future__ import annotations
import threading
import time
import uuid
import urllib.parse
from datetime import datetime, timezone, timedelta
import adapters
from core import now
from feeds import FeedError

class Backfill:
    def __init__(self, store, client):
        self.store, self.client = store, client
        self.lock = threading.RLock()
        self.stop_event, self.wake = threading.Event(), threading.Event()
        self.thread = None
        self.busy = False

    def status(self):
        state = self.store.state("nvd_backfill", {"enabled": False, "index": 0,
            "total": None, "pages": 0, "complete": False, "error": None})
        return {**state, "running": self.busy,
                "schedulerActive": bool(self.thread and self.thread.is_alive())}

    def configure(self, action):
        if action not in {"start", "pause", "resume", "restart"}:
            raise ValueError("Choose start, pause, resume, or restart.")
        with self.lock:
            state = self.store.state("nvd_backfill", {})
            if action == "pause":
                state.update(enabled=False)
            elif action == "restart" or not state.get("generation"):
                state = {"enabled": True, "generation": uuid.uuid4().hex,
                         "index": 0, "total": None, "pages": 0, "complete": False,
                         "startedAt": now(), "error": None, "retryAt": None,
                         "windowStart":"1999-01-01T00:00:00Z","through":now(),
                         "imported":0,"windowsComplete":0}
            elif state.get("complete"):
                raise ValueError("This pass is complete. Choose Restart for a new full pass.")
            else:
                state["enabled"] = True
            self.store.set_state("nvd_backfill", state)
        self.wake.set()
        return self.status()

    def step(self):
        with self.lock:
            state = self.store.state("nvd_backfill", {})
            if not state.get("enabled") or state.get("complete") or self.busy:
                return False
            if state.get("retryAt") and state["retryAt"] > now():
                return False
            self.busy = True
        try:
            index = int(state.get("index", 0))
            beginning = datetime.fromisoformat(state.get("windowStart","1999-01-01T00:00:00Z").replace("Z","+00:00"))
            through = datetime.fromisoformat(state.get("through",state.get("startedAt",now())).replace("Z","+00:00"))
            end = min(through,beginning+timedelta(days=119))
            iso = lambda value:value.isoformat(timespec="milliseconds").replace("+00:00","Z")
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(
                {"startIndex": index, "resultsPerPage": 2000,
                 "pubStartDate":iso(beginning),"pubEndDate":iso(end)})
            response = self.client.get(url, "nvd")
            data = response.data
            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                raise FeedError("NVD backfill response was malformed; the cursor was retained.")
            total = data.get("totalResults")
            if type(total) is not int or total < 0 or data.get("startIndex") != index:
                raise FeedError("NVD returned inconsistent pagination; the cursor was retained.")
            rows = data["vulnerabilities"]
            if len(rows) > 2000 or index+len(rows)>total or (index < total and not rows):
                raise FeedError("NVD pagination did not advance; the cursor was retained.")
            signals = adapters.nvd(data, response.observed_at, url)
            # Reject a malformed page instead of skipping source rows silently.
            if len(signals) != len(rows) or len({signal["id"] for signal in signals}) != len(signals):
                raise FeedError("Some NVD rows could not be normalized; the page was not committed.")
            with self.lock:
                current = self.store.state("nvd_backfill", {})
                if current.get("generation") != state.get("generation"):
                    return False
                next_index = index + len(rows)
                window_done = next_index>=total
                complete = window_done and end>=through
                current.update(index=0 if window_done else next_index, total=total, pages=state.get("pages", 0)+1,
                    complete=complete, lastSuccess=now(), error=None, retryAt=None,
                    enabled=bool(current.get("enabled")) and not complete,windowEnd=iso(end),
                    imported=state.get("imported",0)+len(rows),through=iso(through),
                    windowsComplete=state.get("windowsComplete",0)+int(window_done))
                if window_done and not complete:
                    # NVD timestamp bounds are inclusive. Advance by one millisecond.
                    current["windowStart"] = iso(end+timedelta(milliseconds=1))
                if complete:
                    current["completedAt"] = now()
                # Data and durable cursor advance in the same transaction.
                self.store.ingest("nvd", signals, checkpoint={"nvd_backfill": current})
                self.store.health("nvd",message="Historical NVD page saved. See Historical NVD import for full-pass progress.")
            return True
        except Exception as exc:
            with self.lock:
                current = self.store.state("nvd_backfill", {})
                if current.get("generation") == state.get("generation"):
                    retry = max(60, min(getattr(exc, "retry_seconds", 900), 86400))
                    current.update(error=str(exc)[:300], lastAttempt=now(),
                        retryAt=datetime.fromtimestamp(time.time()+retry, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"))
                    self.store.set_state("nvd_backfill", current)
            return False
        finally:
            with self.lock:
                self.busy = False

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._loop, name="nvd-history", daemon=True)
        self.thread.start()

    def _loop(self):
        while not self.stop_event.is_set():
            self.wake.clear()
            self.step()
            # Separate from the recent-feed cycle; the shared client enforces NVD pacing.
            self.wake.wait(15)

    def close(self):
        self.stop_event.set(); self.wake.set()
        if self.thread:
            self.thread.join(timeout=3)
