"""Independent catalog, inventory, and notification workers."""
from __future__ import annotations
import logging
import os
import threading
import time
from pathlib import Path
from accounts import Accounts
from ai_explainer import AIExplainer
from advisories import VendorSources
from alerts import Alerts
from backfill import Backfill
from config import runtime_path,setting
from components import ComponentEvidence
from core import now
from feeds import Ingestor
from highlights import Highlights
from scanner import Scanner
from store import Store
from taxonomy import Taxonomy
from workspace import Workspace

LOG = logging.getLogger("mastermonk")


class WorkerLock:
    def __init__(self,path):
        self.path,self.file = Path(path),None

    def acquire(self):
        self.file = self.path.open("a+b")
        if self.file.tell()==0:
            self.file.write(b"0");self.file.flush()
        self.file.seek(0)
        try:
            if os.name=="nt":
                import msvcrt
                msvcrt.locking(self.file.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self.file,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except (OSError,BlockingIOError):
            self.file.close();self.file=None
            raise RuntimeError("A collector already owns this data directory. Use the running instance or external sync mode.") from None
        return self

    def close(self):
        if self.file:
            if os.name=="nt":
                import msvcrt
                self.file.seek(0);msvcrt.locking(self.file.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl
                fcntl.flock(self.file,fcntl.LOCK_UN)
            self.file.close();self.file=None

    def __enter__(self):
        return self.acquire()

    def __exit__(self,*args):
        self.close()


class Services:
    def __init__(self,data_dir=None):
        self.path = runtime_path(data_dir)
        self.catalog = Store(self.path/"mastermonk.sqlite3")
        if not self.catalog.state("created_at"):
            self.catalog.set_state("created_at",now())
        self.catalog.rebuild_priorities()
        self.accounts = Accounts(self.path/"workspace.sqlite3")
        self.workspace = Workspace(self.accounts,self.catalog)
        self.highlights = Highlights(self.accounts,self.catalog)
        self.taxonomy = Taxonomy(self.path)
        self.ai = AIExplainer(setting("AI_ENDPOINT"),setting("AI_MODEL"),setting("AI_API_KEY"))
        self.ingestor = Ingestor(self.catalog,self.path,int(setting("INTERVAL","900")))
        self.components = ComponentEvidence(self.ingestor)
        self.scanner = Scanner(self.workspace,self.ingestor.client)
        self.vendors = VendorSources(self.accounts)
        self.alerts = Alerts(self.workspace)
        self.backfill = Backfill(self.catalog,self.ingestor.client)
        self.stop,self.wake = threading.Event(),threading.Event()
        self.thread,self.worker_lock = None,None

    def start_worker(self):
        if self.thread and self.thread.is_alive():
            return
        self.worker_lock = WorkerLock(self.path/"collector.lock").acquire()
        self.ingestor.start()
        self.backfill.start()
        self.thread = threading.Thread(target=self._loop,name="mastermonk-workspace",daemon=True)
        self.thread.start()

    def _loop(self):
        while not self.stop.is_set():
            self.wake.clear()
            try:
                self.workspace.queue_due()
                self.scanner.step()
                self.vendors.step()
                self.alerts.evaluate()
                self.alerts.deliver_one()
                self.catalog.set_state("worker_heartbeat",now())
            except Exception:
                LOG.exception("Workspace worker could not finish this pass")
            self.wake.wait(2)

    def once(self,sources=None,budget=300):
        with WorkerLock(self.path/"collector.lock"):
            success = self.ingestor.sync(sources)
            started = time.monotonic()
            self.workspace.queue_due()
            while time.monotonic()-started<budget:
                if not self.scanner.step():
                    break
            self.backfill.step()
            self.vendors.step()
            self.alerts.evaluate(force=True)
            for _ in range(30):
                if not self.alerts.deliver_one():
                    break
            self.catalog.set_state("worker_heartbeat",now())
            return success

    def close(self):
        self.stop.set();self.wake.set()
        self.ingestor.close();self.backfill.close()
        if self.thread:
            self.thread.join(timeout=3)
        if self.worker_lock:
            self.worker_lock.close()
