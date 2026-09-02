"""Download completeness and startup checks; no simulated intelligence is used."""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from source_package import ARCHIVE_ROOT, ROOT, SOURCE_FILES, build_source_archive, source_paths


def copy_public_files(destination):
    for relative, source in source_paths():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


class DistributionTests(unittest.TestCase):
    def test_manifest_contains_complete_application_and_public_guides(self):
        self.assertEqual(len(SOURCE_FILES), len(set(SOURCE_FILES)))
        required = {
            "START_WINDOWS.bat", "start.py", "server.py", "core.py", "store.py",
            "feeds.py", "adapters.py", "source_package.py", "static/index.html",
            "static/app.js", "static/ui.js", "static/universe.js", "static/style.css",
            "static/mark.svg", "README.md", "RUN_ME_FIRST.md", "LICENSE",
            "SECURITY.md", "CONTRIBUTING.md", "docs/TECHNICAL_GUIDE.md",
            "docs/screenshots/vulnorbit/01-universe.png",
            "docs/screenshots/vulnorbit/SOURCES.md",
        }
        self.assertTrue(required.issubset(SOURCE_FILES))
        self.assertEqual(len(source_paths()), len(SOURCE_FILES))
        self.assertFalse(any(p.startswith(("backend/", "frontend/", "assets/", "data/", "runtime/")) for p in SOURCE_FILES))
        self.assertFalse(any("interview" in p.lower() or "sample_" in p.lower() for p in SOURCE_FILES))
        launcher = (ROOT / "START_WINDOWS.bat").read_bytes()
        self.assertIn(b"\r\n", launcher)
        self.assertNotIn(b"\n", launcher.replace(b"\r\n", b""))
        self.assertIn(b'cd /d "%~dp0"', launcher)

    def test_archive_is_reproducible_complete_and_byte_exact(self):
        payload = build_source_archive()
        self.assertEqual(payload, build_source_archive())
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(
                set(archive.namelist()),
                {ARCHIVE_ROOT + "/" + relative for relative in SOURCE_FILES},
            )
            self.assertEqual(len(archive.namelist()), len(SOURCE_FILES))
            for relative in SOURCE_FILES:
                self.assertEqual(archive.read(ARCHIVE_ROOT + "/" + relative), (ROOT / relative).read_bytes())

    def test_unknown_private_files_are_not_packaged(self):
        with tempfile.TemporaryDirectory(prefix="xploitatlas-private-check-") as temporary:
            directory = Path(temporary)
            copy_public_files(directory)
            for relative in (".env", "runtime/private-note.txt", "docs/private-note.md", "static/private-note.md"):
                target = directory / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("Packaging-exclusion test marker. Not intelligence.", encoding="utf-8")
            with zipfile.ZipFile(io.BytesIO(build_source_archive(directory))) as archive:
                self.assertEqual(len(archive.namelist()), len(SOURCE_FILES))
                self.assertFalse(any(name.endswith("/.env") or "private-note" in name for name in archive.namelist()))

    def test_missing_required_file_fails_before_a_partial_archive_is_returned(self):
        with tempfile.TemporaryDirectory(prefix="xploitatlas-missing-check-") as temporary:
            directory = Path(temporary)
            copy_public_files(directory)
            (directory / "start.py").unlink()
            with self.assertRaisesRegex(FileNotFoundError, "start.py"):
                build_source_archive(directory)

    def test_source_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="xploitatlas-symlink-check-") as temporary:
            directory = Path(temporary)
            copy_public_files(directory)
            target = directory / "RUN_ME_FIRST.md"
            target.unlink()
            try:
                target.symlink_to(directory / "README.md")
            except (NotImplementedError, OSError):
                self.skipTest("Symlink creation is unavailable to this account.")
            with self.assertRaisesRegex(ValueError, "symlinks"):
                build_source_archive(directory)

    def test_relative_documentation_links_resolve_inside_download(self):
        public_files = set(SOURCE_FILES)
        for relative in SOURCE_FILES:
            if not relative.endswith(".md"):
                continue
            text = (ROOT / relative).read_text(encoding="utf-8")
            for value in re.findall(r"!?(?:\[[^\]]*\])\(([^)]+)\)", text):
                target = value.split(" ", 1)[0].strip("<>")
                parsed = urllib.parse.urlsplit(target)
                if parsed.scheme or parsed.netloc or not parsed.path:
                    continue
                path = ((ROOT / relative).parent / urllib.parse.unquote(parsed.path)).resolve()
                self.assertTrue(path.is_relative_to(ROOT), (relative, value))
                self.assertIn(path.relative_to(ROOT).as_posix(), public_files, (relative, value))

    def test_packaging_cli_and_fresh_extraction_start_without_external_dependencies(self):
        with tempfile.TemporaryDirectory(prefix="XploitAtlas download test spaces ") as temporary:
            directory = Path(temporary)
            output = directory / "source.zip"
            result = subprocess.run(
                [sys.executable, "-E", str(ROOT / "source_package.py"), "--output", str(output)],
                cwd=directory, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            verified = subprocess.run(
                [sys.executable, "-E", str(ROOT / "tests/verify_archive.py"), str(output)],
                cwd=directory, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            original_bytes = output.read_bytes()
            duplicate = subprocess.run(
                [sys.executable, "-E", str(ROOT / "source_package.py"), "--output", str(output)],
                cwd=directory, capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertEqual(output.read_bytes(), original_bytes)
            with zipfile.ZipFile(output) as archive:
                archive.extractall(directory)
            project = directory / ARCHIVE_ROOT
            environment = dict(os.environ, PYTHONHOME=str(directory / "missing-python"), PYTHONPATH=str(directory / "missing-path"))
            started = subprocess.run(
                [sys.executable, "-E", str(project / "start.py"), "--help"],
                cwd=directory, env=environment, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(started.returncode, 0, started.stderr)
            self.assertIn("XploitAtlas", started.stdout)
            self.assertFalse((project / "runtime").exists())

    def test_extracted_app_serves_empty_catalog_assets_and_complete_source_download(self):
        with tempfile.TemporaryDirectory(prefix="XploitAtlas HTTP download test ") as temporary:
            directory = Path(temporary)
            with zipfile.ZipFile(io.BytesIO(build_source_archive())) as archive:
                archive.extractall(directory)
            project = directory / ARCHIVE_ROOT
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            command = [
                sys.executable, "-E", str(project / "start.py"), "--no-sync",
                "--host", "127.0.0.1", "--port", str(port),
                "--data-dir", str(directory / "private-runtime"),
            ]
            process = subprocess.Popen(
                command, cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
            )
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            def request(path):
                with opener.open(f"http://127.0.0.1:{port}" + path, timeout=3) as response:
                    return response.status, response.headers, response.read()
            try:
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        self.fail("Extracted application exited: " + process.communicate(timeout=2)[0])
                    try:
                        status, _, body = request("/api/health")
                        break
                    except (OSError, urllib.error.URLError):
                        if time.monotonic() >= deadline:
                            self.fail("Extracted application did not start in time.")
                        time.sleep(0.05)
                self.assertEqual(status, 200)
                health = json.loads(body)
                self.assertEqual(health["mode"], "real-sources-only")
                self.assertFalse(health["sync"]["schedulerActive"])
                status, _, body = request("/api/universe")
                catalog = json.loads(body)
                self.assertEqual(catalog["stats"]["total"], 0)
                self.assertEqual(catalog["records"], [])
                for path in ("/", "/static/app.js", "/static/universe.js", "/static/ui.js", "/static/style.css", "/static/mark.svg"):
                    status, _, body = request(path)
                    self.assertEqual(status, 200)
                    self.assertTrue(body)
                status, headers, body = request("/api/source")
                self.assertEqual(status, 200)
                self.assertIn("XploitAtlas-source.zip", headers["Content-Disposition"])
                with zipfile.ZipFile(io.BytesIO(body)) as downloaded:
                    self.assertEqual(
                        set(downloaded.namelist()),
                        {ARCHIVE_ROOT + "/" + relative for relative in SOURCE_FILES},
                    )
                    self.assertIsNone(downloaded.testzip())
                    self.assertFalse(any("private-runtime" in name or name.endswith(".sqlite3") for name in downloaded.namelist()))
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
