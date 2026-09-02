"""Verify that a downloadable archive exactly matches the committed source."""
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
def verify(path):
    expected = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
                if p.is_file() and not any(part in {"__pycache__", "runtime", ".venv", ".git"} for part in p.relative_to(ROOT).parts)
                and p.name != ".env" and p.suffix not in {".pyc", ".zip", ".sqlite3"}}
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise AssertionError("Archive CRC failed.")
        observed = set()
        for name in archive.namelist():
            member = PurePosixPath(name)
            if member.is_absolute() or ".." in member.parts or member.parts[0] != "vulnorbit":
                raise AssertionError("Unsafe archive path.")
            relative = member.relative_to("vulnorbit").as_posix()
            observed.add(relative)
            if archive.read(name) != (ROOT / relative).read_bytes():
                raise AssertionError("Archive differs from committed file: " + relative)
        if observed != expected:
            raise AssertionError("Archive file set differs: " + repr(observed ^ expected))
        print("Verified standalone source archive:", len(observed), "files; every byte matches the committed application.")

if __name__ == "__main__":
    verify(sys.argv[1])
