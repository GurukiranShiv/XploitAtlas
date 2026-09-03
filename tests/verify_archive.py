"""Verify that a source archive exactly matches the public download manifest."""
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from source_package import ARCHIVE_ROOT, SOURCE_FILES, source_paths


def verify(path):
    source_paths(ROOT)
    expected = set(SOURCE_FILES)
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise AssertionError("Archive CRC failed.")
        observed = set()
        for item in archive.infolist():
            member = PurePosixPath(item.filename)
            if item.is_dir() or member.is_absolute() or ".." in member.parts or member.parts[0] != ARCHIVE_ROOT:
                raise AssertionError("Unexpected archive path: " + item.filename)
            relative = member.relative_to(ARCHIVE_ROOT).as_posix()
            if relative not in expected or relative in observed:
                raise AssertionError("Unexpected or duplicate project file: " + relative)
            observed.add(relative)
            if archive.read(item) != (ROOT / relative).read_bytes():
                raise AssertionError("Archive differs from committed file: " + relative)
        if observed != expected:
            raise AssertionError("Archive file set differs: " + repr(observed ^ expected))
    print("Verified complete source archive:", len(observed), "files; every byte matches the public project.")


if __name__ == "__main__":
    verify(sys.argv[1])
