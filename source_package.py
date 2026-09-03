"""Build the complete public source download from an explicit file allowlist."""
from __future__ import annotations

import argparse
import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ARCHIVE_ROOT = "XploitAtlas"
SOURCE_FILES = (
    ".dockerignore",
    ".env.example",
    ".gitattributes",
    ".github/workflows/xploitatlas.yml",
    ".gitignore",
    "CONTRIBUTING.md",
    "Dockerfile",
    "LICENSE",
    "README.md",
    "RUN_ME_FIRST.md",
    "SECURITY.md",
    "START_WINDOWS.bat",
    "adapters.py",
    "compose.yaml",
    "core.py",
    "docs/TECHNICAL_GUIDE.md",
    "docs/screenshots/vulnorbit/01-universe.png",
    "docs/screenshots/vulnorbit/02-source-health.png",
    "docs/screenshots/vulnorbit/03-provenance-coverage.png",
    "docs/screenshots/vulnorbit/04-package-lookup.png",
    "docs/screenshots/vulnorbit/SOURCES.md",
    "feeds.py",
    "package.json",
    "server.py",
    "source_package.py",
    "start.py",
    "static/app.js",
    "static/fonts/IBMPlexSans-Regular.woff2",
    "static/fonts/IBMPlexSans-SemiBold.woff2",
    "static/fonts/IBMPlexSerif-Regular.woff2",
    "static/fonts/IBMPlexSerif-Medium.woff2",
    "static/fonts/IBMPlexMono-Regular.woff2",
    "static/fonts/OFL.txt",
    "static/fonts/README.md",
    "static/index.html",
    "static/mark.svg",
    "static/style.css",
    "static/ui.js",
    "static/universe.js",
    "store.py",
    "tests/test_core.py",
    "tests/test_distribution.py",
    "tests/test_live.py",
    "tests/ui.test.js",
    "tests/style.test.js",
    "tests/verify_archive.py",
)


def source_paths(root=ROOT):
    """Fail closed if a required file is missing or any source path is a symlink."""
    root = Path(root).resolve()
    paths = []
    for relative in SOURCE_FILES:
        path = root / relative
        parts = Path(relative).parts
        if any(root.joinpath(*parts[:i]).is_symlink() for i in range(1, len(parts) + 1)):
            raise ValueError("Source downloads cannot include symlinks: " + relative)
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise FileNotFoundError("Required project file is missing: " + relative)
        paths.append((relative, path))
    return paths


def build_source_archive(root=ROOT):
    """Package only public project files; never walk runtime or private directories."""
    paths = source_paths(root)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative, path in paths:
            # Fixed ZIP metadata makes repeat downloads byte-for-byte comparable.
            member = zipfile.ZipInfo(ARCHIVE_ROOT + "/" + relative, (1980, 1, 1, 0, 0, 0))
            member.compress_type = zipfile.ZIP_DEFLATED
            member.external_attr = 0o100644 << 16
            archive.writestr(member, path.read_bytes())
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description="Build a complete XploitAtlas source ZIP, without runtime data or credentials.")
    parser.add_argument("--output", type=Path, required=True, help="Path for a new ZIP file; existing files are not overwritten.")
    args = parser.parse_args()
    payload = build_source_archive()
    try:
        with args.output.open("xb") as output:
            output.write(payload)
    except FileExistsError:
        parser.error("The output file already exists. Choose a new output path.")
    print(f"Created {args.output}: {len(SOURCE_FILES)} public project files.")


if __name__ == "__main__":
    main()
