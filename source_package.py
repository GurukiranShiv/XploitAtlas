"""Build the complete public source download from an explicit file allowlist."""
from __future__ import annotations

import argparse
import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ARCHIVE_ROOT = "MasterMonk"
SOURCE_FILES = (
    '.dockerignore',
    '.env.example',
    '.gitattributes',
    '.github/workflows/catalog-pages.yml',
    '.github/workflows/mastermonk.yml',
    '.gitignore',
    'CONTRIBUTING.md',
    'Dockerfile',
    'LICENSE',
    'README.md',
    'SECURITY.md',
    'START.sh',
    'START_MACOS.command',
    'START_WINDOWS.bat',
    'THIRD_PARTY_NOTICES.md',
    '_vendor/VERSIONS.json',
    '_vendor/waitress-3.0.2.dist-info/LICENSE.txt',
    '_vendor/waitress/__init__.py',
    '_vendor/waitress/__main__.py',
    '_vendor/waitress/adjustments.py',
    '_vendor/waitress/buffers.py',
    '_vendor/waitress/channel.py',
    '_vendor/waitress/compat.py',
    '_vendor/waitress/parser.py',
    '_vendor/waitress/proxy_headers.py',
    '_vendor/waitress/receiver.py',
    '_vendor/waitress/rfc7230.py',
    '_vendor/waitress/runner.py',
    '_vendor/waitress/server.py',
    '_vendor/waitress/task.py',
    '_vendor/waitress/trigger.py',
    '_vendor/waitress/utilities.py',
    '_vendor/waitress/wasyncore.py',
    'accounts.py',
    'adapters.py',
    'advisories.py',
    'ai_explainer.py',
    'alerts.py',
    'mastermonk.py',
    'backfill.py',
    'compose.yaml',
    'components.py',
    'config.py',
    'core.py',
    'docs/OPERATIONS.md',
    'docs/screenshots/mastermonk-3.2/01-universe-overview.png',
    'docs/screenshots/mastermonk-3.2/02-universe-focused-record.png',
    'docs/screenshots/mastermonk-3.2/03-discover-overview.png',
    'docs/screenshots/mastermonk-3.2/04-discover-live-catalog.png',
    'docs/screenshots/mastermonk-3.2/05-record-evidence.png',
    'docs/screenshots/mastermonk-3.2/06-record-actions.png',
    'docs/screenshots/mastermonk-3.2/07-investigation-lab.png',
    'docs/screenshots/mastermonk-3.2/08-change-intelligence.png',
    'docs/screenshots/mastermonk-3.2/09-change-stream.png',
    'docs/screenshots/mastermonk-3.2/10-component-compare-form.png',
    'docs/screenshots/mastermonk-3.2/11-component-evidence-badges.png',
    'docs/screenshots/mastermonk-3.2/12-component-differences.png',
    'docs/screenshots/mastermonk-3.2/13-intelligence-catalog.png',
    'docs/screenshots/mastermonk-3.2/SOURCES.md',
    'epss_bulk.py',
    'feeds.py',
    'highlights.py',
    'manifests.py',
    'package-lock.json',
    'package.json',
    'prioritization.py',
    'requirements.txt',
    'safe_http.py',
    'scanner.py',
    'server.py',
    'services.py',
    'source_package.py',
    'start.py',
    'static/app.js',
    'static/briefing.js',
    'static/cosmos.css',
    'static/evidence-graph.js',
    'static/fonts/IBMPlexMono-Regular.woff2',
    'static/fonts/IBMPlexSans-Regular.woff2',
    'static/fonts/IBMPlexSans-SemiBold.woff2',
    'static/fonts/IBMPlexSerif-Medium.woff2',
    'static/fonts/IBMPlexSerif-Regular.woff2',
    'static/fonts/OFL.txt',
    'static/fonts/README.md',
    'static/index.html',
    'static/manifest.webmanifest',
    'static/media/mastermonk-logo.png',
    'static/media/deep-field.webp',
    'static/icons/favicon-64.png',
    'static/icons/mastermonk-192.png',
    'static/icons/mastermonk-512.png',
    'static/osint.js',
    'static/renderer-status.js',
    'static/site.html',
    'static/site.js',
    'static/space-geometry.js',
    'static/style.css',
    'static/sw.js',
    'static/ui.js',
    'static/universe-canvas.js',
    'static/universe-layout.js',
    'static/universe-webgl.js',
    'static/universe.js',
    'static/vendor/BUILD.json',
    'static/vendor/THREE-LICENSE.md',
    'static/vendor/three.js',
    'static_export.py',
    'store.py',
    'taxonomy.py',
    'tests/__init__.py',
    'tests/test_pure_logic.py',
    'tools/build-graphics.mjs',
    'tools/three-entry.js',
    'tools/verify.py',
    'webapp.py',
    'workspace.py',
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
            member.create_system = 3
            mode = 0o100755 if relative.endswith(('.sh', '.command')) else 0o100644
            member.external_attr = mode << 16
            archive.writestr(member, path.read_bytes())
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description="Build a complete MasterMonk source ZIP, without runtime data or credentials.")
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
