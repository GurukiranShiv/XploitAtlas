# XploitAtlas technical guide

[Project overview](../README.md) · [Start here](../RUN_ME_FIRST.md) · [Security boundaries](../SECURITY.md)

This guide covers the public Canvas-based application in this repository. Local-only WebGL experiments and unfinished upgrades are not part of this download.

## What you can do

- **Explore a perspective-projected point cloud:** drag to orbit, scroll or use buttons to zoom, select a vulnerability, and expand the canvas. Arrow keys rotate; `+`/`-` zoom; `Home` resets; Space toggles orbit.
- **Use the accessible table:** search, filter by severity, publication window, or KEV status, sort by priority/CVSS/EPSS/publication, and page through all matching records.
- **Investigate evidence:** inspect source observations, source-specific scores, CVSS vectors, CWE identifiers, KEV evidence, vendor advisories, tagged exploit references, and remediation links.
- **See actual changes:** compare fields between saved source versions. History distinguishes local observation time from publisher time.
- **Check packages:** submit an ecosystem, registry package name, and exact installed version to OSV; inspect affected ranges and published fixed branches.
- **Learn with a real record:** follow identity → impact → evidence → response in an animated walkthrough. Choose any investigated record as the teaching example.
- **Export and extend:** download the canonical catalog as provenance-bearing JSON or spreadsheet-safe CSV; download the application source from the interface.

The interface respects reduced-motion preferences, provides pause controls, keyboard navigation and focus indicators, and keeps the record table available alongside the canvas.

## Sources and coverage

| Source | What is used | Refresh behavior |
| --- | --- | --- |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) / [official CISA mirror](https://github.com/cisagov/kev-data) | Complete known-exploited catalog, dates, required actions, ransomware evidence, reference links | Every scheduled cycle; the official GitHub mirror is tried if the primary feed is unavailable |
| [NVD API](https://nvd.nist.gov/developers/vulnerabilities) | CVE descriptions, CVSS, CWE, CPE-derived product labels, source-tagged exploit/advisory/patch references | Initial KEV enrichment plus separate published and modified streams, initially covering seven days; durable pagination and overlapping incremental windows |
| [FIRST EPSS](https://www.first.org/epss/) / [API](https://api.first.org/epss/) | Dated exploitation probabilities and percentiles | Up to 1,000 tracked CVEs per cycle in batches of 100; rotating sweep; the source publishes daily scores |
| [GitHub Advisory Database API](https://docs.github.com/en/rest/security-advisories/global-advisories) | Reviewed advisories, aliases, package ranges, first patched releases, CVSS | Seven-day initial modified window, then paginated updates with a five-minute overlap |
| [CVE / CNA](https://www.cve.org/) | Publisher descriptions, severity, affected products, vendor references, rejected status | On investigation, with successful results cached for six hours and failure backoff |
| [OSV](https://google.github.io/osv.dev/api/) | Package/version matches, advisory aliases, range events and fixed releases | On package checks and advisory investigation |

The scheduler defaults to a 15-minute interval after each completed cycle; the minimum configured interval is five minutes. Provider retry delays take precedence. NVD imports up to one page of 2,000 KEV records during bootstrap and one page of 1,000 records from each incremental stream per cycle. GitHub imports one page of 100 advisories per cycle. Cursors survive restarts, so backlogs continue automatically. NVD catch-up windows are bounded to its date-range limit.

**Coverage is explicit.** This is a growing local catalog, not a complete historical mirror of every CVE. Sources reports the imported windows, page progress, last successful fetch, latest attempt, errors, and retry times. Dashboard statistics describe the local catalog. The canvas renders up to 4,500 matching records; its count discloses that limit, while the paginated table can access the entire local result set.

Vendor advisories and exploit evidence are linked from publisher records and source-tagged references. XploitAtlas does not independently verify exploit reliability or execute exploit material.

## How to read the universe

Each point maps to one actual canonical CVE or advisory. Vendors form constellations; connections shown on focus indicate a shared vendor label. Perspective, rotation, and zoom operate on x/y/z layout positions projected onto a 2D Canvas. This public version does not use WebGL or Three.js. A deterministic layout algorithm places the records in space; **distance and position are not measured risk or attack telemetry**.

Point size reflects the supplied CVSS score. KEV takes precedence in the color encoding, followed by severity; unknown scores have a neutral treatment. The learning animation illustrates investigation order, not observed attack traffic.

KEV inclusion is evidence of exploitation in the wild, not proof that an attack is occurring now or that a particular asset is affected. Absence from KEV is not proof that exploitation has never occurred. EPSS is a prediction for the next 30 days; CVSS is technical severity. The dated and attributed values are kept distinct.

## Explainable triage model

`vulnorbit-1` is an additive, capped heuristic, not a calibrated risk probability:

| Evidence | Points |
| --- | ---: |
| CISA KEV inclusion | 60 |
| CISA reports known ransomware use | 10 |
| Source-reported CVSS × 2, rounded | 0–20 |
| EPSS ≥ 50% / ≥ 10% / ≥ 1% | 15 / 10 / 5 |
| Publisher-tagged exploit reference | 5 |

The score is capped at 100. KEV records use **Act now**; otherwise scores ≥30 use **Investigate**, ≥14 use **Review**, and lower scores use **Monitor**. Rejected/withdrawn authoritative records use **Verify record** and are not treated as ordinary low-risk findings. Every point contribution and missing input is shown.

Canonical CVSS prefers CVE/CNA, then NVD, then GitHub. Each source retains its own metric and timestamp, and disagreement is displayed. Package ranges remain attributed to their respective source; fixed releases are never guessed from severity or a generic “latest version” assumption.

Prioritization still requires your actual exposure, affected versions, business impact, and compensating controls. CISA catalog due dates apply to covered US federal agencies; other users should apply their own obligations.

## Persistence and provenance

The default `runtime/` directory contains:

- `vulnorbit.sqlite3`: source observations, canonical records, field-level changes, cursor checkpoints, source health, and fetch fingerprints.
- `raw/<source>/<sha256>.json.gz`: exact raw GET responses, compressed locally. Raw files are retained for 30 days. Observation and change history is retained until the database is deliberately removed.

Imports commit normalized observations, canonical materializations, change events, and cursor movement in one SQLite transaction. Failed pages cannot advance the cursor. A validated, complete, nonempty CISA catalog is required before removing KEV status; empty or malformed feeds retain the previous evidence.

The first successful source import establishes its baseline. Subsequent first observations and changed fields generate events; the app does not fabricate a timeline from disclosure dates. Fresh fetch times alone do not count as field changes.

Package checks send the ecosystem, package name, and installed version to OSV. Query inputs and POST bodies are not logged or saved as raw captures. Matching public advisory records are retained and fused into the catalog. API credentials are kept in environment variables and are never sent to the browser.

To back up a running database, use SQLite’s backup facility; copying only the `.sqlite3` file while WAL writes are active can miss data. Alternatively, stop the process before copying the complete runtime directory.

## Configuration

| Setting / flag | Default | Purpose |
| --- | --- | --- |
| `VULNORBIT_HOST` / `--host` | `127.0.0.1` | Interface to bind |
| `VULNORBIT_PORT` / `--port` | `8787` | Local HTTP port |
| `VULNORBIT_DATA_DIR` / `--data-dir` | `runtime` beside the source | Persistent storage directory |
| `VULNORBIT_INTERVAL` / `--interval` | `900` seconds | Delay between completed import cycles; minimum 300 |
| `VULNORBIT_ALLOWED_HOSTS` | Localhost names | Comma-separated hostnames accepted from a reverse proxy |
| `NVD_API_KEY` | Empty | Optional NVD key; adjusts API pacing |
| `GITHUB_TOKEN` | Empty | Optional token for the public advisory API |
| `--once` | Off | Run one bounded import cycle, print actual status, and exit |
| `--no-sync` | Off | Serve saved intelligence without automatic imports |

Python reads the process environment, not a `.env` file. In PowerShell, set optional variables before starting:

```powershell
$env:NVD_API_KEY = "your-key"
.\START_WINDOWS.bat
```

For Docker Compose, copy `.env.example` to `.env` if optional credentials are needed. `.env` is excluded from Git, Docker build context, and source downloads.

## HTTP API

| Endpoint | Behavior |
| --- | --- |
| `GET /api/health` | Source health, scheduler state, observation baseline |
| `GET /api/universe?q=&severity=all&days=0&kev=0&sort=priority&limit=40&offset=0` | Filtered summaries, match count, catalog statistics and latest records |
| `GET /api/record?id=CVE-…` | Saved canonical record with provenance |
| `GET /api/events?id=CVE-…&before=…` | Observed changes with cursor pagination; ID filter is optional |
| `POST /api/enrich` | Request publisher and matching OSV evidence; JSON: `{"id":"CVE-…","osv":"GHSA-…"}` with optional OSV alias |
| `POST /api/package` | OSV query; JSON keys: `ecosystem`, `name`, `version` |
| `POST /api/sync` | Queue a source refresh; requests are rate limited |
| `GET /api/export?format=json` or `format=csv` | Full local catalog export |
| `GET /api/source` | Standalone source archive, excluding runtime data and credentials |

Browser POST requests must be same-origin. A local command-line client must explicitly send `X-VulnOrbit-Client: local-cli`. No CORS access is enabled. Upstream destinations are allowlisted HTTPS providers; redirects are rejected, responses are size-limited, and NVD requests are paced.

The included HTTP server is intended for local or protected internal use. A public deployment needs an authenticated TLS reverse proxy, appropriate process supervision, and operational sizing. Multi-user authentication, tenant isolation, asset inventory/SBOM ingestion, and alert delivery are extension work; they are not claimed by this version.

## Development and validation

Run these commands from the extracted project root, not from `docs/`.

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -p 'test_*.py' -v
node --check static/app.js
node --check static/universe.js
node --check static/ui.js
node --test tests/ui.test.js
```

Node is needed only for these optional JavaScript checks, not to run the app. Opt-in integration tests fetch actual upstream feeds into a disposable directory and exercise normalization, transaction rollback, KEV reconciliation, history, raw-response hashing, package matching, HTTP routes, origin checks, and source/export downloads:

```bash
VULNORBIT_LIVE_TESTS=1 python3 -m unittest discover -s tests -p test_live.py -v
```

PowerShell:

```powershell
$env:VULNORBIT_LIVE_TESTS = "1"
py -3.12 -E -m unittest discover -s tests -p test_live.py -v
```

An unavailable provider can fail the live integration run. Tests never substitute a sample catalog. Validation-only mutations of genuine observations exercise reconciliation and rollback exclusively in temporary databases; they are not installed or served as application intelligence.

The repository workflow checks syntax, boundaries, JavaScript, complete download contents, and Windows startup. Real-source integration checks are opt-in via a manual workflow run or the commands above; provider outages can fail them. No browser visual review is claimed.

## Build a complete source download

```bash
python3 source_package.py --output ../XploitAtlas-source.zip
python3 tests/verify_archive.py ../XploitAtlas-source.zip
```

The in-app **Download source** action uses the same explicit file list. Required code, local graphics, setup instructions, public documentation, screenshots and provenance, tests, and licensing are included. Runtime databases, raw responses, credentials, and unlisted files are excluded. The archive has one top-level `XploitAtlas/` folder. GitHub **Code → Download ZIP** also contains the complete project on this branch.

## Code map

| File | Responsibility |
| --- | --- |
| `adapters.py` | Validate and normalize the six upstream sources |
| `core.py` | Canonical fusion, metric precedence, priority reasoning and field diffs |
| `store.py` | SQLite transactions, materialized catalog, provenance, history and paging |
| `feeds.py` | Bounded HTTP, raw captures, resumable imports, enrichment and scheduler |
| `server.py` / `start.py` | HTTP endpoints and startup |
| `source_package.py` | Explicit file allowlist and complete source-download packaging |
| `static/universe.js` | Perspective-projected 3D scene and interaction |
| `static/app.js` / `static/ui.js` | Evidence, tables, source health, packages and learning |
| `static/style.css` | Responsive interface, accessible focus and motion preferences |

The repository root is the application directory: `START_WINDOWS.bat`, `start.py`, the Python modules, and `static/` ship together. The older scanner prototype, interview preparation, demo fixtures, and backend screenshots are not included in this clean project.

## License

Application code is provided under the [MIT license](../LICENSE). Upstream data retains its providers’ terms and attribution; the application license does not relicense provider content.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for extension guidelines and [SECURITY.md](../SECURITY.md) for the application’s security boundaries.
