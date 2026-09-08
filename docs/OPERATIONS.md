# Operating MasterMonk

The README covers first startup. This guide covers configuration, collection, supported inputs, automation, and publishing.

## Configuration and upgrades

Copy .env.example to .env only when you need different settings. Values are literal; shell commands are never evaluated. Environment variables override the file.

| Setting | Default / purpose |
| --- | --- |
| MASTERMONK_HOST / MASTERMONK_PORT | 127.0.0.1 / 8787 |
| MASTERMONK_DATA_DIR | runtime beside the application |
| MASTERMONK_SYNC_MODE | embedded; alternatives external or off |
| MASTERMONK_INTERVAL | 900 seconds between regular source cycles |
| MASTERMONK_BASE_URL | Public HTTPS origin for a shared server |
| MASTERMONK_ALLOWED_HOSTS | Additional accepted hostnames, comma separated |
| MASTERMONK_TRUSTED_PROXY | One explicitly trusted reverse-proxy IP |
| MASTERMONK_PUBLIC_CATALOG | 1; set 0 to require sign-in for catalog browsing |
| MASTERMONK_NVD_API_KEY / MASTERMONK_GITHUB_TOKEN | Optional upstream credentials |
| MASTERMONK_SMTP_* | Optional TLS email delivery; see .env.example |
| MASTERMONK_WEBHOOK_SECRET | Optional HMAC secret for webhook recipients |
| MASTERMONK_AI_ENDPOINT / MASTERMONK_AI_MODEL | Empty; optional chat-completions endpoint and installed model name |
| MASTERMONK_AI_API_KEY | Empty; optional server-side model credential |

For a deliberate upgrade, stop the old server and collector and back up the entire runtime directory first. MasterMonk 3.x uses `mastermonk.sqlite3` for the public catalog and `workspace.sqlite3` for accounts, private tools, and highlights. Copy the stopped runtime into the extracted new MasterMonk folder to retain your data, or leave it out for a separate empty installation. Version 3.2 does not add a database migration. Keep the original backup for rollback; do not run both versions against one workspace. New installations use only `MASTERMONK_` configuration names.

Back up the runtime directory while the web server and collector are stopped, or use SQLite-aware online backups. Protect backups like the live account and inventory data.

## Accounts and access

Discover, Universe, Intelligence, Compare, Changes, Sources, and Learn are readable without an account by default. For private or administrative tools, the operator uses the terminal's expiring setup code to create the first administrator. Subsequent accounts are created under Settings by an administrator. Each account owns its inventories, alerts, saved filters, priority settings, and API tokens. Administrators manage accounts and global collection; they do not have an API for reading another person's inventory.

Passwords contain 15–128 characters. Sessions expire after 12 hours, or one hour of inactivity. Changing a password or disabling an account revokes its sessions and API tokens. Local account recovery:

    python mastermonk.py user-reset YOUR_USERNAME

API tokens are created in Settings and shown once. They expire after 90 days. Scopes are read, scan, and inventory:write. Account administration, token creation, and collector control require an interactive session. Importing and automatically scanning needs both write and scan scopes.

## Collection and coverage

Default startup runs the web application and its collector together. To keep collection independent:

    python start.py --sync-mode external
    python mastermonk.py worker

Run these as separate supervised processes, pointing at the same absolute data directory. One process holds the collector lock. A scheduler can instead run a bounded pass:

    python mastermonk.py sync --data-dir /absolute/path/to/runtime --sources cisa,github,nvd,epss

The sync command returns 2 when any requested source fails. The --budget argument controls inventory work after feed collection, from 0 to 3600 seconds. Collection needs either a running worker or scheduled jobs; hosting the frontend alone cannot collect data.

| Source | Collection behavior |
| --- | --- |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Full published catalog each cycle; records retain CISA actions and dates. |
| [NVD](https://nvd.nist.gov/developers/vulnerabilities) | Recent/modified windows with persisted cursors. Optional backfill uses rate-limited date windows from 1999 to its captured endpoint. |
| [GitHub Advisories](https://docs.github.com/en/rest/security-advisories/global-advisories) | Reviewed advisories, paginated with update checkpoints; older coverage depends on import history. |
| [FIRST EPSS](https://www.first.org/epss/data) | One dated daily CSV applied to all matching tracked CVEs, with a six-hour download cache. Records absent from that snapshot stay distinguishable from refreshed records. |
| [CVE/CNA](https://www.cve.org/) | Enriched on demand from publisher records. |
| [OSV](https://google.github.io/osv.dev/api/) | Exact package/version queries in batches, with pagination and full advisory evidence. |
| [CSAF](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html) / [OpenVEX](https://github.com/openvex/spec) | User-added JSON or public HTTPS sources; CSAF provider metadata can enumerate advisory changes. |
| [MITRE CAPEC](https://capec.mitre.org/data/index.html) | Fetched on demand for CWE learning relationships, cached for seven days; its explicit ATT&CK taxonomy mappings are linked when supplied. |

Start, pause, or resume historical NVD imports in Sources. CLI equivalents are **python mastermonk.py backfill start**, **pause**, **resume**, and **status**. Completion covers the captured time span; subsequent normal collection continues forward. Progress reports actual windows, pages, and records. There is no preloaded historical archive.

Vendor documents support CSAF 2.0/2.1 and OpenVEX statements. Connector fetches use public HTTPS port 443, reject redirects, and validate public DNS addresses. Each statement retains issuer, document version/date, and product identity. Your trust choice is recorded; cryptographic publisher signatures are not verified. Statements annotate findings without automatically suppressing them.

## Inventory input

Uploads are limited to 5 MiB and 5,000 components. Supported exact-version ecosystems are npm, PyPI, Maven, Go, crates.io, NuGet, Packagist, and RubyGems.

| Input | What can be established |
| --- | --- |
| package-lock.json, npm-shrinkwrap.json | Exact registry package versions from v1/v2/v3 locks, with available dependency paths. |
| requirements.txt | Exact pins; includes, ranges, editable/local dependencies, markers, and alternate-index ambiguity are reported as coverage limitations. |
| poetry.lock, Cargo.lock | Supported registry packages with pinned versions. |
| go.sum | Checksum-listed candidates; it does not establish the resolved build graph. |
| go.mod | Declared dependencies; replacements, excludes, and missing transitive resolution remain limitations. |
| pom.xml | Locally resolvable direct versions and properties; not a Maven resolution engine. |
| CycloneDX JSON 1.4–1.6 / SPDX JSON 2.2–2.3 | Versioned package URLs and available dependency/product relationships. |

The scanner does not execute package managers or install uploaded dependencies. Unsupported or unresolved components remain visible and make a policy run incomplete. Use a resolved SBOM when the original manifest cannot establish the complete build.

A daily inventory refresh is optional. Replace a manifest to update versions while retaining previous findings and notes. A complete subsequent scan can resolve removed matches; failed or incomplete queries preserve earlier findings. Asset importance and internet exposure feed your configurable priority weights.

## CLI and API

Check the application's actual Python dependency manifest:

    python mastermonk.py check requirements.txt --fail-on kev
    python mastermonk.py check package-lock.json --fail-on high --format sarif --output dependency-results.sarif

Use your own manifest path for your software. Exit codes: **0** completed without a policy violation, **1** policy violations, **2** incomplete coverage or failed queries. KEV policy checks require a fresh CISA catalog. Other policies are critical and priority; priority accepts --threshold 0–100. Unknown severity cannot establish a successful high/critical policy check.

The API accepts Authorization: Bearer with a token from Settings. Send application/json for mutations.

| Route | Purpose |
| --- | --- |
| GET /api/catalog, /api/record?id=..., /api/sources | Public-source intelligence, subject to the instance's public-catalog setting |
| GET /api/inventories, /api/findings | Your inventory and matched findings |
| POST /api/inventories | Import name, filename, content; optional asset context and scan flag |
| POST /api/inventories/replace | Replace an owned inventory's manifest using id, filename, content |
| POST /api/inventories/action | Queue a scan or update/delete an owned inventory |
| POST /api/package | Query ecosystem, name, version |
| GET /api/component-compare?left_ecosystem=...&left_name=...&left_version=...&right_ecosystem=...&right_name=...&right_version=... | Public current OSV exact-version comparison when public-catalog mode is enabled |
| GET /badge/component.svg?ecosystem=...&name=...&version=... | Dynamic public SVG showing current OSV match and collected KEV counts |
| GET /api/evidence?id=... | Evidence for an owned finding |
| GET /api/trends?days=30&basis=source | Counts using actual provider publication and modification dates |
| GET /api/trends?days=30&basis=observed | Counts from this instance's actual saved observation history |
| GET /api/trend-records?basis=source&metric=published&start=YYYY-MM-DD&end=YYYY-MM-DD | Collected records behind an activity period |
| GET /api/compare?from=YYYY-MM-DD&to=YYYY-MM-DD | Inclusive UTC saved-observation comparison, up to 367 days; exact distinct-record counts, up to 200 records per category, and latest 50 field-change events |
| GET /api/taxonomy?id=... | MITRE CAPEC relationships for the record's reported CWE identifiers |
| GET /api/highlight?token=... | Enabled shareable briefing; follows the public-catalog setting |
| GET /api/highlights; POST /api/highlights, /api/highlights/action | Your pages, create a page, or revoke/restore/delete an owned page; writes require an interactive session |
| POST /api/ai/explain | Explicit, signed-in generation for one collected record; one concurrent job, six requests per account per hour |

The interface uses the same API and exposes accepted action names. Interactive requests use the session's CSRF token; API-token scopes are enforced separately. Anonymous users cannot change accounts, preferences, private tools, or highlights. The bounded CVE/GHSA publisher lookup can enrich the shared public catalog.

## Component comparison and badges

The Compare view accepts only supported ecosystems and exact versions. Each side uses OSV's package-query API, saves only the returned public advisory evidence, and reuses a bounded five-minute in-process cache. The response separates advisory identifiers that appear only for component A, in both responses, or only for component B. Those groups are evidence differences, not automatic upgrade or remediation advice. Incomplete pagination remains visible, and zero matches are described as “0 OSV matches,” never as secure.

The SVG badge is public only while public-catalog mode is enabled and the instance is reachable. Its URL exposes the ecosystem, package name, and exact version to the server, intermediary logs, and OSV. It returns “source unavailable” when the live query fails. Per-client and instance-wide request limits protect the OSV connector; a five-minute public cache header lets normal README and documentation embeds reuse the response. Private package names or versions should not be put in public badge URLs.

## Highlights and date briefings

Open a record → **Add to highlights** → **Highlights**. Add a title, a briefing note, and optional per-record notes, then explicitly create the shared page. Up to 24 records per page and 100 pages per account are supported. The page presents current public evidence, not a frozen snapshot. Notes are escaped plain text and labelled as author interpretation. Revoke, restore, or delete the page from **Manage my highlights**. Disabling its owner also makes the public link unavailable.

The random link is a capability: anyone with it can read its notes and selected public records when public browsing is enabled. Copying a link does not publish a local server. On `127.0.0.1`, it is useful only on that same device. A reachable HTTPS origin or your existing tunnel allows another device to open it while the server and tunnel are running. Changing a quick-tunnel hostname requires updating the hostname in the link; the stored page token survives. Do not put confidential notes in a shared briefing.

The date comparison separates first indexing from later changes. Counts are distinct records within each category, not a total of all revisions. The before/after table shows exactly what was saved in each change event, not a reconstructed database snapshot at both endpoints. Records in different categories can overlap. Publisher timeline charts remain a separate view of source dates.

## Optional AI reading aid

AI is disabled by default. Configure a chat-completions-compatible endpoint and a model that you have actually installed or have access to, then restart MasterMonk. `MASTERMONK_AI_ENDPOINT` is the complete endpoint path (normally ending in `/v1/chat/completions`); `MASTERMONK_AI_MODEL` is the provider's exact model identifier. Supply `MASTERMONK_AI_API_KEY` only if required. HTTPS remote endpoints must pass the public-address checks; plain HTTP is allowed only for `localhost`, `127.0.0.1`, or `::1`. Use a local endpoint on the MasterMonk server, not a mobile client's localhost.

The model must accept JSON-object response formatting. Open a CVE → **AI reading aid** → **Send this record & generate explanation**. This sends the selected public description, scores, and source links only. No private inventory, highlight note, or account data is sent. The model returns summary, importance, defensive investigation checks, and citations restricted to supplied URLs. These checks do not guarantee factual correctness. Output is escaped plain text, labelled AI-generated, kept in the browser only, and never merged into observations, alerts, or priority scoring. Closing it discards the output. Provider failures return an error rather than invented evidence.

A local model may run without API fees but needs separately installed model software and adequate hardware. Remote providers may charge; MasterMonk does not purchase credits or download a model. Credentials stay server-side and out of the ZIP.

## Watchlists and delivery

A new watch records its current baseline. Later KEV additions or threshold crossings create deduplicated notifications; changing priority weights starts a new baseline rather than replaying old matches.

Inbox and private Atom feeds work without outbound mail configuration. Atom links are bearer secrets and can be rotated. Email requires configured SMTP TLS settings; webhook destinations must be public HTTPS. Delivery includes stable event identifiers, bounded retries, and visible failure state. X-MasterMonk-Signature is an optional HMAC-SHA256 signature over the exact webhook body. Automatic delivery occurs only for destinations you configure.

## Share with an audience

**Full application:** run Docker Compose or supervised web/worker processes on a host with persistent disk. Put the web service behind an HTTPS reverse proxy, configure BASE_URL, and forward only through the specified trusted proxy. The supplied Compose file binds the host's port to loopback and stores data in a named volume.

    docker compose up --build -d

Public browsing is enabled by default (MASTERMONK_PUBLIC_CATALOG=1). Browsers can read the catalog, investigations, and Learn views; accounts remain required for private tools and administration. The same-origin CVE/GHSA lookup fetches only allowlisted public publisher records, with per-client and instance-wide limits. Set MASTERMONK_PUBLIC_CATALOG=0 when the catalog must also require authentication. A hosting provider supplies the compute, persistence, and domain/TLS arrangement. Costs depend on that provider and usage.

The full application is also an installable PWA. Android, iPhone, iPad, Windows, macOS, and Linux clients all use the same responsive frontend and HTTPS API. Mobile devices do not run separate collectors. The server remains the authoritative source of catalog records, timestamps, accounts, and alert state. The service worker caches only bundled interface files and never caches `/api/`, `/feeds/`, individual vulnerability pages, sessions, or workspace responses.

**Static public edition:** collect real records, then export them:

    python mastermonk.py sync --data-dir .catalog-data --sources cisa,github,nvd,epss --budget 0
    python mastermonk.py export-site --data-dir .catalog-data --output _site --base-url YOUR_PUBLIC_HTTPS_URL

Use an empty output directory. The exporter refuses an empty catalog. It writes a read-only catalog, 3D explorer, per-record pages, and a sitemap. It never copies the account or inventory database. The page shows its snapshot time; updated data requires a new export. Static hosting does not provide sign-in, inventory uploads, scans, or alerts.

The optional **Publish public catalog snapshot** GitHub Actions workflow runs only when manually started. After reviewing and committing this build, choose GitHub Pages' GitHub Actions source, then run that workflow. It deploys a new snapshot only if all requested imports and the export succeed. Check [GitHub Pages availability and limits](https://docs.github.com/en/pages/getting-started-with-github-pages/about-github-pages) for your account. No domain purchase is required to use the supplied github.io address.

## Verification

    python -E -m unittest discover -s tests -v
    python -E tools/verify.py
    python -E tools/verify.py --live

The unit command checks isolated priority mathematics, CAPEC identifier and XML-safety primitives, the actual bundled dependency manifest, badge wording, and neutral SARIF metadata. It performs no network or database work and contains no vulnerability fixture or account. The full verification command validates syntax, actual bundled graphics exports and hash, shell-asset completeness, the launcher, empty first-run state, comparison routes, access protection without a session, and startup from a freshly extracted source ZIP. The optional live command queries CISA and OSV using this project's actual requirements.txt. It does not fabricate records or accounts. It does not exercise account creation, shared-link revocation, model generation, or rendered GPU/touch behavior; those need review with your own real instance.

The workflow configures equivalent Windows, macOS, and Linux startup checks on Python 3.11 and 3.14. Configuration is not evidence those jobs have already run. These checks do not replace exercising real account workflows, reviewing GPU visuals on your hardware, or a deployment security review.

Build a complete allowlisted source download:

    python source_package.py --output MasterMonk.zip

Maintainers can rebuild the pinned graphics bundle with npm ci --ignore-scripts followed by npm run build:vendor. Runtime users do not need Node.js.
