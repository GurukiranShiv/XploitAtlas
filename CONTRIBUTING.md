# Contributing

Use real publisher records and preserve their identity, source URL, observation time, and relevant source timestamp. Failed imports must preserve the last successful evidence and expose their error. Unknown values remain unknown.

Do not add synthetic vulnerability fixtures, demo results, preset accounts, or bundled datasets. Verification can use the actual empty first-run state, this project's real dependencies, and current provider responses in disposable directories. Never publish credentials or runtime data with verification output.

Keep owner checks, API scopes, CSRF protection, bounded requests, and transaction boundaries intact when adding features. Provider additions need documented provenance and rate limits. UI changes need keyboard access, readable evidence outside the 3D view, and reduced-motion support.

Run **python -E -m unittest discover -s tests -v** for fast pure-logic feedback, then **python -E tools/verify.py** and, when changing provider behavior, the relevant real-source checks. Unit tests may use mathematical primitives, format identifiers from official taxonomies, and this repository's actual dependency files; do not add synthetic vulnerability or advisory records. Report what ran and any unverified behavior; an unavailable provider is not a passing check. [Operations](docs/OPERATIONS.md) explains validation and graphics rebuilding.

Keep user setup in README and operational detail in docs/OPERATIONS.md. Add required public files to SOURCE_FILES in source_package.py. Preserve dependency licenses and authentic screenshot provenance; remove internal review notes before proposing a public release.
