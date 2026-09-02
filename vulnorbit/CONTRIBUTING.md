# Contributing to XploitAtlas

Keep the real-source contract intact. A missing response is unknown; an import failure is a visible failure. Do not seed the runtime database with example vulnerabilities, invent scores, label public exploit references as verified executions, or derive event history that was never observed.

New adapters should preserve the publisher identifier, source URL, observation time, relevant source timestamp, and source-specific evidence. Validate the response before reconciliation. Commit data and cursor changes together. Use deterministic identity resolution; do not merge advisories solely because their titles look similar.

Place new network hosts in the explicit allowlist only when a documented provider integration needs them. Scope credentials to the intended provider, enforce bounded requests and provider rate limits, and retain provenance. Preserve unknown, rejected, and conflicting records explicitly.

Render external text with escaping or textContent. Keep keyboard/table alternatives, reduced-motion behavior, and data encodings understandable. Layout coordinates and explanatory animation must not be presented as observed attack data.

Run the validation commands in README.md. Add meaningful tests for changed trust boundaries, identity rules, source removal, or transaction behavior. Live test inputs belong in disposable directories, and upstream outages should never be hidden behind a substitute dataset.

Useful future extensions include documented CSAF/VEX connectors, inventory and SBOM matching, asset-aware prioritization, deduplicated alerts, and a supervised authenticated multi-user deployment. These need explicit provenance and coverage rules of their own.
