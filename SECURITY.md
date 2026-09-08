# Security

Public-source catalog browsing is enabled by default; private inventories, saved settings, and administrative controls require authentication. Set MASTERMONK_PUBLIC_CATALOG=0 to gate the catalog too. CVE/GHSA lookups require a matching Origin and are bounded to two concurrent requests, six per client per minute, and twenty per instance per minute, with provider caching. They accept identifiers, not arbitrary URLs. Public component comparison and badge routes accept supported package identities only, share a two-request concurrency bound, and apply per-client and instance limits. Badge responses cache for at most five minutes.

MasterMonk has password-based accounts, owner-scoped workspaces, expiring sessions, scoped API tokens, CSRF protection, request limits, and escaped source text. Passwords use salted scrypt hashes. Session cookies are HttpOnly and SameSite=Strict, with Secure enabled for a configured HTTPS origin. Password changes and account disablement revoke access tokens.

The default listener is local. Shared deployments require a configured HTTPS origin, persistent storage, and a reverse proxy with an explicitly trusted IP. Waitress is the application server; it does not terminate TLS. MasterMonk 3.2.0 has not undergone an independent security audit.

Inventories, credentials, webhook destinations, and notifications belong to the operator's runtime storage. Package checks send package names, ecosystems, and exact versions to OSV. Public badge URLs also expose those three values to anyone who sees the URL and to normal request logs; do not embed a badge for a private component. Vendor connectors fetch URLs explicitly configured by an account owner; outbound requests reject private addresses and redirects. The app reads dependency metadata and public intelligence; it does not execute package managers or exploit references.

Public-catalog mode exposes public vulnerability intelligence and deliberately shared highlight notes. Highlight links use random tokens; owners can revoke them, and disabled owners' links stop working. Do not use these links for confidential briefings. Static exports contain only public vulnerability intelligence. Source ZIPs use an explicit allowlist excluding runtime databases, raw responses, credentials, and private files. Backups and private Atom links require operator protection.

Optional AI requests require a signed-in interactive session and CSRF validation. The administrator configures the endpoint server-side; visitors cannot choose arbitrary destinations. Remote endpoints must use public HTTPS; loopback HTTP is supported for locally installed models. Only selected public record fields are sent. Model output is untrusted plain text, marked AI-generated, and citations must match provided URLs. This is not factual verification: users must check the source evidence. Output is not retained in the catalog. Model credentials never appear in API responses.

The MITRE CAPEC download is limited in size, rejects XML entity declarations, uses bounded cache refreshes, and retains source and retrieval information. CWE-to-CAPEC-to-ATT&CK links are class-level learning associations, not verified exploitation of a particular record.

For a suspected application vulnerability, use the repository's private vulnerability reporting feature if available. If it is unavailable, request a private contact without posting credentials or sensitive details. Provide the affected version, route or feature, and reproducible observations.

See [Operations](docs/OPERATIONS.md) for configuration, account recovery, backups, and deployment.
