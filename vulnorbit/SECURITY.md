# Security boundaries

XploitAtlas retrieves public vulnerability intelligence. It does not execute exploit references. Package checks send the entered ecosystem, package name, and exact version to OSV; matching public advisory records are retained. Query bodies and credentials are excluded from request logs and raw-response captures.

The default service listens on 127.0.0.1. It has no built-in multi-user authentication. Use an authenticated TLS reverse proxy and restrict accepted hostnames before making it available beyond a trusted local environment. The standard-library HTTP server is not an internet edge server.

The application escapes source text, validates source URLs, restricts upstream hosts to HTTPS providers, rejects redirects, limits response sizes and request bodies, checks Host and Origin on mutation routes, and exports CSV with formula prefixes neutralized. Source downloads use an explicit file allowlist and exclude databases, raw captures, and environment secrets.

SQLite and raw-response files belong to the local operator. Treat the runtime directory and backup exports according to your organization’s data handling requirements. Supply optional API credentials through the environment; never commit them.

For a suspected application vulnerability, use the repository’s private vulnerability reporting feature if available. If no private channel is configured, open an issue requesting a private contact without publishing exploit details or credentials.

An unavailable provider, a missing metric, or a published advisory is not evidence that a specific asset has been compromised. The Sources view and per-record evidence establish exactly what was observed.
