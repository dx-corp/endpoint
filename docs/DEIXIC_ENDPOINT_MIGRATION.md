# Deixic Endpoint naming and compatibility

Deixic Endpoint is the canonical customer-facing name for Deixic's endpoint
telemetry and policy-enforcement surface. The current implementation uses the
`merlin` runtime and compatibility namespace. The source is a first-class
product under `products/deixic-endpoint`. This promotion does not by itself
activate commercial entitlements, deploy binaries, define support policy, or
certify production readiness.

## Compatibility matrix

| Surface | Canonical presentation | Retained identifier | Status | Migration boundary |
| --- | --- | --- | --- | --- |
| Product and UI | Deixic Endpoint | Merlin in compatibility explanations | New visible copy uses Deixic Endpoint | Historical material and machine coordinates retain their exact values. |
| Linux command | Deixic Endpoint help text | `merlin` | Retained compatibility command | Scripts and service units continue to call the existing binary. |
| macOS command | Deixic Endpoint help text | `merlin-macos`, `MerlinMacOS` | Retained compatibility commands and Swift symbols | Existing installation and automation paths continue to work. |
| Packages and services | Deixic Endpoint installation copy | `merlin.service`, `Merlin-<version>.pkg`, `merlin-<version>-linux-*`, `com.evalops.merlin*` | Retained compatibility coordinates | Artifact names, package IDs, and service labels need a separately reviewed migration. |
| Configuration and state | Deixic Endpoint in operator guidance | `MERLIN_*`, `/etc/merlin`, `/var/lib/merlin`, `/Library/Application Support/Merlin`, `/Library/Logs/Merlin` | Retained compatibility contract | Existing enrolled devices preserve their configuration and telemetry paths. |
| APIs and telemetry | Deixic Endpoint in human-readable descriptions | `X-Merlin-*`, `merlin_*` metrics, schema values, table names, roles, spool names | Retained compatibility contract | Wire identifiers and stored values remain unchanged. |
| Delivery graph | Deixic Endpoint (`merlin` component) | component and Deploy lane `merlin`, images `ghcr.io/dx-corp/merlin-*`, required context `Merlin macOS / macOS Swift` | Retained integration coordinates | Branch protection and Deploy continue to consume the current identifiers. |

## Source language

New product and operator copy uses Deixic Endpoint. Code comments may use
Merlin when they describe an exact binary, type, module, protocol field, file,
fixture, or historical implementation detail. Removing a retained identifier
requires a separate reviewed change that names affected consumers and defines
a migration window.
