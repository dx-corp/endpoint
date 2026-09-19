# Deixic Endpoint for macOS

The macOS agent is a Swift Package with process, network, file, persistence,
and security telemetry providers. It shares the public rule and spool contracts
with the Linux agent while using native macOS sources and capability checks.

Build and run the standalone test matrix with:

```sh
swift package resolve
swift test
./test-client.sh
```

Build an unsigned local package with `./build.sh`. Packaging helpers live under
`packaging/`; pass signing identities only through their documented environment
variables and never commit them. A distributable package additionally requires
Apple-issued entitlements, Developer ID application and installer certificates,
notarization, and stapling.

The source can exercise providers available to the current host. Endpoint
Security and Network Extension behavior depends on the corresponding Apple
entitlements and user or MDM approval. A local build does not establish those
capabilities or release trust.
