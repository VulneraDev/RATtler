# RATtler Endpoint Security sensor

This directory contains RATtler's notification-only native macOS collector. It
subscribes to process, memory-mapping, task-port, tracing, remote-thread, and
code-signature invalidation events and emits minimal JSONL. It never subscribes
to authorization events and cannot block system activity.

## Build

```sh
make -C native/macos
native/macos/build/rattler-es-sensor --help
```

An unsigned build verifies source compatibility but cannot connect to Endpoint
Security. Live use requires:

1. An Apple Developer team approved for the
   `com.apple.developer.endpoint-security.client` entitlement.
2. A provisioning profile containing that entitlement.
3. Code signing with the approved identity.
4. User approval for Full Disk Access.
5. Root execution.

Apple documents the framework in
[Endpoint Security](https://developer.apple.com/documentation/EndpointSecurity)
and the restricted capability in the
[Endpoint Security Client Entitlement](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.developer.endpoint-security.client).

After provisioning, sign with:

```sh
make -C native/macos sign IDENTITY="Developer ID Application: Example Corp (TEAMID)"
sudo native/macos/build/rattler-es-sensor --output /var/log/rattler/native-events.jsonl
```

Use a root-controlled output directory in production. The collector creates its
log with mode `0600`, refuses symbolic links and non-regular files, and reports
global sequence gaps so the Python bridge can surface lost coverage. The log
contains process paths, PIDs, signing identifiers, and Team IDs.

The bridge currently emits rules `RAT-NATIVE-000` through `RAT-NATIVE-006` for
event loss, code-signature invalidation, writable-executable memory, risky
executable mappings, remote threads, tracing, and task-port-to-remote-thread
correlation.

Do not add authorization events until notification-only behavior, performance,
dropped-event accounting, and failure recovery have been validated on supported
macOS versions.
