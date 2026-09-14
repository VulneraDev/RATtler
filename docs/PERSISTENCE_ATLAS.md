# Persistence Atlas

Persistence Atlas is RATtler's bounded, source-aware map of macOS autostart and
security configuration. It is included in every normal scan as the
`persistence_atlas` sensor and has a dedicated view in the macOS app.

The goal is to make persistence review explainable without labeling every
installed extension, profile, or login item as malicious. Inventory, coverage,
and alerts are kept separate.

## Sources

Each source reports `healthy` or `degraded` independently. A denied browser or
privacy-control directory therefore does not hide cron, shell, or login-item
coverage.

| Source | What is retained |
| --- | --- |
| Login items | Name, path, status, and bounded app signing/Gatekeeper context |
| Background task management | Metadata for the per-user background-items database |
| Shell startup | Metadata and bounded inspection of standard user startup files |
| Cron | System cron-file metadata plus privacy-safe current-user job summaries |
| Periodic jobs | Metadata for files under `/etc/periodic` |
| Authorization plug-ins | Bundle metadata, strict signing identity, and Gatekeeper context |
| Browser extensions | Bounded manifest name, version, permission count, and update URL |
| Developer extensions | VS Code, Cursor, Windsurf, and Xcode extension metadata |
| Configuration profiles | Bounded name, identifier, UUID, organization, scope, and enrollment state |
| Privacy controls | TCC database filesystem metadata only—not its grant rows |
| Security controls | SIP, application-firewall, and FileVault command state |

Notarization is recorded as distribution context when macOS exposes it. It is
not a runtime-safety verdict and does not suppress behavioral evidence.

## Alert rules

| Rule | Signal | Severity |
| --- | --- | --- |
| `RAT-PERSIST-101` | Persistence asset is a symbolic link | medium |
| `RAT-PERSIST-102` | Persistence asset is group- or world-writable | high |
| `RAT-PERSIST-103` | System persistence asset is not root-owned | medium |
| `RAT-PERSIST-104` | Startup or cron source references a temporary staging path | high |
| `RAT-PERSIST-105` | Startup or cron source configures library preloading | high |
| `RAT-PERSIST-106` | Privileged authorization plug-in fails strict signing | high |
| `RAT-PERSIST-107` | Extension manifest uses an unencrypted update URL | medium |
| `RAT-PERSIST-108` | Login item launches from a risky staging location | high |
| `RAT-PERSIST-109` | Login-item app fails strict signing validation | medium |

Ordinary extension permissions, installed profiles, and security-control values
are inventory evidence. They do not create malware findings on their own.

## Safety and privacy bounds

- At most 512 objects are considered per source and 2,500 across the sensor.
- At most 24 objects per source are returned in the report.
- Traversal stops after six directory levels, 50,000 visited paths per source,
  and 16,384 children per directory; it never follows symbolic links.
- Manifest and startup-file inspection is capped at 1 MiB per file.
- Command output is capped at 2 MiB.
- Signing checks are capped at 16 authorization plug-ins and eight login apps.
- Current-user cron command text is never returned. Reports retain only line
  numbers and whether a preload or staging-path pattern was present.
- Configuration-profile payload content is excluded; only list metadata and
  enrollment state are retained.
- TCC grant rows are never read or copied into a report.
- No source data is uploaded by RATtler.

Some local paths, file ownership, extension names, signing identifiers, and
configuration command results can appear in an exported report. Treat exports
as endpoint evidence and share them only with people authorized to investigate
the Mac.

## Integrity baselines

Creating a normal RATtler integrity baseline now includes eligible Atlas file
assets. Symlinks, oversized files, TCC databases, command-only configuration,
and current-user crontab text are excluded.

On later scans, a source that cannot be read is marked degraded and its Atlas
asset kind is excluded from that comparison. RATtler does not turn a permission
failure into a false "baselined asset is missing" alert.

The baseline remains owned by the current user. It improves drift detection but
does not claim tamper resistance against malware already running with that
user's privileges; root-owned state belongs to the future signed system
extension milestone.
