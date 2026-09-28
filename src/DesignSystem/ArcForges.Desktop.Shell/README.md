# ArcForges.Desktop.Shell

Framework-neutral state for a multi-window desktop shell: per-launch window ownership, dockable/collapsible panel arrangements, display-aware layout restoration, and device-local persistence. UI frameworks are adapters over these models; this project does not choose or load one.

`WindowRegistry` is scoped to one `InstanceId` for the current launch. Saved layouts deliberately do not use that ephemeral identity. A `DeviceLocalLayoutStore` is instead scoped by a validated application key and layout key beneath the owner-selected `LocalApplicationData` root, so a new launch can restore a prior arrangement without sharing it between applications or layouts. The keys are hashed before being used in the path.

Layout writes use a flushed same-directory temporary file followed by replacement, preserving the last committed layout if a write is interrupted. Invalid or truncated JSON is reported as corrupt without being overwritten. Restore filters panels no longer registered by the current application, clamps window bounds to the current display work areas, and falls back to the primary display if a saved display has disappeared.

This project is non-packable. Package activation and UI-framework adapters are intentionally outside this task.
