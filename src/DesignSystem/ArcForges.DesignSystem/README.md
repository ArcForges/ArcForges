# ArcForges.DesignSystem

Framework-neutral semantic tokens for the shared desktop visual language. The
catalog defines light, dark and high-contrast palettes, semantic typography,
first-class Comfortable, Compact and ProfessionalDense geometry, spacing,
shape, elevation and restrained motion. UI components consume these meanings;
they do not define their own color or size values.

The token library has no third-party dependencies. Avalonia adapters and shell
components belong to their own delivery tasks and must consume these semantic
values. This library does not choose a product's theme or density preference.

## Legacy scaffold reconciliation

The retained `ArcForges.Desktop.Graphics` and `ArcForges.Desktop.Text` projects
contain no behavior to migrate; their visual-token responsibility is delivered
here under the new `ArcForges.DesignSystem` identity. `ArcForges.Desktop.Experience`,
`ArcForges.Desktop.Preview` and `ArcForges.Desktop.RichContent` likewise contain
no behavior to move; their future shared-shell mechanisms map to
`ArcForges.Desktop.Shell` under PLT.27 and later shell tasks. All five existing
project and assembly identities remain untouched and are not referenced by this
library. They remain unpublished scaffolds until their owning tasks resolve
their retained compatibility disposition. No old namespace or package identity
is renamed or repurposed.

The nested `Tests` project verifies palette contrast, semantic coverage, density
snapshots and the raw-value markup policy offline. Package publication and
artifact evidence belong to PLT.35.
