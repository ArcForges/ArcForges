# Third-party control admission

Desktop UI controls are not admitted by package availability or by a successful ordinary
build. Before a control is used by a shipped shell, its actual consuming application must
complete a Native AOT publish with zero trim and AOT diagnostics. The proof and the control's
licence position are recorded together against the consuming boundary.

## Admission rule

Each control has one explicit record with these fields:

- exact package ID, version, and package containing the control (a control namespace is not
  necessarily a NuGet package ID);
- exact consuming project and user-visible shell surface;
- target framework, RID, SDK, and publish properties used for the real consumer;
- a durable CI or local proof reference tied to the source commit and candidate package bytes;
- the unedited publish result, showing Native AOT was enabled and zero trim/AOT diagnostics;
- exact licence expression and authoritative licence/source references for every package
  supplying the control, plus the redistribution obligations at the consuming boundary.

The lifecycle is `proposed` → `admitted` only after every field is complete and the real
consumer proof passes. A proposed or unverified control must not be referenced by shell code.
An ordinary library build, analyzer-only result, placeholder consumer, or a proof for a
different version/RID does not admit it. No diagnostic suppression is allowed to manufacture
a zero-diagnostic result. If a control or package version changes, its proof and licence record
must be repeated for that exact candidate.

## Current position and candidate

The current `DesktopPlatform` source tree has no Avalonia control or XAML usage. The following
is a proposed first candidate, not an admitted dependency:

| Status | Control | Package / version | Licence | Intended consuming boundary |
|---|---|---|---|---|
| Proposed — **not admitted** | `Avalonia.Controls.TableView` (read-only table) | `Avalonia` 12.1.3; TableView is part of the core package, not a separate `DataGrid` package | MIT, per the exact NuGet package | `ArcForges.Desktop.Shell`, for a read-only operator activity/history list in the desktop host |

The official Avalonia documentation identifies TableView as a read-only data-display control
available since Avalonia 12.1 and included in the core controls package. The exact candidate
package publishes an MIT licence. The older `Avalonia.Controls.DataGrid` package is deprecated
for read-only tables. These facts establish candidate suitability and licensing only; they are
not an AOT result and do not make the control safe to adopt.

The consuming boundary must preserve the MIT copyright and licence notice when the package is
redistributed. MIT permits copying, modifying, and redistributing the code subject to its
notice condition; keeping Avalonia's implementation in its package is an ArcForges design
choice, not a restriction imposed by MIT. Any combined-work obligations must be assessed for
the actual shell distribution. No Avalonia package reference, copied source, or runtime usage
is added to `DesktopPlatform` by this record.

| Evidence | Value |
|---|---|
| Real Native AOT proof | Not recorded; required before admission |
| Admission state | Not admitted; PRF.09 must exercise this process against the real candidate |
| Current package ownership | None in `DesktopPlatform`; the candidate remains outside its dependency closure |

## Authoritative references

- [Avalonia TableView documentation](https://docs.avaloniaui.net/controls/data-display/structured-data/tableview)
- [Avalonia 12.1.3 package and licence](https://www.nuget.org/packages/Avalonia/12.1.3)
- [Avalonia DataGrid package status](https://www.nuget.org/packages/Avalonia.Controls.DataGrid)
