// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// One no-follow observation of an absolute Windows reference. Missing final entries are distinguished from
/// inaccessible or unobservable parents; neither the observation nor its handles confer cleanup authority.
/// </summary>
internal sealed record WindowsReferenceObservation(
    IReadOnlyList<WorkspaceObjectIdentity> Ancestors,
    WorkspaceEntryMetadata? Final,
    bool MissingFinal)
{
    // A reference comparison uses the Windows volume/file ID, including ordinary multi-link files.
    // Ownership encoding and removal capture retain their separate, stricter link-count requirements.
    internal bool OverlapsDirectory(WorkspaceObjectIdentity target, IReadOnlyList<WorkspaceObjectIdentity> targetAncestors)
    {
        static bool SameNativeObject(WorkspaceObjectIdentity left, WorkspaceObjectIdentity right) =>
            left.Volume == right.Volume && left.Low == right.Low && left.High == right.High;
        return Final is { } final &&
            (SameNativeObject(final.Identity, target) || final.Kind == WorkspaceEntryType.Directory &&
             targetAncestors.Any(item => SameNativeObject(item, final.Identity))) ||
            Ancestors.Any(item => SameNativeObject(item, target));
    }
}

internal sealed partial class WorkspacePath
{
    internal static WindowsReferenceObservation ObserveWindowsReference(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new WorkspacePathException("path_enforcement_unavailable");
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path)) throw new WorkspacePathException("root_not_absolute");
        var selected = Path.TrimEndingDirectorySeparator(path);
        var parentPath = Path.GetDirectoryName(selected);
        if (parentPath is null)
        {
            using var root = OpenRoot(selected);
            return new WindowsReferenceObservation(root.WindowsRootAncestors(),
                root.InspectEntry("", allowRoot: true), MissingFinal: false);
        }

        var name = Path.GetFileName(selected);
        _ = Components(name);
        using var parent = OpenRoot(parentPath);
        var ancestors = parent.WindowsRootAncestors();
        try
        {
            return new WindowsReferenceObservation(ancestors, parent.InspectEntry(name), MissingFinal: false);
        }
        catch (WorkspacePathException error) when (error.Reason is "native_2" or "native_3")
        {
            // Only the final name is missing: the no-follow parent and its ancestors were opened above.
            return new WindowsReferenceObservation(ancestors, Final: null, MissingFinal: true);
        }
    }
}
