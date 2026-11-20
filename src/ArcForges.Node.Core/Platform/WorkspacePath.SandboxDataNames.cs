// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspacePath
{
    private const int SandboxDataNameEntryBudget = 10_000;
    private static readonly TimeSpan SandboxDataNameScanBudget = TimeSpan.FromSeconds(5);

    /// <summary>Observes exact portable spelling beneath this held root. Publication still needs its native guard.</summary>
    internal void CheckSandboxDataName(string path, bool allowMissingFinal)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var parts = Components(path);
        using var deadline = new CancellationTokenSource(SandboxDataNameScanBudget);
        int remaining = SandboxDataNameEntryBudget;
        int prefixLength = 0;
        try
        {
            foreach (string component in parts)
            {
                if (remaining == 0)
                {
                    throw new WorkspacePathException("directory_enumeration_limit");
                }

                var names = ReadSandboxDataNames(path[..prefixLength], remaining, deadline.Token);
                if (names.Truncated)
                {
                    throw new WorkspacePathException("directory_enumeration_limit");
                }

                remaining -= names.Names.Count;
                if (prefixLength != 0)
                {
                    prefixLength++; // the separator before this component
                }

                prefixLength += component.Length;
                if (HasExactSandboxDataName(names, component))
                {
                    continue;
                }

                if (prefixLength != path.Length || !allowMissingFinal)
                {
                    throw new WorkspacePathException("path_not_found");
                }

                // An NTFS short name can resolve without appearing among the canonical enumerated names.
                if (OperatingSystem.IsWindows() && !InspectRemovalAbsent(path))
                {
                    throw new WorkspacePathException("path_case_collision");
                }
            }
        }
        catch (OperationCanceledException exception) when (deadline.IsCancellationRequested)
        {
            throw new WorkspacePathException("directory_enumeration_deadline", exception);
        }
    }

    private static bool HasExactSandboxDataName(WorkspaceDirectoryPage names, string component)
    {
        bool exact = false;
        foreach (string observed in names.Names)
        {
            if (!string.Equals(observed, component, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (exact || !string.Equals(observed, component, StringComparison.Ordinal))
            {
                throw new WorkspacePathException("path_case_collision");
            }

            exact = true;
        }

        return exact;
    }

    private WorkspaceDirectoryPage ReadSandboxDataNames(string parent, int maximum, CancellationToken cancellationToken)
    {
        int first = _directories.Count;
        try
        {
            return WorkspaceDirectoryEntries.Read(this, parent, maximum, cancellationToken);
        }
        finally
        {
            // Keep existing caller-held handles. Each successive scan can retire its own temporary traversal.
            for (int index = _directories.Count - 1; index >= first; index--)
            {
                _directories[index].Dispose();
            }

            _directories.RemoveRange(first, _directories.Count - first);
        }
    }
}
