// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using ArcForges.RunSupervisor.Protocol;
using Google.Protobuf;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    internal async IAsyncEnumerable<RunServiceWatchOutputFrame> WatchRunOutputAsync(RunServiceWatchOutputRequest request,
        Action<string, StreamKind>? audit,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        string runId = ToHex(request.RunId);
        string? epoch = request.HasEpoch ? request.Epoch : null;
        ulong offset = request.Offset;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var poll = PollRunOutput(request, runId, epoch, offset, ref audit);
            if (poll.Frame is { } frame)
            {
                yield return frame;
                if (poll.Cursor is not { } cursor)
                {
                    yield break;
                }

                epoch = cursor.Epoch;
                offset = cursor.Offset;
            }
            else
            {
                await Task.Delay(TimeSpan.FromMilliseconds(125), _clock, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private OutputPoll PollRunOutput(RunServiceWatchOutputRequest request, string runId, string? epoch, ulong offset,
        ref Action<string, StreamKind>? audit)
    {
        try
        {
            var row = _store.Read(reader => RunRecords.Get(reader, OwnerId, runId));
            if (row is null)
            {
                return Failure(Error(request.Meta, ErrorCategory.State, "not_found", "run_not_visible"));
            }

            var mode = (RunTerminalMode)ReadRunSnapshot(row).TerminalMode;
            var stream = request.HasStream ? (RunOutputStream)request.Stream
                : mode == RunTerminalMode.Interactive ? RunOutputStream.Terminal : RunOutputStream.Stdout;
            if (mode == RunTerminalMode.Interactive ? stream != RunOutputStream.Terminal
                : stream is not (RunOutputStream.Stdout or RunOutputStream.Stderr))
            {
                return Failure(Error(request.Meta, ErrorCategory.Validation, "invalid_argument", "run_output_stream_unavailable"));
            }

            if (audit is { } record)
            {
                audit = null;
                record(runId, (StreamKind)stream);
            }

            var meta = Response(request.Meta, row.Revision);
            var result = ReadProtectedRunOutput(new(runId, row.Epoch, row.LaunchSha256, mode), stream, epoch, offset);
            bool finished = row.State is StoredRunState.Exited or StoredRunState.Failed;
            switch (result.Status)
            {
                case RunOutputReadStatus.Chunk when result.Data is { Length: > 0 } data:
                    return new(new()
                    {
                        Meta = meta,
                        Chunk = new()
                        {
                            Epoch = result.Epoch,
                            Offset = result.Offset,
                            NextOffset = result.NextOffset,
                            Stream = (StreamKind)stream,
                            Data = ByteString.CopyFrom(data),
                        },
                    }, (result.Epoch, result.NextOffset));
                case RunOutputReadStatus.Gap when result.GapReason is { } reason:
                    return new(Gap(result.Epoch, result.EarliestOffset, reason), (result.Epoch, result.EarliestOffset));
                case RunOutputReadStatus.InvalidCursor:
                    return Failure(Error(request.Meta, ErrorCategory.Validation, "invalid_cursor", "run_output_offset_unavailable"));
                case RunOutputReadStatus.StreamUnavailable:
                    return Failure(Error(request.Meta, ErrorCategory.Validation, "invalid_argument", "run_output_stream_unavailable"));
                case RunOutputReadStatus.Complete when finished:
                    return new(new() { Meta = meta, Run = RunView(row) });
                case RunOutputReadStatus.Tail or RunOutputReadStatus.Complete when !finished:
                case RunOutputReadStatus.Unavailable when row.State == StoredRunState.Starting:
                    return default;
                case RunOutputReadStatus.Unavailable when finished && row.PayloadStarted == StoredPayloadStart.NotStarted:
                    if (epoch is not null && epoch != row.Epoch)
                    {
                        return new(Gap(row.Epoch, 0, "epoch_changed"), (row.Epoch, 0));
                    }

                    return offset == 0 ? new(new() { Meta = meta, Run = RunView(row) })
                        : Failure(Error(request.Meta, ErrorCategory.Validation, "invalid_cursor", "run_output_offset_unavailable"));
                default:
                    return Failure(Error(request.Meta, ErrorCategory.State, "not_found", "run_output_continuity_unavailable"));
            }

            RunServiceWatchOutputFrame Gap(string currentEpoch, ulong earliestOffset, string reason) => new()
            {
                Meta = meta,
                Gap = new() { Epoch = currentEpoch, RequestedOffset = offset, EarliestOffset = earliestOffset, Reason = reason },
            };
        }
        catch (Exception failure) when (IsStorageFailure(failure))
        {
            return Failure(StorageFailure(request.Meta));
        }

        OutputPoll Failure(ArcError error) => new(new() { Meta = Response(request.Meta), Error = error });
    }

    private RunOutputReadResult ReadProtectedRunOutput(RunOutputIdentity identity, RunOutputStream stream, string? epoch, ulong offset)
    {
        _roots.ValidateControlPaths();
        using var data = WorkspacePath.OpenRoot(_dataRoot);
        WorkspacePath.CheckSandboxDirectory(data.RootHandle, configuredRoot: true);
        using var control = data.OpenSandboxDirectory("control", configuredRoot: true);
        try
        {
            using var output = control.OpenSandboxDirectory("run-" + identity.RunId);
            return RunOutputSpool.Read(identity, name => OpenRunOutputLeaf(output, name), stream, epoch, offset);
        }
        catch (WorkspacePathException error) when (error.Reason is "native_2" or "native_3")
        {
            return new(RunOutputReadStatus.Unavailable, identity.Epoch, offset, 0, 0, null, null);
        }
    }

    private static SafeFileHandle OpenRunOutputLeaf(WorkspacePath output, string name)
    {
        if (WorkspacePath.Components(name).Length != 1)
        {
            throw new InvalidDataException("run_output_leaf_invalid");
        }

        return OperatingSystem.IsWindows() ? OpenWindowsRunOutputLeaf(output, name) : output.OpenRead(name);
    }

    [SupportedOSPlatform("windows")]
    private static SafeFileHandle OpenWindowsRunOutputLeaf(WorkspacePath directory, string name)
    {
        const uint genericRead = 0x80000000;
        const uint openExisting = 3;
        const uint openReparsePoint = 0x00200000;
        var path = Path.Combine(directory.RootPath, name);
        // Indices are atomically replaced and sealed prefixes may append while a watcher reads.
        var file = OpenSharedRunOutput(path, genericRead, FileShare.ReadWrite | FileShare.Delete, 0, openExisting, openReparsePoint, 0);
        try
        {
            if (file.IsInvalid)
            {
                throw new WorkspacePathException("native_" + Marshal.GetLastPInvokeError().ToString(CultureInfo.InvariantCulture));
            }

            var observed = WorkspacePath.Identity(file);
            if (!observed.IsFile || observed.Links != 1 || observed.Volume != directory.RootIdentity.Volume
                || !path.Equals(WorkspacePath.CanonicalMxcGrantPath(file, path), StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("run_output_leaf_identity_changed");
            }

            return file;
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle OpenSharedRunOutput(string name, uint access, FileShare share, nint security,
        uint disposition, uint flags, nint template);

    private readonly record struct OutputPoll(RunServiceWatchOutputFrame? Frame, (string Epoch, ulong Offset)? Cursor = null);
}
