// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json.Nodes;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using Grpc.Core;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.CommandLine;

internal static class TerminalOutput
{
    private const int MaximumChunkBytes = 65_536;
    private static readonly TimeSpan LiveSnapshotWindow = TimeSpan.FromSeconds(2);

    /// <summary>Relays one output stream and returns its authoritative terminal Run when received.</summary>
    internal static async Task<Run?> PumpAsync(Cli cli, V2CliSession session, Run run, StreamKind stream, ulong offset,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> write, bool follow, CancellationToken ct)
    {
        if (!V2Shapes.IsValid(run))
        {
            throw InvalidFrame("run_identity_invalid");
        }

        if (run.TerminalMode == TerminalMode.Interactive ? stream != StreamKind.Terminal
            : run.TerminalMode != TerminalMode.Pipes || stream is not (StreamKind.Stdout or StreamKind.Stderr))
        {
            throw new V2CommandException(V2Cli.Error(ErrorCategory.Validation, "invalid_argument", "run_output_stream_unavailable"), null);
        }

        var request = new RunServiceWatchOutputRequest
        {
            Meta = Cli.Meta(),
            RunId = run.RunId.Clone(),
            Epoch = run.Epoch,
            Offset = offset,
            Stream = stream,
        };
        using var snapshot = !follow && !IsTerminal(run) ? CancellationTokenSource.CreateLinkedTokenSource(ct) : null;
        snapshot?.CancelAfter(LiveSnapshotWindow);
        var receive = snapshot?.Token ?? ct;
        DateTime? deadline = cli.Timeout is { } timeout ? DateTime.UtcNow + timeout : null;
        using var call = session.Runs.WatchOutput(request, deadline: deadline, cancellationToken: receive);
        long revision = run.Revision.Value;
        while (await MoveNextAsync(call.ResponseStream, snapshot, ct).ConfigureAwait(false))
        {
            var frame = call.ResponseStream.Current;
            if (!Equals(frame.Meta?.CorrelationId, request.Meta.CorrelationId))
            {
                throw InvalidFrame("run_output_correlation_invalid");
            }

            if (frame.Error is { } error)
            {
                throw new V2CommandException(error, null);
            }

            if (frame.Meta?.ResultRev is not { } observed || observed.Value < revision)
            {
                throw InvalidFrame("run_output_revision_invalid");
            }

            revision = observed.Value;
            if (frame.Chunk is { } chunk)
            {
                ValidateChunk(chunk, run.Epoch, stream, offset);
                if (!cli.Output.Json)
                {
                    await write(chunk.Data.Memory, ct).ConfigureAwait(false);
                }

                await PrintJsonAsync(cli, frame, stream, ct).ConfigureAwait(false);
                offset = chunk.NextOffset;
            }
            else if (frame.Gap is { } gap)
            {
                var epochChanged = await ReportGapAsync(cli, gap, run.Epoch, stream, offset, ct).ConfigureAwait(false);
                await PrintJsonAsync(cli, frame, stream, ct).ConfigureAwait(false);
                if (epochChanged)
                {
                    throw InvalidFrame("run_output_epoch_changed");
                }

                offset = gap.EarliestOffset;
            }
            else if (frame.Run is { } final)
            {
                ValidateFinal(run, final, revision);
                await PrintJsonAsync(cli, frame, stream, ct).ConfigureAwait(false);
                return final;
            }
            else
            {
                throw InvalidFrame("run_output_frame_missing");
            }
        }

        ct.ThrowIfCancellationRequested();
        if (SnapshotElapsed(snapshot, ct))
        {
            string message = string.Create(CultureInfo.InvariantCulture,
                $"arcforges: live {StreamName(stream)} output has no verified tail after the bounded read. Resume at offset {offset}.");
            await cli.Output.Error.WriteLineAsync(message.AsMemory(), ct).ConfigureAwait(false);
            return null;
        }

        throw new V2CommandException(V2Cli.Error(ErrorCategory.State, "node_unavailable", "run_output_ended_before_final"), null);
    }

    private static async Task<bool> MoveNextAsync(IAsyncStreamReader<RunServiceWatchOutputFrame> frames,
        CancellationTokenSource? snapshot, CancellationToken caller)
    {
        try
        {
            return await frames.MoveNext(snapshot?.Token ?? caller).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (SnapshotElapsed(snapshot, caller))
        {
            return false;
        }
        catch (RpcException failure) when (failure.StatusCode == StatusCode.Cancelled && SnapshotElapsed(snapshot, caller))
        {
            return false;
        }
    }

    private static void ValidateChunk(OutputChunk chunk, string epoch, StreamKind stream, ulong offset)
    {
        if (!chunk.HasEpoch || chunk.Epoch != epoch || !chunk.HasStream || chunk.Stream != stream
            || !chunk.HasOffset || chunk.Offset != offset || !chunk.HasNextOffset
            || !chunk.HasData || chunk.Data.Length is < 1 or > MaximumChunkBytes
            || ulong.MaxValue - offset < (ulong)chunk.Data.Length || chunk.NextOffset != offset + (ulong)chunk.Data.Length)
        {
            throw InvalidFrame("run_output_chunk_invalid");
        }
    }

    private static async ValueTask<bool> ReportGapAsync(Cli cli, OutputGap gap, string epoch, StreamKind stream, ulong offset,
        CancellationToken ct)
    {
        if (!gap.HasEpoch || !gap.HasRequestedOffset || gap.RequestedOffset != offset || !gap.HasEarliestOffset)
        {
            throw InvalidFrame("run_output_gap_invalid");
        }

        if (gap.Reason == "epoch_changed" && gap.Epoch != epoch)
        {
            await cli.Output.Error.WriteLineAsync("arcforges: output GAP (epoch_changed). The stream lost its original Run epoch.".AsMemory(), ct)
                .ConfigureAwait(false);
            return true;
        }

        if (gap.Epoch != epoch || gap.EarliestOffset <= offset || gap.Reason is not ("retention" or "slow_consumer"))
        {
            throw InvalidFrame("run_output_gap_invalid");
        }

        string message = string.Create(CultureInfo.InvariantCulture,
            $"arcforges: output GAP ({StreamName(stream)}, {gap.Reason}). Requested offset {offset}. First retained offset {gap.EarliestOffset}.");
        await cli.Output.Error.WriteLineAsync(message.AsMemory(), ct).ConfigureAwait(false);
        return false;
    }

    private static void ValidateFinal(Run original, Run final, long revision)
    {
        if (!V2Shapes.IsValid(final) || !IsTerminal(final) || final.Revision.Value != revision
            || !final.RunId.Equals(original.RunId) || !final.SandboxId.Equals(original.SandboxId)
            || !final.SandboxRevision.Equals(original.SandboxRevision) || final.Epoch != original.Epoch
            || final.LaunchSha256 != original.LaunchSha256 || final.TerminalMode != original.TerminalMode
            || final.ProfileId != original.ProfileId || final.ProfileVersion != original.ProfileVersion
            || !Equals(final.CreatedAt, original.CreatedAt)
            || (original.StartedAt is not null && !original.StartedAt.Equals(final.StartedAt))
            || (IsTerminal(original) && (final.State != original.State || !final.Exit.Equals(original.Exit))))
        {
            throw InvalidFrame("run_output_final_invalid");
        }
    }

    private static async ValueTask PrintJsonAsync(Cli cli, RunServiceWatchOutputFrame frame, StreamKind stream, CancellationToken ct)
    {
        if (cli.Output.Json)
        {
            var line = (JsonObject)CliOutput.ToJsonNode(frame);
            line["stream"] = StreamName(stream);
            cli.Output.Essential(line.ToJsonString());
            await cli.Output.Out.FlushAsync(ct).ConfigureAwait(false);
        }
    }

    private static bool IsTerminal(Run run) => run is { State: RunState.Exited or RunState.Failed, Exit.GroupEmptyVerified: true };

    private static bool SnapshotElapsed(CancellationTokenSource? snapshot, CancellationToken caller) =>
        !caller.IsCancellationRequested && snapshot?.IsCancellationRequested == true;

    private static string StreamName(StreamKind stream) => stream.ToString().ToLowerInvariant();

    private static V2CommandException InvalidFrame(string reason) =>
        new(V2Cli.Error(ErrorCategory.Internal, "invalid_output_response", reason), null);
}
