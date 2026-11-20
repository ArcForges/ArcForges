// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.CommandLine;
using System.CommandLine.Parsing;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using Google.Protobuf;
using Grpc.Core;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.CommandLine;

internal static class DataCommands
{
    private const int ChunkBytes = 1_048_576;
    private const string Import = "import";
    private const string Export = "export";
    private const string CommitMethod = "DataService.CommitImport";
    private static readonly TimeSpan s_deadline = TimeSpan.FromSeconds(30);

    internal static void AddTo(Command sandbox, Func<ParseResult, Cli> factory)
    {
        sandbox.Subcommands.Add(Usage(factory));
        sandbox.Subcommands.Add(Files(factory));
        sandbox.Subcommands.Add(ImportFile(factory));
        sandbox.Subcommands.Add(ExportFile(factory));
        sandbox.Subcommands.Add(Transfers(factory));
    }

    private static Command Usage(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("sandbox-id") { Description = "Sandbox ID" };
        var command = new Command("usage", "Show the latest measurement of owned Sandbox data") { id };
        V2Cli.Set(command, factory, async (cli, result, ct) =>
        {
            var request = new DataServiceGetUsageRequest { Meta = Cli.Meta(), SandboxId = ReadSandbox(result, id) };
            await using var session = await V2CliSession.OpenAsync(cli, ct).ConfigureAwait(false);
            var reply = await QueryAsync(() => session.Data.GetUsageAsync(request, deadline: cli.Deadline(s_deadline),
                cancellationToken: ct)).ConfigureAwait(false);
            return V2Cli.Print(cli, V2Cli.Require(reply.Value, reply.Error));
        });
        return command;
    }

    private static Command Files(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("sandbox-id") { Description = "Sandbox ID" };
        var directory = new Argument<string?>("relative-dir") { Arity = ArgumentArity.ZeroOrOne, Description = "Owned relative directory" };
        var limit = new Option<uint?>("--limit") { Description = "Page size between 1 and 200" };
        var cursor = new Option<string?>("--cursor") { Description = "Opaque continuation from the preceding page" };
        var command = new Command("files", "List owned data entries in a Sandbox") { id, directory, limit, cursor };
        V2Cli.Set(command, factory, async (cli, result, ct) =>
        {
            var request = new DataServiceListEntriesRequest { Meta = Cli.Meta(), SandboxId = ReadSandbox(result, id) };
            if (result.GetValue(directory) is { } path)
            {
                request.RelativeDirectory = OwnedPath(path);
            }

            if (result.GetValue(limit) is { } count)
            {
                request.Limit = SandboxCommands.PageSize(count);
            }

            if (result.GetValue(cursor) is { } next)
            {
                request.Cursor = next;
            }

            await using var session = await V2CliSession.OpenAsync(cli, ct).ConfigureAwait(false);
            var reply = await QueryAsync(() => session.Data.ListEntriesAsync(request, deadline: cli.Deadline(s_deadline),
                cancellationToken: ct)).ConfigureAwait(false);
            return V2Cli.Print(cli, V2Cli.Require(reply.Value, reply.Error));
        });
        return command;
    }

    private static Command ImportFile(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("sandbox-id") { Description = "Sandbox ID" };
        var source = new Argument<string>("source") { Description = "Local regular file to read" };
        var target = new Option<string>("--to") { Required = true, Description = "Owned relative path in the Sandbox" };
        var version = new Option<string?>("--expected-file-version") { Description = "Target version from sandbox files" };
        var overwrite = new Option<bool>("--overwrite") { Description = "Replace the exact observed Sandbox file version" };
        var options = new TransferOptions();
        var command = new Command(Import, "Import one local file into an owned Sandbox path") { id, source, target, overwrite, version };
        options.AddTo(command);
        V2Cli.Set(command, factory, (cli, result, ct) => WithProgressAsync(cli, async progress =>
        {
            var sandbox = ReadSandbox(result, id);
            string path = OwnedPath(result.GetValue(target)!);
            var selection = options.Read(result);
            string? expectedVersion = result.GetValue(version);
            bool replace = result.GetValue(overwrite);
            if (replace != (expectedVersion is { Length: > 0 }) || selection.Resume is not null && (replace || expectedVersion is not null))
            {
                throw new UsageException("A new overwrite requires --overwrite and --expected-file-version together. A resumed import uses its original version.");
            }

            using var local = LocalTransferFile.OpenSource(result.GetValue(source)!);
            string digest = Convert.ToHexStringLower(await SHA256.HashDataAsync(local.Body, ct).ConfigureAwait(false));
            local.VerifySource();
            ulong length = (ulong)local.Length;
            await using var session = await V2CliSession.OpenAsync(cli, ct).ConfigureAwait(false);
            using var pin = session.PinConnection();
            var activeEpoch = await EpochAsync(cli, session, selection.OwnerEpoch, ct).ConfigureAwait(false);
            progress.Epoch = activeEpoch;
            TransferObservation inspected;
            if (selection.Resume is { } retained)
            {
                await VerifyResumeEpochAsync(cli, session, activeEpoch, ct).ConfigureAwait(false);
                inspected = await InspectTransferAsync(cli, session, retained, ct).ConfigureAwait(false);
            }
            else
            {
                var identity = await BeginIdentityAsync(cli, session, selection, sandbox, activeEpoch, ct).ConfigureAwait(false);
                var request = new DataServiceBeginImportRequest
                {
                    SandboxId = sandbox,
                    RelativePath = path,
                    ByteLength = length,
                    Sha256 = digest,
                    OwnerEpoch = activeEpoch,
                    Meta = identity.Meta,
                };
                if (replace)
                {
                    request.Overwrite = true;
                    request.ExpectedFileVersion = expectedVersion;
                }

                progress.Begin = identity;
                var response = await SendAsync(cli, "DataService.BeginImport", identity, progress,
                    () => session.Data.BeginImportAsync(request, deadline: cli.Deadline(s_deadline), cancellationToken: ct),
                    ct).ConfigureAwait(false);
                var accepted = RequireTransfer(V2Cli.Require(response.Value, response.Error, identity).Transfer, identity);
                RequireBinding(accepted, sandbox, path, Import, identity);
                progress.Set(accepted, response.Meta, identity);
                inspected = await InspectTransferAsync(cli, session, accepted.TransferId, ct).ConfigureAwait(false);
                MatchTransfer(accepted, inspected.Value, null);
            }

            var transfer = inspected.Value;
            RequireBinding(transfer, sandbox, path, Import, null);
            progress.Set(inspected);
            if (!transfer.HasByteLength || transfer.ByteLength != length || !transfer.HasSha256 || transfer.Sha256 != digest
                || !transfer.HasVerifiedOffset || transfer.VerifiedOffset > length)
            {
                throw Refusal("identity_changed", "source_does_not_match_the_import_manifest", ErrorCategory.Conflict);
            }

            if (transfer.State == TransferState.Complete)
            {
                return await CompleteAsync(cli, session, progress, activeEpoch, ct).ConfigureAwait(false);
            }

            RequireOpen(transfer);
            await WriteImportAsync(cli, session, local, progress, activeEpoch, ct).ConfigureAwait(false);
            local.VerifySource();
            await CommitImportAsync(cli, session, progress, activeEpoch, ct).ConfigureAwait(false);
            return await CompleteAsync(cli, session, progress, activeEpoch, ct).ConfigureAwait(false);
        }));
        return command;
    }

    private static Command ExportFile(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("sandbox-id") { Description = "Sandbox ID" };
        var pathOption = new Argument<string>("relative-path") { Description = "Owned relative file to snapshot" };
        var target = new Option<string>("--to") { Required = true, Description = "New local output file" };
        var version = new Option<string?>("--expected-file-version") { Description = "Source version from sandbox files" };
        var options = new TransferOptions();
        var command = new Command(Export, "Export one verified file snapshot to a new local destination") { id, pathOption, target, version };
        options.AddTo(command);
        V2Cli.Set(command, factory, (cli, result, ct) => WithProgressAsync(cli, async progress =>
        {
            var sandbox = ReadSandbox(result, id);
            string path = OwnedPath(result.GetValue(pathOption)!);
            var selection = options.Read(result);
            var expectedVersion = result.GetValue(version);
            if (selection.Resume is not null && expectedVersion is not null)
            {
                throw new UsageException("A resumed export uses the version of its existing snapshot.");
            }

            using var destination = LocalTransferFile.Destination.Create(result.GetValue(target)!);
            progress.Destination = destination;
            await using var session = await V2CliSession.OpenAsync(cli, ct).ConfigureAwait(false);
            using var pin = session.PinConnection();
            var activeEpoch = await EpochAsync(cli, session, selection.OwnerEpoch, ct).ConfigureAwait(false);
            progress.Epoch = activeEpoch;
            TransferObservation inspected;
            if (selection.Resume is { } retained)
            {
                await VerifyResumeEpochAsync(cli, session, activeEpoch, ct).ConfigureAwait(false);
                inspected = await InspectTransferAsync(cli, session, retained, ct).ConfigureAwait(false);
            }
            else
            {
                var identity = await BeginIdentityAsync(cli, session, selection, sandbox, activeEpoch, ct).ConfigureAwait(false);
                var request = new DataServiceBeginExportRequest { Meta = identity.Meta, OwnerEpoch = activeEpoch, SandboxId = sandbox, RelativePath = path };
                if (expectedVersion is not null)
                {
                    request.ExpectedFileVersion = expectedVersion;
                }

                progress.Begin = identity;
                var response = await SendAsync(cli, "DataService.BeginExport", identity, progress,
                    () => session.Data.BeginExportAsync(request, deadline: cli.Deadline(s_deadline), cancellationToken: ct),
                    ct).ConfigureAwait(false);
                var accepted = RequireTransfer(V2Cli.Require(response.Value, response.Error, identity).Transfer, identity);
                RequireBinding(accepted, sandbox, path, Export, identity);
                progress.Set(accepted, response.Meta, identity);
                inspected = await InspectTransferAsync(cli, session, accepted.TransferId, ct).ConfigureAwait(false);
                MatchTransfer(accepted, inspected.Value, null);
            }

            RequireBinding(inspected.Value, sandbox, path, Export, null);
            progress.Set(inspected);
            await WaitForCompletionAsync(cli, session, progress, ct).ConfigureAwait(false);
            if (progress.Current!.ClosedAt is not null)
            {
                throw Refusal("not_found", "export_snapshot_already_closed");
            }

            await DownloadAsync(cli, session, progress.Current, destination.Body, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            destination.Publish();
            destination.Dispose();
            if (destination.CleanupFailure is not null)
            {
                throw Unknown("local_export_handle_close_unconfirmed", null);
            }

            return await CompleteAsync(cli, session, progress, activeEpoch, ct).ConfigureAwait(false);
        }));
        return command;
    }

    private static Command Transfers(Func<ParseResult, Cli> factory)
    {
        var inspectId = new Argument<string>("transfer-id") { Description = "Transfer ID" };
        var inspect = new Command("inspect", "Inspect transfer progress, verified size/digest and closure") { inspectId };
        V2Cli.Set(inspect, factory, async (cli, result, ct) =>
        {
            var id = V2Cli.ReadId(result.GetValue(inspectId), "transfer ID");
            await using var session = await V2CliSession.OpenAsync(cli, ct).ConfigureAwait(false);
            var inspected = await InspectTransferAsync(cli, session, id, ct).ConfigureAwait(false);
            return V2Cli.Print(cli, new JsonObject
            {
                ["transfer"] = CliOutput.ToJsonNode(inspected.Value),
                ["revision"] = inspected.Revision.Value,
            });
        });

        var closeId = new Argument<string>("transfer-id") { Description = "Transfer ID" };
        var epoch = new Option<string?>("--owner-epoch") { Description = "Original owner epoch from the transfer" };
        var commandId = new Option<string?>("--command-id") { Description = "Exact original Close command ID for replay" };
        var revision = new Option<long?>("--expected-revision") { Description = "Expected transfer revision" };
        var close = new Command("close", "Release or safely cancel a retained transfer") { closeId, epoch, commandId, revision };
        V2Cli.Set(close, factory, (cli, result, ct) => WithProgressAsync(cli, async progress =>
        {
            var id = V2Cli.ReadId(result.GetValue(closeId), "transfer ID");
            var selectedEpoch = ReadOptionalId(result.GetValue(epoch), "--owner-epoch");
            var selectedCommand = ReadOptionalId(result.GetValue(commandId), "--command-id");
            var selectedRevision = result.GetValue(revision);
            if (selectedCommand is not null && (selectedEpoch is null || selectedRevision is null))
            {
                throw new UsageException("Resend the original --owner-epoch and --expected-revision with --command-id.");
            }

            await using var session = await V2CliSession.OpenAsync(cli, ct).ConfigureAwait(false);
            using var pin = session.PinConnection();
            var activeEpoch = await EpochAsync(cli, session, selectedEpoch, ct).ConfigureAwait(false);
            progress.Epoch = activeEpoch;
            var identity = NewIdentity(activeEpoch, selectedCommand);
            if (selectedRevision is long provided)
            {
                identity.Meta.ExpectedRev = SandboxCommands.PositiveRevision(provided);
            }
            else
            {
                progress.Set(await InspectTransferAsync(cli, session, id, ct).ConfigureAwait(false));
                if (progress.Current!.ClosedAt is not null)
                {
                    return V2Cli.Print(cli, new DataServiceCloseTransferValue { Transfer = progress.Current });
                }

                identity.Meta.ExpectedRev = progress.Revision;
            }

            var transfer = await CloseAsync(cli, session, id, identity, progress, ct).ConfigureAwait(false);
            return V2Cli.Print(cli, new DataServiceCloseTransferValue { Transfer = transfer }, progress.Last);
        }));

        return new Command("transfer", "Inspect and close owned-data transfers") { inspect, close };
    }

    private static async Task WriteImportAsync(Cli cli, V2CliSession session, LocalTransferFile source, TransferProgress progress,
        Id epoch, CancellationToken ct)
    {
        var transfer = progress.Current!;
        ulong offset = transfer.VerifiedOffset;
        source.Body.Position = (long)offset;
        var buffer = ArrayPool<byte>.Shared.Rent(ChunkBytes);
        try
        {
            while (offset < transfer.ByteLength)
            {
                int count = (int)Math.Min((ulong)ChunkBytes, transfer.ByteLength - offset);
                await source.Body.ReadExactlyAsync(buffer.AsMemory(0, count), ct).ConfigureAwait(false);
                source.VerifySource();
                var identity = NewIdentity(epoch, expected: progress.Revision);
                var request = new DataServiceWriteImportRequest
                {
                    Meta = identity.Meta,
                    OwnerEpoch = epoch,
                    TransferId = transfer.TransferId,
                    Offset = offset,
                    Chunk = ByteString.CopyFrom(buffer.AsSpan(0, count)),
                };
                var reply = await SendAsync(cli, "DataService.WriteImport", identity, progress,
                    () => session.Data.WriteImportAsync(request, deadline: cli.Deadline(s_deadline), cancellationToken: ct),
                    ct).ConfigureAwait(false);
                var updated = RequireTransfer(V2Cli.Require(reply.Value, reply.Error, identity).Transfer, identity);
                MatchTransfer(transfer, updated, identity);
                ulong next = offset + (ulong)count;
                if (!updated.HasVerifiedOffset || updated.VerifiedOffset != next)
                {
                    throw Unknown("import_offset_unconfirmed", identity);
                }

                progress.Set(updated, reply.Meta, identity);
                RequireOpen(updated);
                offset = next;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static async Task CommitImportAsync(Cli cli, V2CliSession session, TransferProgress progress, Id epoch, CancellationToken ct)
    {
        var transfer = progress.Current!;
        var identity = NewIdentity(epoch, expected: progress.Revision);
        var request = new DataServiceCommitImportRequest { Meta = identity.Meta, OwnerEpoch = epoch, TransferId = transfer.TransferId };
        var reply = await SendAsync(cli, CommitMethod, identity, progress,
            () => session.Data.CommitImportAsync(request, deadline: cli.Deadline(s_deadline), cancellationToken: ct), ct).ConfigureAwait(false);
        var value = V2Cli.Require(reply.Value, reply.Error, identity);
        var commit = value.Operation;
        if (commit is null || !identity.CommandId.Equals(commit.CommandId) || !identity.OwnerEpoch.Equals(commit.OwnerEpoch)
            || !transfer.TransferId.Equals(commit.AggregateId) || commit.Method != CommitMethod)
        {
            throw Unknown("import_commit_receipt_unconfirmed", identity);
        }

        progress.Commit = commit;
        var current = RequireTransfer(value.Transfer, identity);
        MatchTransfer(transfer, current, identity);
        progress.Set(current, reply.Meta, identity);
        if (commit.State == OperationState.Unknown || commit.Effect == EffectCertainty.Unknown && commit.State != OperationState.Accepted)
        {
            throw Unknown("import_commit_outcome_unknown", identity);
        }

        await WaitForCompletionAsync(cli, session, progress, ct).ConfigureAwait(false);
        if (commit.State != OperationState.Succeeded || commit.Effect != EffectCertainty.Happened)
        {
            throw Unknown("import_commit_receipt_unconfirmed", identity);
        }
    }

    private static async Task DownloadAsync(Cli cli, V2CliSession session, Transfer transfer, Stream stage, CancellationToken ct)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        ulong offset = 0;
        do
        {
            var request = new DataServiceReadExportRequest
            {
                Meta = Cli.Meta(),
                TransferId = transfer.TransferId,
                Offset = offset,
                MaxBytes = ChunkBytes,
            };
            var reply = await QueryAsync(() => session.Data.ReadExportAsync(request, deadline: cli.Deadline(s_deadline),
                cancellationToken: ct)).ConfigureAwait(false);
            var chunk = V2Cli.Require(reply.Value, reply.Error).Chunk;
            if (!V2Shapes.IsValid(chunk) || !chunk.HasOffset || chunk.Offset != offset
                || (ulong)chunk.Data.Length > transfer.ByteLength - offset
                || chunk.Eof != (offset + (ulong)chunk.Data.Length == transfer.ByteLength)
                || !chunk.Eof && chunk.Data.Length == 0)
            {
                throw Refusal("identity_changed", "export_snapshot_range_unconfirmed", ErrorCategory.Conflict);
            }

            await stage.WriteAsync(chunk.Data.Memory, ct).ConfigureAwait(false);
            digest.AppendData(chunk.Data.Span);
            offset += (ulong)chunk.Data.Length;
            if (chunk.Eof)
            {
                break;
            }
        }
        while (offset < transfer.ByteLength);

        if (Convert.ToHexStringLower(digest.GetHashAndReset()) != transfer.Sha256)
        {
            throw Refusal("identity_changed", "export_snapshot_digest_mismatch", ErrorCategory.Conflict);
        }
    }

    private static async Task WaitForCompletionAsync(Cli cli, V2CliSession session, TransferProgress progress, CancellationToken ct)
    {
        var bound = cli.Timeout ?? s_deadline;
        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(ct);
        waiting.CancelAfter(bound);
        var original = progress.Current!;
        var current = original;
        while (current.State != TransferState.Complete)
        {
            RequireOpen(current);
            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(200), waiting.Token).ConfigureAwait(false);
                var inspected = await InspectTransferAsync(cli, session, current.TransferId, waiting.Token).ConfigureAwait(false);
                current = inspected.Value;
                MatchTransfer(original, current, null);
                progress.Set(inspected);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw Refusal("busy", "transfer_materialization_pending");
            }
            catch (RpcException failure) when (waiting.IsCancellationRequested && !ct.IsCancellationRequested
                && failure.StatusCode is StatusCode.Cancelled or StatusCode.DeadlineExceeded)
            {
                throw Refusal("busy", "transfer_materialization_pending");
            }
        }
    }

    private static async Task<int> CompleteAsync(Cli cli, V2CliSession session, TransferProgress progress, Id epoch, CancellationToken ct)
    {
        var transfer = progress.Current!;
        if (transfer.ClosedAt is null)
        {
            transfer = await CloseAsync(cli, session, transfer.TransferId, NewIdentity(epoch, expected: progress.Revision),
                progress, ct).ConfigureAwait(false);
        }

        var output = new JsonObject { ["transfer"] = CliOutput.ToJsonNode(transfer) };
        if (progress.Last is null)
        {
            output["ownerEpoch"] = IdText.Format(epoch);
        }
        if (progress.Commit is { } commit)
        {
            output["operation"] = CliOutput.ToJsonNode(commit);
        }

        if (progress.Begin is { } begin)
        {
            output["beginCommandId"] = IdText.Format(begin.CommandId);
        }

        if (progress.Destination?.PublicationConfirmed == true)
        {
            output["localFilePublished"] = true;
        }

        return V2Cli.Print(cli, output, progress.Last);
    }

    private static async Task<Transfer> CloseAsync(Cli cli, V2CliSession session, Id id, V2CommandIdentity identity,
        TransferProgress progress, CancellationToken ct)
    {
        var request = new DataServiceCloseTransferRequest { Meta = identity.Meta, OwnerEpoch = identity.OwnerEpoch, TransferId = id };
        var reply = await SendAsync(cli, "DataService.CloseTransfer", identity, progress,
            () => session.Data.CloseTransferAsync(request, deadline: cli.Deadline(s_deadline), cancellationToken: ct), ct).ConfigureAwait(false);
        var closed = RequireTransfer(V2Cli.Require(reply.Value, reply.Error, identity).Transfer, identity);
        if (!id.Equals(closed.TransferId))
        {
            throw Unknown("transfer_close_identity_unconfirmed", identity);
        }

        if (progress.Current is { } original)
        {
            MatchTransfer(original, closed, identity);
        }

        progress.Set(closed, reply.Meta, identity);
        if (closed.ClosedAt is null || closed.State is not (TransferState.Complete or TransferState.Failed))
        {
            throw Unknown("transfer_close_unconfirmed", identity);
        }

        return closed;
    }

    private static async Task<TransferObservation> InspectTransferAsync(Cli cli, V2CliSession session, Id id, CancellationToken ct)
    {
        var request = new DataServiceInspectTransferRequest { Meta = Cli.Meta(), TransferId = id };
        var response = await QueryAsync(() => session.Data.InspectTransferAsync(request, deadline: cli.Deadline(s_deadline),
            cancellationToken: ct)).ConfigureAwait(false);
        var transfer = RequireTransfer(V2Cli.Require(response.Value, response.Error).Transfer, null);
        if (!id.Equals(transfer.TransferId))
        {
            throw Refusal("identity_changed", "transfer_identity_changed", ErrorCategory.Conflict);
        }

        return new(transfer, ResultRevision(response.Meta, null));
    }

    private static async Task<V2CommandIdentity> BeginIdentityAsync(Cli cli, V2CliSession session, TransferSelection selection,
        Id sandbox, Id epoch, CancellationToken ct)
    {
        var identity = NewIdentity(epoch, selection.CommandId);
        identity.Meta.ExpectedRev = selection.ExpectedRevision is long revision
            ? SandboxCommands.PositiveRevision(revision)
            : (await SandboxCommands.InspectAsync(session, sandbox, cli.Deadline(s_deadline), ct).ConfigureAwait(false)).Revision;
        return identity;
    }

    private static async Task<Id> EpochAsync(Cli cli, V2CliSession session, Id? original, CancellationToken ct)
    {
        if (original is not null)
        {
            return original;
        }

        var handshake = await session.HandshakeAsync(cli.Deadline(s_deadline), ct).ConfigureAwait(false);
        return V2Cli.Require(V2Cli.Require(handshake.Value, handshake.Error).OwnerEpoch, null);
    }

    private static async Task VerifyResumeEpochAsync(Cli cli, V2CliSession session, Id original, CancellationToken ct)
    {
        var current = await EpochAsync(cli, session, original: null, ct).ConfigureAwait(false);
        if (!original.Equals(current))
        {
            throw Refusal("owner_epoch_retired", "the_original_transfer_epoch_is_no_longer_active", ErrorCategory.Conflict);
        }
    }

    private static V2CommandIdentity NewIdentity(Id epoch, Id? command = null, Revision? expected = null)
    {
        command ??= CommandIds.New();
        var meta = Cli.Meta();
        meta.CommandId = command;
        meta.ExpectedRev = expected;
        return new(epoch, command, meta);
    }

    private static async Task<T> QueryAsync<T>(Func<AsyncUnaryCall<T>> call)
    {
        using var response = call();
        return await response.ResponseAsync.ConfigureAwait(false);
    }

    private static Task<T> SendAsync<T>(Cli cli, string method, V2CommandIdentity identity, TransferProgress progress,
        Func<AsyncUnaryCall<T>> call, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        progress.Last = identity;
        return V2Cli.SendAsync(cli, method, identity, call);
    }

    private static Transfer RequireTransfer(Transfer? value, V2CommandIdentity? identity)
    {
        if (!V2Shapes.IsValid(value))
        {
            throw Unknown("transfer_outcome_unconfirmed", identity);
        }

        return value;
    }

    private static Revision ResultRevision(ResponseMeta? meta, V2CommandIdentity? identity) =>
        meta?.ResultRev is { Value: > 0 } revision ? revision : throw Unknown("transfer_revision_unconfirmed", identity);

    private static void RequireBinding(Transfer value, Id sandbox, string path, string direction, V2CommandIdentity? identity)
    {
        if (!sandbox.Equals(value.SandboxId) || value.RelativePath != path || value.Direction != direction)
        {
            throw identity is null ? Refusal("identity_changed", "transfer_does_not_match_the_requested_file", ErrorCategory.Conflict)
                : Unknown("transfer_identity_unconfirmed", identity);
        }
    }

    private static void MatchTransfer(Transfer previous, Transfer current, V2CommandIdentity? identity)
    {
        RequireBinding(current, previous.SandboxId, previous.RelativePath, previous.Direction, identity);
        if (!previous.TransferId.Equals(current.TransferId) || !previous.ExpiresAt.Equals(current.ExpiresAt)
            || previous.HasByteLength && (!current.HasByteLength || current.ByteLength != previous.ByteLength)
            || previous.HasSha256 && (!current.HasSha256 || current.Sha256 != previous.Sha256)
            || previous.HasVerifiedOffset && (!current.HasVerifiedOffset || current.VerifiedOffset < previous.VerifiedOffset))
        {
            throw Unknown("transfer_progress_unconfirmed", identity);
        }
    }

    private static void RequireOpen(Transfer transfer)
    {
        if (transfer.State == TransferState.RecoveryRequired)
        {
            throw Unknown("transfer_recovery_required", null);
        }

        if (transfer.ClosedAt is not null || transfer.State is not (TransferState.Open or TransferState.Streaming))
        {
            throw Refusal("not_found", "transfer_no_longer_open");
        }
    }

    private static V2CommandException Refusal(string code, string reason, ErrorCategory category = ErrorCategory.State) =>
        new(V2Cli.Error(category, code, reason), null);

    private static V2CommandException Unknown(string reason, V2CommandIdentity? identity)
    {
        if (identity is not null)
        {
            return new V2CommandException(V2Cli.UnknownEffect(reason, identity.Meta.CorrelationId), identity);
        }

        var error = V2Cli.Error(ErrorCategory.Execution, "outcome_unknown", reason);
        error.Effect = EffectCertainty.Unknown;
        return new V2CommandException(error, null);
    }

    private static async Task<int> WithProgressAsync(Cli cli, Func<TransferProgress, Task<int>> operation)
    {
        var progress = new TransferProgress();
        try
        {
            return await operation(progress).ConfigureAwait(false);
        }
        catch (V2CommandException failure)
        {
            return V2Cli.Fail(cli, failure.Error, failure.Identity ?? progress.Last, progress.Current, observations: progress.Observations());
        }
        catch (OperationCanceledException)
        {
            return V2Cli.Fail(cli, V2Cli.Error(ErrorCategory.State, "transfer_cancelled", "local_transfer_wait_cancelled"),
                progress.Last, progress.Current, observations: progress.Observations());
        }
        catch (RpcException failure)
        {
            return V2Cli.Fail(cli, V2Cli.Error(ErrorCategory.State, "node_unavailable", failure.StatusCode.ToString()),
                progress.Last, progress.Current, observations: progress.Observations());
        }
        catch (NodeUnavailableException failure) when (progress.Destination?.CleanupFailure is not null)
        {
            var error = failure.Error ?? (failure.Reason switch
            {
                NodeUnavailableReason.AccessDenied => V2Cli.Error(ErrorCategory.Authorization, "permission_denied", "local_node_access_denied"),
                NodeUnavailableReason.Busy => V2Cli.Error(ErrorCategory.Resource, "overloaded", "local_node_busy"),
                NodeUnavailableReason.Incompatible => V2Cli.Error(ErrorCategory.Execution, "unsupported_combination", "local_node_incompatible"),
                _ => V2Cli.Error(ErrorCategory.State, "node_unavailable", failure.Reason.ToString()),
            });
            return V2Cli.Fail(cli, error, progress.Last, progress.Current, observations: progress.Observations());
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException or ArgumentException)
        {
            var error = LocalError(failure, progress.Destination?.Published == true);
            if (progress.Destination?.Published == true)
            {
                progress.PublicationFailure = failure.InnerException is Win32Exception native
                    ? FormattableString.Invariant($"{failure.Message} (native error {native.NativeErrorCode})")
                    : failure.Message;
            }

            return V2Cli.Fail(cli, error, progress.Last, progress.Current, observations: progress.Observations());
        }
    }

    private static ArcError LocalError(Exception failure, bool published)
    {
        if (published)
        {
            var error = V2Cli.Error(ErrorCategory.Execution, "outcome_unknown", "local_publish_durability_unconfirmed");
            error.Effect = EffectCertainty.Unknown;
            return error;
        }

        if (failure.InnerException is Win32Exception native)
        {
            return native.NativeErrorCode switch
            {
                17 when OperatingSystem.IsLinux() => V2Cli.Error(ErrorCategory.Conflict, "identity_changed", "local_destination_exists"),
                80 or 183 when OperatingSystem.IsWindows() => V2Cli.Error(ErrorCategory.Conflict, "identity_changed", "local_destination_exists"),
                28 when OperatingSystem.IsLinux() => V2Cli.Error(ErrorCategory.Resource, "disk_space", "local_disk_space"),
                112 when OperatingSystem.IsWindows() => V2Cli.Error(ErrorCategory.Resource, "disk_space", "local_disk_space"),
                _ => V2Cli.Error(ErrorCategory.Validation, "invalid_argument", failure.Message),
            };
        }

        return V2Cli.Error(ErrorCategory.Validation, "invalid_argument", failure.Message);
    }

    private static Id ReadSandbox(ParseResult result, Argument<string> id) =>
        V2Cli.ReadId(result.GetValue(id), "Sandbox ID");

    private static Id? ReadOptionalId(string? value, string name) => value is null ? null : V2Cli.ReadId(value, name);

    private static string OwnedPath(string value) => OperatingSystem.IsWindows() ? value.Replace('\\', '/') : value;

    private sealed class TransferProgress
    {
        internal Transfer? Current { get; private set; }
        internal Revision? Revision { get; private set; }
        internal Id? Epoch { get; set; }
        internal V2CommandIdentity? Begin { get; set; }
        internal V2CommandIdentity? Last { get; set; }
        internal Operation? Commit { get; set; }
        internal LocalTransferFile.Destination? Destination { get; set; }
        internal string? PublicationFailure { get; set; }

        internal void Set(TransferObservation observation)
        {
            Current = observation.Value;
            Revision = observation.Revision;
        }

        internal void Set(Transfer value, ResponseMeta meta, V2CommandIdentity identity)
        {
            Current = value;
            Revision = ResultRevision(meta, identity);
        }

        internal JsonObject? Observations()
        {
            if (Epoch is null && Begin is null && Commit is null && Destination?.Published != true && Destination?.CleanupFailure is null)
            {
                return null;
            }

            var observations = new JsonObject();
            if (Epoch is { } epoch)
            {
                observations["transferOwnerEpoch"] = IdText.Format(epoch);
            }
            if (Begin is { } begin)
            {
                observations["beginCommandId"] = IdText.Format(begin.CommandId);
            }

            if (Commit is { } commit)
            {
                observations["commitCommandId"] = IdText.Format(commit.CommandId);
            }

            if (Destination?.PublicationConfirmed == true)
            {
                observations["localFilePublished"] = true;
            }
            else if (Destination?.Published == true)
            {
                observations["localPublicationUnconfirmed"] = true;
                if (PublicationFailure is not null)
                {
                    observations["localPublicationFailure"] = PublicationFailure;
                }
            }

            if (Destination?.CleanupFailure is { } cleanup)
            {
                observations["localStagingCleanupFailure"] = cleanup;
            }

            return observations;
        }
    }

    private sealed record TransferObservation(Transfer Value, Revision Revision);

    private sealed record TransferSelection(Id? Resume, Id? OwnerEpoch, Id? CommandId, long? ExpectedRevision);

    private sealed class TransferOptions
    {
        private readonly Option<string?> _resume = new("--resume") { Description = "Resume the existing transfer with this ID" };
        private readonly Option<string?> _epoch = new("--owner-epoch") { Description = "Original owner epoch for resume or exact Begin replay" };
        private readonly Option<string?> _command = new("--command-id") { Description = "Original Begin command for exact replay" };
        private readonly Option<long?> _revision = new("--expected-revision") { Description = "Expected Sandbox configuration revision" };

        internal void AddTo(Command command)
        {
            command.Options.Add(_resume);
            command.Options.Add(_epoch);
            command.Options.Add(_command);
            command.Options.Add(_revision);
        }

        internal TransferSelection Read(ParseResult result)
        {
            var resume = ReadOptionalId(result.GetValue(_resume), "--resume");
            var epoch = ReadOptionalId(result.GetValue(_epoch), "--owner-epoch");
            var command = ReadOptionalId(result.GetValue(_command), "--command-id");
            var revision = result.GetValue(_revision);
            if ((resume is not null || command is not null) != (epoch is not null)
                || resume is not null && (command is not null || revision is not null)
                || command is not null && revision is null)
            {
                throw new UsageException("Resume requires the original --owner-epoch. Exact Begin replay also requires --command-id and --expected-revision.");
            }

            return new(resume, epoch, command, revision);
        }
    }
}
