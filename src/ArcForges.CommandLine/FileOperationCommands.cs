// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.CommandLine;

/// <summary>Local HUMAN inspection and acknowledgment of a file effect whose result may be unknown.</summary>
internal static class FileOperationCommands
{
    internal static Command Build(Func<ParseResult, Cli> factory)
    {
        var group = new Command("file-operation", "Inspect and acknowledge local file-operation recovery");
        group.Subcommands.Add(Show(factory));
        group.Subcommands.Add(Acknowledge(factory));
        return group;
    }

    private static Command Show(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("command-id") { Description = "The original operation command ID" };
        var command = new Command("show", "Show a local file-operation recovery record") { id };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            if (!TryId(result.GetValue(id), out var operationId))
                return cli.Output.Usage("command-id: give a complete, nonzero operation ID.");
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (operation, exit, warnings) = await ReadAsync(cli, session, operationId, cancellationToken).ConfigureAwait(false);
            if (operation is null)
            {
                RenderStageLocations(cli, warnings);
                return exit;
            }
            Render(cli, operation, warnings);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Acknowledge(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("command-id") { Description = "The original operation command ID" };
        var digest = new Option<string>("--digest") { Description = "Exact request SHA-256 from show", Required = true };
        var command = new Command("acknowledge", "Release an UNKNOWN recovery hold after inspection") { id, digest };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            if (!TryId(result.GetValue(id), out var operationId))
                return cli.Output.Usage("command-id: give a complete, nonzero operation ID.");
            if (!TryDigest(result.GetValue(digest), out var requestedDigest))
                return cli.Output.Usage("digest: give exactly 64 hexadecimal SHA-256 digits.");
            if (!ClientProcess.InteractiveTerminal)
                return cli.Output.Usage("acknowledgment requires an interactive local HUMAN confirmation.");

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (operation, exit, warnings) = await ReadAsync(cli, session, operationId, cancellationToken).ConfigureAwait(false);
            if (operation is null)
            {
                RenderStageLocations(cli, warnings);
                return exit;
            }
            RenderStageLocations(cli, warnings);
            if (operation.State != FileOperationState.Unknown || !operation.Held ||
                !CryptographicOperations.FixedTimeEquals(operation.RequestSha256.Span, requestedDigest))
            {
                cli.Output.Error.WriteLine("The operation is not a held UNKNOWN with that digest. Show it again; nothing was changed.");
                return ExitCodes.Failed;
            }

            // A global --yes never skips this explicit confirmation. The exact command and escaped target are visible.
            cli.Output.Error.Write("Acknowledge UNKNOWN command " + IdText.Format(operation.CommandId) + " for " + Target(operation) +
                "? This releases the hold but does not establish success. Type 'acknowledge' to continue: ");
            var answer = await Console.In.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (!string.Equals(answer?.Trim(), "acknowledge", StringComparison.Ordinal))
            {
                cli.Output.Error.WriteLine("Nothing was changed.");
                return ExitCodes.Failed;
            }

            var request = new FileServiceAcknowledgeFileOperationRequest
            {
                Meta = Cli.Meta(),
                OperationCommandId = operationId,
                OperationDigest = ByteString.CopyFrom(requestedDigest),
            };
            var action = CommandIds.Begin(request, item => item.Meta, (item, meta) => item.Meta = meta);
            var response = await cli.MutateAsync("AcknowledgeFileOperation", request.Meta.CommandId, action,
                item => session.Channel.Files.AcknowledgeFileOperationAsync(item, deadline: cli.Deadline(TimeSpan.FromSeconds(10)),
                    cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            if (!NodeShapes.IsValid(response) || response.Meta?.CorrelationId is not { } responseCorrelation ||
                !responseCorrelation.Equals(request.Meta.CorrelationId) ||
                response.Error is { } error && !error.CorrelationId.Equals(request.Meta.CorrelationId))
                return cli.Output.Fail(TaskRoute.MalformedResponse(), request.Meta.CorrelationId);
            if (response.Error is { } failure) return cli.Output.Fail(failure, request.Meta.CorrelationId);
            if (response.Value?.Receipt is not { Effect: EffectCertainty.Happened } receipt ||
                !receipt.CommandId.Equals(request.Meta.CommandId) || response.Value.Operation is not { } acknowledged ||
                !acknowledged.CommandId.Equals(operationId) || acknowledged.State != FileOperationState.Unknown ||
                !acknowledged.Acknowledged || acknowledged.Held || acknowledged.Kind != operation.Kind ||
                !Equals(acknowledged.WorkspacePath, operation.WorkspacePath) || !Equals(acknowledged.AttemptId, operation.AttemptId) ||
                !Equals(acknowledged.Error, operation.Error) || !Equals(acknowledged.CreatedAt, operation.CreatedAt) ||
                !CryptographicOperations.FixedTimeEquals(acknowledged.RequestSha256.Span, requestedDigest))
                return cli.Output.Fail(TaskRoute.MalformedResponse(), request.Meta.CorrelationId);

            if (cli.Output.Json) cli.Output.Document(acknowledged);
            else cli.Output.Essential("The hold was released. The earlier file effect remains UNKNOWN.");
            return ExitCodes.Success;
        });
        return command;
    }

    private static async Task<(FileOperation? Operation, int Exit, string[] Warnings)> ReadAsync(Cli cli, NodeSession session, Id id, CancellationToken token)
    {
        var request = new FileServiceGetFileOperationRequest { Meta = Cli.Meta(), OperationCommandId = id };
        var response = await cli.CallAsync("GetFileOperation", request.Meta,
            () => session.Channel.Files.GetFileOperationAsync(request, deadline: cli.Deadline(TimeSpan.FromSeconds(10)),
                cancellationToken: token)).ConfigureAwait(false);
        if (!NodeShapes.IsValid(response) || response.Meta?.CorrelationId is not { } correlation ||
            !correlation.Equals(request.Meta.CorrelationId) ||
            response.Error is { } error && !error.CorrelationId.Equals(request.Meta.CorrelationId))
            return (null, cli.Output.Fail(TaskRoute.MalformedResponse(), request.Meta.CorrelationId), []);
        if (response.Meta.Warnings.Any(warning => warning.StartsWith(StageWarningPrefix, StringComparison.Ordinal) && !TryStageWarning(warning, out _)))
            return (null, cli.Output.Fail(TaskRoute.MalformedResponse(), request.Meta.CorrelationId), []);
        if (response.Error is { } failure) return (null, cli.Output.Fail(failure, request.Meta.CorrelationId), response.Meta.Warnings.ToArray());
        if (response.Value?.Operation is not { } operation || !operation.CommandId.Equals(id))
            return (null, cli.Output.Fail(TaskRoute.MalformedResponse(), request.Meta.CorrelationId), []);
        return (operation, ExitCodes.Success, response.Meta.Warnings.ToArray());
    }

    internal static void Render(Cli cli, FileOperation operation, IReadOnlyList<string>? warnings = null)
    {
        var locations = StageLocations(warnings);
        if (cli.Output.Json)
        {
            var document = (JsonObject)CliOutput.ToJsonNode(operation);
            if (locations.Count > 0)
            {
                var stages = new JsonArray();
                foreach (var location in locations)
                    stages.Add((JsonNode)new JsonObject { ["slot"] = location.Slot, ["path"] = location.Path, ["confirmedAtCheck"] = location.Confirmed, ["identityBound"] = location.HasIdentity });
                document["localStageLocations"] = stages;
            }
            cli.Output.DocumentTerminalSafe(document);
            return;
        }

        cli.Output.Essential("Command: " + IdText.Format(operation.CommandId));
        cli.Output.Essential("Target: " + Target(operation));
        cli.Output.Essential("Request SHA-256: " + Convert.ToHexStringLower(operation.RequestSha256.Span));
        cli.Output.Essential("Kind: " + operation.Kind + "; state: " + operation.State);
        cli.Output.Essential("Held: " + operation.Held + "; acknowledged: " + operation.Acknowledged);
        if (operation.State == FileOperationState.Unknown)
        {
            cli.Output.Essential("The effect is UNKNOWN. Do not automatically repeat the operation.");
            if (locations.Count == 0)
                cli.Output.Essential("No named-stage location was reported. An anonymous stage may be unavailable; other handles may retain it.");
            RenderStageLocations(cli, warnings);
            if (operation.Held)
                cli.Output.Essential("Inspect the target and recovery evidence before acknowledging this exact command and digest.");
        }
        else if (operation.State == FileOperationState.Prepared)
        {
            cli.Output.Essential("The effect may be in progress. Do not automatically repeat the operation.");
        }
    }

    private const string StageWarningPrefix = "arcforges.file-stage.v1:";
    private static readonly UTF8Encoding StrictStageUtf8 = new(false, true);
    internal sealed record StageLocation(int Slot, string Path, bool Confirmed, bool HasIdentity);

    internal static bool TryStageWarning(string warning, out StageLocation? location)
    {
        location = null;
        if (!warning.StartsWith(StageWarningPrefix, StringComparison.Ordinal) || warning.Length > 5600) return false;
        var parts = warning[StageWarningPrefix.Length..].Split(':', 3);
        if (parts.Length != 3 || parts[0] is not ("1" or "2") || parts[1] is not ("confirmed" or "last-known" or "unbound")) return false;
        try
        {
            var bytes = Convert.FromBase64String(parts[2]);
            if (bytes.Length is < 1 or > 4096 || Convert.ToBase64String(bytes) != parts[2]) return false;
            var path = StrictStageUtf8.GetString(bytes);
            if (!Path.IsPathFullyQualified(path) || path.Contains('\0')) return false;
            location = new StageLocation(parts[0] == "1" ? 1 : 2, path, parts[1] == "confirmed", parts[1] != "unbound");
            return true;
        }
        catch (Exception exception) when (exception is FormatException or DecoderFallbackException or ArgumentException)
        {
            return false;
        }
    }

    private static List<StageLocation> StageLocations(IReadOnlyList<string>? warnings)
    {
        var locations = new List<StageLocation>();
        if (warnings is not null)
            foreach (var warning in warnings)
                if (TryStageWarning(warning, out var location) && location is not null) locations.Add(location);
        return locations;
    }

    internal static void RenderStageLocations(Cli cli, IReadOnlyList<string>? warnings)
    {
        foreach (var location in StageLocations(warnings))
        {
            var text = (location.Slot == 1 ? "Preimage stage " : "Intended stage ") +
                (location.Confirmed ? "(identity confirmed at check): " : location.HasIdentity ? "(last-known location; identity not confirmed): " :
                    "(reserved location; object identity not recorded and object may not exist): ") +
                Escaped(location.Path);
            if (cli.Output.Json) cli.Output.Error.WriteLine(text);
            else cli.Output.Essential(text);
        }
    }

    private static string Target(FileOperation operation) => operation.WorkspacePath is { } path
        ? "workspace " + IdText.Format(path.WorkspaceId) + " path " + Escaped(path.Path)
        : "attempt " + IdText.Format(operation.AttemptId);

    // A workspace path is untrusted filesystem metadata; escape terminal controls and directional formatting.
    private static string Escaped(string value)
    {
        var output = new StringBuilder(value.Length + 2).Append('"');
        foreach (var character in value)
        {
            if (character is '"' or '\\') output.Append('\\').Append(character);
            else if (char.IsControl(character) || char.GetUnicodeCategory(character) == UnicodeCategory.Format)
                output.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
            else output.Append(character);
        }
        return output.Append('"').ToString();
    }

    private static bool TryId(string? text, out Id id)
    {
        byte[] bytes;
        if (IdText.TryParse(text, out var parsed)) bytes = parsed;
        else if (Guid.TryParseExact(text, "D", out var guid)) bytes = guid.ToByteArray(bigEndian: true);
        else { id = new Id(); return false; }
        id = new Id { Value = ByteString.CopyFrom(bytes) };
        return bytes.AsSpan().IndexOfAnyExcept((byte)0) >= 0;
    }

    private static bool TryDigest(string? text, out byte[] digest)
    {
        digest = [];
        if (text is not { Length: 64 }) return false;
        try { digest = Convert.FromHexString(text); return digest.Length == 32; }
        catch (FormatException) { return false; }
    }
}
