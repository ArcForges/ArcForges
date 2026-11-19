// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.CommandLine;

internal static class V2Cli
{
    private const int MaxInputBytes = 8 * 1024 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static void Set(Command command, Func<ParseResult, Cli> factory,
        Func<Cli, ParseResult, CancellationToken, Task<int>> body, bool stream = false) =>
        command.SetAction(async (result, cancellationToken) =>
        {
            Cli cli;
            try
            {
                cli = factory(result);
            }
            catch (UsageException exception)
            {
                var output = new CliOutput(result.InvocationConfiguration.Output, result.InvocationConfiguration.Error,
                    result.GetValue<bool>("--json"), quiet: false, color: false, verbose: false, width: 120);
                return Fail(new Cli(output, testMode: false, timeout: null, yes: false),
                    Error(ErrorCategory.Validation, "invalid_argument", exception.Message), stream: stream);
            }

            try
            {
                if (cli.WaitApproval is not null)
                {
                    throw new UsageException("--wait-approval is unavailable for this command.");
                }

                return await body(cli, result, cancellationToken).ConfigureAwait(false);
            }
            catch (UsageException exception)
            {
                return Fail(cli, Error(ErrorCategory.Validation, "invalid_argument", exception.Message), stream: stream);
            }
            catch (V2CommandException exception)
            {
                return Fail(cli, exception.Error, exception.Identity, stream: stream);
            }
            catch (NodeUnavailableException exception)
            {
                var error = exception.Error ?? (exception.Reason switch
                {
                    NodeUnavailableReason.AccessDenied => Error(ErrorCategory.Authorization, "permission_denied", "local_node_access_denied"),
                    NodeUnavailableReason.Busy => Error(ErrorCategory.Resource, "overloaded", "local_node_busy"),
                    NodeUnavailableReason.Incompatible => Error(ErrorCategory.Execution, "unsupported_combination", "local_node_incompatible"),
                    _ => Error(ErrorCategory.State, "node_unavailable", exception.Reason + ". Run 'arcforges node start' to start the local service."),
                });
                return Fail(cli, error, stream: stream);
            }
            catch (RpcException exception)
            {
                return Fail(cli, exception.StatusCode switch
                {
                    StatusCode.Unauthenticated or StatusCode.PermissionDenied =>
                        Error(ErrorCategory.Authorization, "permission_denied", exception.StatusCode.ToString()),
                    StatusCode.ResourceExhausted => Error(ErrorCategory.Resource, "overloaded", exception.StatusCode.ToString()),
                    StatusCode.Unimplemented => Error(ErrorCategory.Execution, "unsupported_combination", exception.StatusCode.ToString()),
                    _ => Error(ErrorCategory.State, "node_unavailable", exception.StatusCode.ToString()),
                }, stream: stream);
            }
            catch (OperationCanceledException)
            {
                return Fail(cli, Error(ErrorCategory.State, "node_unavailable", "call_cancelled"), stream: stream);
            }
        });

    internal static Id ReadId(string? text, string label)
    {
        if (!IdText.TryParse(text, out var id) || id.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            throw new UsageException(label + " requires a full, nonzero 26-character ID.");
        }

        return new Id { Value = ByteString.CopyFrom(id) };
    }

    internal static async Task<T> ReadJsonAsync<T>(string path, MessageParser<T> parser, CancellationToken ct)
        where T : IMessage<T>
    {
        try
        {
            await using var stream = File.OpenRead(path);
            var length = stream.Length;
            if (length > MaxInputBytes)
            {
                throw new UsageException("JSON input exceeds 8 MiB.");
            }

            var bytes = new byte[(int)length + 1];
            var size = await stream.ReadAtLeastAsync(bytes, bytes.Length, false, ct).ConfigureAwait(false);
            if (size != length)
            {
                throw new UsageException("The JSON input changed while it was being read.");
            }

            var start = bytes.AsSpan(0, size).StartsWith(Encoding.UTF8.Preamble) ? Encoding.UTF8.Preamble.Length : 0;
            return parser.ParseJson(StrictUtf8.GetString(bytes, start, size - start));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or FormatException)
        {
            throw new UsageException("Provide a readable UTF-8 file in the command's protobuf JSON schema.");
        }
    }

    internal static T Require<T>(T? value, ArcError? error, V2CommandIdentity? identity = null) where T : class =>
        value is not null && error is null ? value : throw new V2CommandException(error ??
            (identity is null
                ? Error(ErrorCategory.State, "node_unavailable", "response_outcome_missing")
                : UnknownEffect("response_outcome_missing", identity.Meta.CorrelationId)), identity);

    internal static async Task<T> SendAsync<T>(Cli cli, string method, V2CommandIdentity identity, Func<AsyncUnaryCall<T>> call)
    {
        var started = Stopwatch.GetTimestamp();
        try
        {
            using var dispatched = call();
            return await dispatched.ResponseAsync.ConfigureAwait(false);
        }
        catch (RpcException exception)
        {
            throw new V2CommandException(UnknownEffect(method + "/" + exception.StatusCode, identity.Meta.CorrelationId), identity);
        }
        catch (OperationCanceledException)
        {
            throw new V2CommandException(UnknownEffect(method + "/cancelled", identity.Meta.CorrelationId), identity);
        }
        finally
        {
            cli.Output.Trace($"{method} {Stopwatch.GetElapsedTime(started).TotalMilliseconds:0.0} ms " +
                $"(correlation {IdText.Format(identity.Meta.CorrelationId)})");
        }
    }

    internal static int Print(Cli cli, IMessage value, V2CommandIdentity? identity = null) =>
        Print(cli, (JsonObject)CliOutput.ToJsonNode(value), identity);

    internal static int Print(Cli cli, JsonObject value, V2CommandIdentity? identity = null)
    {
        if (cli.Output.Json)
        {
            WriteIdentity(value, identity);
            cli.Output.DocumentTerminalSafe(value);
        }
        else
        {
            cli.Output.Essential(HumanFields(value));
            WriteIdentity(cli, identity);
        }

        return 0;
    }

    internal static void PrintLine(Cli cli, IMessage value)
    {
        if (cli.Output.Json)
        {
            cli.Output.JsonLine(value);
        }
        else
        {
            cli.Output.Essential(HumanFields((JsonObject)CliOutput.ToJsonNode(value)));
        }
    }

    internal static int Fail(Cli cli, ArcError error, V2CommandIdentity? identity = null, IMessage? value = null, bool stream = false,
        JsonObject? observations = null)
    {
        if (cli.Output.Json)
        {
            var document = new JsonObject { ["error"] = CliOutput.ToJsonNode(error) };
            if (value is not null)
            {
                document["value"] = CliOutput.ToJsonNode(value);
            }

            if (observations is not null)
            {
                document["observations"] = observations;
            }

            WriteIdentity(document, identity);
            if (stream)
            {
                cli.Output.Essential(document.ToJsonString());
            }
            else
            {
                cli.Output.DocumentTerminalSafe(document);
            }
        }
        else
        {
            if (value is not null)
            {
                cli.Output.Essential(HumanFields((JsonObject)CliOutput.ToJsonNode(value)));
            }

            if (observations is not null)
            {
                cli.Output.Essential(HumanFields(observations));
            }

            var detail = Messages.For(error);
            var correlation = IdText.Format(error.CorrelationId);
            cli.Output.Error.WriteLine($"error: {detail} ({error.Category.ToString().ToUpperInvariant()}/{Messages.Plain(error.Code)}, " +
                $"effect {error.Effect}, correlation {correlation})");
            WriteIdentity(cli, identity);
        }

        return error.Code switch
        {
            "receipt_compacted" => 3,
            "outcome_unknown" => 8,
            _ when error.Effect == EffectCertainty.Unknown => 8,
            "node_stopping" or "node_unavailable" => 7,
            "unsupported_combination" or "terminal_unavailable" or "pause_unsupported" => 5,
            "busy" or "in_use" or "managed_use" => 3,
            "not_found" => 2,
            _ => error.Category switch
            {
                ErrorCategory.Validation => 2,
                ErrorCategory.Conflict => 3,
                ErrorCategory.Authentication or ErrorCategory.Authorization or ErrorCategory.Entitlement => 4,
                ErrorCategory.Resource => 6,
                _ => 8,
            },
        };
    }

    internal static ArcError UnknownEffect(string reason, Id? correlationId = null) => new()
    {
        Category = ErrorCategory.Execution,
        Code = "outcome_unknown",
        MessageKey = "cli.outcome_unknown",
        CorrelationId = correlationId,
        Effect = EffectCertainty.Unknown,
        Details = new ErrorDetails { State = new StateFailure { Reason = reason } },
        Retry = new RetryAdvice { Mode = RetryMode.Reconcile, ReconciliationOperation = "NodeService.GetOperation" },
    };

    internal static ArcError Error(ErrorCategory category, string code, string reason) => new()
    {
        Category = category,
        Code = code,
        MessageKey = "cli." + code,
        Effect = EffectCertainty.DidNotHappen,
        Details = new ErrorDetails { State = new StateFailure { Reason = reason } },
        Retry = new RetryAdvice { Mode = RetryMode.Never },
    };

    private static string HumanFields(JsonObject value) =>
        value.Count == 0 ? "No results." : string.Join(Environment.NewLine, value.Select(field => $"{field.Key}: {field.Value?.ToJsonString()}"));

    private static void WriteIdentity(JsonObject result, V2CommandIdentity? identity)
    {
        if (identity is not null)
        {
            result["commandId"] = IdText.Format(identity.CommandId);
            result["ownerEpoch"] = IdText.Format(identity.OwnerEpoch);
            if (identity.Meta.ExpectedRev is { } expected)
            {
                result["expectedRevision"] = expected.Value.ToString(CultureInfo.InvariantCulture);
            }

            if (identity.TerminalOption is { } terminal)
            {
                result["terminal"] = terminal;
            }
        }
    }

    private static void WriteIdentity(Cli cli, V2CommandIdentity? identity)
    {
        if (identity is not null)
        {
            cli.Output.Error.WriteLine($"command ID {IdText.Format(identity.CommandId)}, owner epoch {IdText.Format(identity.OwnerEpoch)}");
            if (identity.Meta.ExpectedRev is { } expected)
            {
                cli.Output.Error.WriteLine($"expected revision {expected.Value.ToString(CultureInfo.InvariantCulture)}");
            }

            if (identity.TerminalOption is { } terminal)
            {
                cli.Output.Error.WriteLine("terminal " + terminal);
            }
        }
    }
}

internal sealed record V2CommandIdentity(Id OwnerEpoch, Id CommandId, RequestMeta Meta)
{
    internal string? TerminalOption { get; init; }
}

internal sealed class V2CommandException(ArcError error, V2CommandIdentity? identity) : Exception(error.Code)
{
    internal ArcError Error { get; } = error;
    internal V2CommandIdentity? Identity { get; } = identity;
}

internal sealed class V2MutationOptions
{
    private readonly Option<string?> _ownerEpoch = new("--owner-epoch") { Description = "Original owner epoch of an explicitly replayed command" };
    private readonly Option<string?> _commandId = new("--command-id") { Description = "Original ID of an explicitly replayed command" };

    internal void AddTo(Command command)
    {
        command.Options.Add(_ownerEpoch);
        command.Options.Add(_commandId);
        command.Validators.Add(result =>
        {
            if ((result.GetValue(_ownerEpoch) is null) != (result.GetValue(_commandId) is null))
            {
                result.AddError("--owner-epoch and --command-id must be supplied together.");
            }
        });
    }

    internal bool IsReplay(ParseResult result) => result.GetValue(_commandId) is not null || result.GetValue(_ownerEpoch) is not null;

    internal async Task<V2CommandIdentity> BeginAsync(ParseResult result, V2CliSession session, DateTime deadline, CancellationToken ct)
    {
        Id epoch;
        Id id;
        if (IsReplay(result))
        {
            epoch = V2Cli.ReadId(result.GetValue(_ownerEpoch), "--owner-epoch");
            id = V2Cli.ReadId(result.GetValue(_commandId), "--command-id");
        }
        else
        {
            var response = await session.HandshakeAsync(deadline, ct).ConfigureAwait(false);
            var handshake = V2Cli.Require(response.Value, response.Error);
            epoch = V2Cli.Require(handshake.OwnerEpoch, null);
            id = CommandIds.New();
        }

        var meta = Cli.Meta();
        meta.CommandId = id;
        return new V2CommandIdentity(epoch, id, meta);
    }
}
