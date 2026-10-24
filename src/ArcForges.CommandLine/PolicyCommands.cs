// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges policy ...</c> (experience/cli.md C-04; policy.proto): show the document (the protobuf JSON mapping, optionally one
/// section), the defaults, validate or apply a JSON file, edit the document in <c>$VISUAL</c> or <c>$EDITOR</c> (validated, then applied with
/// <c>expected_rev</c>), list revisions and restore one. ID fields are base32 text in the JSON this command prints and accepts.
/// <c>policy explain &lt;operation&gt; --origin agent|script|remote</c> shows the permission matrix's decision and its source (11 section 1).
/// </summary>
internal static class PolicyCommands
{
    private static readonly TimeSpan Unary = TimeSpan.FromSeconds(10);
    private static readonly JsonParser Parser = new(JsonParser.Settings.Default.WithIgnoreUnknownFields(false));
    private static readonly JsonFormatter Formatter = new(JsonFormatter.Settings.Default.WithFormatDefaultValues(false));

    public static Command Build(Func<ParseResult, Cli> factory)
    {
        var policy = new Command("policy", "Show, validate, change and restore the node policy");
        policy.Subcommands.Add(Show(factory));
        policy.Subcommands.Add(Defaults(factory));
        policy.Subcommands.Add(Validate(factory));
        policy.Subcommands.Add(Apply(factory));
        policy.Subcommands.Add(Edit(factory));
        policy.Subcommands.Add(Revisions(factory));
        policy.Subcommands.Add(Restore(factory));
        policy.Subcommands.Add(Explain(factory));
        return policy;
    }

    private static Command Show(Func<ParseResult, Cli> factory)
    {
        var section = new Option<string?>("--section") { Description = "One top-level section (for example resources or pools)", HelpName = "s" };
        var command = new Command("show", "Show the current policy document and its revision") { section };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var request = new PolicyServiceGetPolicyRequest { Meta = Cli.Meta() };
            var response = await cli.CallAsync("GetPolicy", request.Meta, () => session.Channel.Policy.GetPolicyAsync(request, deadline: cli.Deadline(Unary),
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            var document = CliOutput.ToJsonNode(response.Value.Document);
            if (result.GetValue(section) is { } name)
            {
                var key = JsonName(name);
                if (document is not JsonObject sections || !sections.ContainsKey(key) && !IsSection(key))
                {
                    throw new UsageException($"--section: '{name}' is not a section of the policy document.");
                }

                document = (document as JsonObject)?[key]?.DeepClone() ?? new JsonObject();
            }

            if (!cli.Output.Json)
            {
                cli.Output.Note(string.Create(CultureInfo.InvariantCulture, $"policy revision {response.Value.Revision.Revision.Value}"));
                cli.Output.Out.WriteLine(document.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
                return ExitCodes.Success;
            }

            cli.Output.Document(new JsonObject { ["revision"] = CliOutput.ToJsonNode(response.Value.Revision), ["document"] = document });
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Defaults(Func<ParseResult, Cli> factory)
    {
        var command = new Command("defaults", "Show the default policy document of this node");
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var request = new PolicyServiceGetDefaultPolicyRequest { Meta = Cli.Meta() };
            var response = await cli.CallAsync("GetDefaultPolicy", request.Meta, () => session.Channel.Policy.GetDefaultPolicyAsync(request,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            cli.Output.Document(response.Value.Document);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Validate(Func<ParseResult, Cli> factory)
    {
        var file = new Argument<string>("file") { Description = "A policy document in the protobuf JSON mapping" };
        var command = new Command("validate", "Validate a policy document without applying it (exit 1 with ERROR issues)") { file };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var document = Read(result.GetValue(file)!);
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var request = new PolicyServiceValidatePolicyRequest { Meta = Cli.Meta(), Document = document };
            var response = await cli.CallAsync("ValidatePolicy", request.Meta, () => session.Channel.Policy.ValidatePolicyAsync(request,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
            }
            else
            {
                PrintIssues(cli, response.Value.Issues);
                cli.Output.Line(response.Value.Valid ? "valid" : "invalid");
            }

            return response.Value.Valid ? ExitCodes.Success : ExitCodes.Failed;
        });
        return command;
    }

    private static Command Apply(Func<ParseResult, Cli> factory)
    {
        var file = new Argument<string>("file") { Description = "A policy document in the protobuf JSON mapping" };
        var comment = new Option<string?>("--comment") { Description = "The revision comment (<= 500 characters)" };
        var command = new Command("apply", "Replace the policy document (a new revision)") { file, comment };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var document = Read(result.GetValue(file)!);
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (revision, exit) = await CurrentRevisionAsync(cli, session, cancellationToken).ConfigureAwait(false);
            return revision is null ? exit : await UpdateAsync(cli, session, document, revision, result.GetValue(comment), cancellationToken).ConfigureAwait(false);
        });
        return command;
    }

    private static Command Edit(Func<ParseResult, Cli> factory)
    {
        var comment = new Option<string?>("--comment") { Description = "The revision comment (<= 500 characters)" };
        var command = new Command("edit", "Edit the policy document in $VISUAL or $EDITOR, then validate and apply it") { comment };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var request = new PolicyServiceGetPolicyRequest { Meta = Cli.Meta() };
            var current = await cli.CallAsync("GetPolicy", request.Meta, () => session.Channel.Policy.GetPolicyAsync(request, deadline: cli.Deadline(Unary),
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (current.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            var path = Path.Combine(Path.GetTempPath(), "arcforges-policy-" + Guid.NewGuid().ToString("N")[..12] + ".json");
            try
            {
                var original = CliOutput.ToJsonNode(current.Value.Document).ToJsonString(new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(path, original, new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);
                var editor = Environment.GetEnvironmentVariable("VISUAL") is { Length: > 0 } visual ? visual
                    : Environment.GetEnvironmentVariable("EDITOR") is { Length: > 0 } editorVariable ? editorVariable
                    : OperatingSystem.IsWindows() ? "notepad" : "vi";
                var exitCode = await RunEditorAsync(editor, path, cancellationToken).ConfigureAwait(false);
                if (exitCode != 0)
                {
                    cli.Output.Error.WriteLine(string.Create(CultureInfo.InvariantCulture, $"error: the editor exited with {exitCode}; nothing was applied"));
                    return ExitCodes.Failed;
                }

                var edited = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
                if (edited == original)
                {
                    cli.Output.Line("no change");
                    return ExitCodes.Success;
                }

                return await UpdateAsync(cli, session, Parse(edited, path), current.Value.Revision.Revision, result.GetValue(comment), cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                File.Delete(path);
            }
        });
        return command;
    }

    private static Command Revisions(Func<ParseResult, Cli> factory)
    {
        var limit = new Option<int?>("--limit") { Description = "At most this many (1..200; default 50)", HelpName = "n" };
        var command = new Command("revisions", "List policy revisions, newest first") { limit };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var request = new PolicyServiceListPolicyRevisionsRequest { Meta = Cli.Meta(), Page = new PageRequest { Limit = result.GetValue(limit) ?? 50 } };
            var response = await cli.CallAsync("ListPolicyRevisions", request.Meta, () => session.Channel.Policy.ListPolicyRevisionsAsync(request,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
                return ExitCodes.Success;
            }

            cli.Output.Table(["REVISION", "CREATED", "BY", "COMMENT"], [.. response.Value.Revisions.Select(revision => (IReadOnlyList<string>)
            [
                revision.Revision.Value.ToString(CultureInfo.InvariantCulture),
                CliOutput.When(revision.CreatedAt),
                revision.Actor?.Origin.ToString().ToUpperInvariant() ?? "-",
                revision.Comment,
            ])]);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Restore(Func<ParseResult, Cli> factory)
    {
        var revision = new Argument<long>("revision") { Description = "The revision to restore (as a new revision)" };
        var comment = new Option<string?>("--comment") { Description = "The revision comment (<= 500 characters)" };
        var command = new Command("restore", "Create a new revision equal to an earlier one") { revision, comment };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (current, exit) = await CurrentRevisionAsync(cli, session, cancellationToken).ConfigureAwait(false);
            if (current is null)
            {
                return exit;
            }

            var request = new PolicyServiceRestorePolicyRevisionRequest { Meta = Cli.Meta(), Revision = new Revision { Value = result.GetValue(revision) } };
            request.Meta.ExpectedRev = current;
            if (result.GetValue(comment) is { } text)
            {
                request.Comment = text;
            }

            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("RestorePolicyRevision", request.Meta.CommandId, action, r => session.Channel.Policy.RestorePolicyRevisionAsync(r,
                deadline: cli.Deadline(Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
            }
            else
            {
                cli.Output.Line(string.Create(CultureInfo.InvariantCulture, $"policy revision {response.Value.Revision.Revision.Value}"));
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Explain(Func<ParseResult, Cli> factory)
    {
        var operation = new Argument<string>("operation") { Description = "A permission matrix operation, for example task.cancel_others" };
        var origin = new Option<string>("--origin") { Description = "The origin: human, script, agent, remote or peer", Required = true, HelpName = "o" };
        var command = new Command("explain", "Explain the permission decision for an operation and origin, with its source") { operation, origin };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var name = result.GetValue(origin)!;
            var value = name.ToUpperInvariant() switch
            {
                "HUMAN" => Origin.Human,
                "SCRIPT" => Origin.Script,
                "AGENT" => Origin.Agent,
                "REMOTE" => Origin.Remote,
                "PEER" => Origin.Peer,
                _ => throw new UsageException($"--origin: '{name}' is not human, script, agent, remote or peer."),
            };
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var request = new PolicyServiceExplainPermissionRequest { Meta = Cli.Meta(), Operation = result.GetValue(operation)!, Origin = value };
            var response = await cli.CallAsync("ExplainPermission", request.Meta, () => session.Channel.Policy.ExplainPermissionAsync(request,
                deadline: cli.Deadline(TimeSpan.FromSeconds(5)), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
                return ExitCodes.Success;
            }

            var decision = response.Value.Decision switch
            {
                PermissionDecision.Allow => "allowed",
                PermissionDecision.Approval => "needs an approval",
                PermissionDecision.Deny => "denied",
                PermissionDecision.RemotePolicy => "decided by the remote-control policy (risk " + response.Value.RemoteRisk.ToString().ToLowerInvariant() + ")",
                _ => response.Value.Decision.ToString(),
            };
            cli.Output.Line($"{request.Operation} for {name.ToUpperInvariant()}: {decision}");
            cli.Output.Line($"  source: {response.Value.Source}");
            return ExitCodes.Success;
        });
        return command;
    }

    private static async Task<(Revision? Revision, int Exit)> CurrentRevisionAsync(Cli cli, NodeSession session, CancellationToken cancellationToken)
    {
        var request = new PolicyServiceGetPolicyRequest { Meta = Cli.Meta() };
        var response = await cli.CallAsync("GetPolicy", request.Meta, () => session.Channel.Policy.GetPolicyAsync(request, deadline: cli.Deadline(Unary),
            cancellationToken: cancellationToken)).ConfigureAwait(false);
        return response.Error is { } error ? (null, cli.Output.Fail(error, request.Meta.CorrelationId)) : (response.Value.Revision.Revision, ExitCodes.Success);
    }

    private static async Task<int> UpdateAsync(Cli cli, NodeSession session, PolicyDocument document, Revision expected, string? comment, CancellationToken cancellationToken)
    {
        var request = new PolicyServiceUpdatePolicyRequest { Meta = Cli.Meta(), Document = document };
        request.Meta.ExpectedRev = expected;
        if (comment is not null)
        {
            request.Comment = comment;
        }

        var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
        var response = await cli.MutateAsync("UpdatePolicy", request.Meta.CommandId, action, r => session.Channel.Policy.UpdatePolicyAsync(r,
            deadline: cli.Deadline(Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
        if (response.Error is { } error)
        {
            return cli.Output.Fail(error, request.Meta.CorrelationId);
        }

        if (cli.Output.Json)
        {
            cli.Output.Document(response.Value);
            return ExitCodes.Success;
        }

        PrintIssues(cli, response.Value.Warnings);
        cli.Output.Line(string.Create(CultureInfo.InvariantCulture, $"policy revision {response.Value.Revision.Revision.Value}"));
        return ExitCodes.Success;
    }

    private static async Task<int> RunEditorAsync(string editor, string path, CancellationToken cancellationToken)
    {
        // $EDITOR may carry arguments ("code --wait"): the first word is the program, the file comes last.
        var words = editor.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var start = new ProcessStartInfo(words[0]) { UseShellExecute = false };
        foreach (var argument in words.Skip(1))
        {
            start.ArgumentList.Add(argument);
        }

        start.ArgumentList.Add(path);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("The editor did not start.");
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        return process.ExitCode;
    }

    private static PolicyDocument Read(string file)
    {
        string text;
        try
        {
            text = File.ReadAllText(file);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new UsageException($"file: '{file}' cannot be read ({exception.Message}).");
        }

        return Parse(text, file);
    }

    /// <summary>Parses a document in the protobuf JSON mapping, with ID fields as base32 text (as the CLI prints them) or as <c>{"value": base64}</c>.</summary>
    internal static PolicyDocument Parse(string text, string source)
    {
        try
        {
            var node = JsonNode.Parse(text) ?? throw new UsageException($"{source}: an empty document.");
            if (node is JsonObject { Count: 2 } wrapper && wrapper["document"] is JsonObject inner && wrapper.ContainsKey("revision"))
            {
                // The output of 'policy show --json'.
                node = inner.DeepClone();
            }

            ParseIds(node);
            return Parser.Parse<PolicyDocument>(node.ToJsonString());
        }
        catch (Exception exception) when (exception is JsonException or InvalidProtocolBufferException or FormatException)
        {
            throw new UsageException($"{source}: not a policy document in the protobuf JSON mapping ({exception.Message}).");
        }
    }

    private static void ParseIds(JsonNode node)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var (key, child) in obj.ToList())
                {
                    if (child is JsonValue value && key.EndsWith("Id", StringComparison.Ordinal) && value.TryGetValue<string>(out var text) && IdText.TryParse(text, out var id))
                    {
                        obj[key] = new JsonObject { ["value"] = Convert.ToBase64String(id) };
                    }
                    else if (child is not null)
                    {
                        ParseIds(child);
                    }
                }

                break;
            case JsonArray array:
                foreach (var item in array)
                {
                    if (item is not null)
                    {
                        ParseIds(item);
                    }
                }

                break;
        }
    }

    private static void PrintIssues(Cli cli, IEnumerable<PolicyIssue> issues)
    {
        foreach (var issue in issues)
        {
            cli.Output.Error.WriteLine($"{issue.Severity.ToString().ToLowerInvariant()}: {issue.Path}: {issue.Message}");
        }
    }

    /// <summary>The JSON name of a section given as <c>retry_safety</c> or <c>retrySafety</c>.</summary>
    private static string JsonName(string name)
    {
        var parts = name.Split('_', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length <= 1 ? name : parts[0] + string.Concat(parts.Skip(1).Select(part => char.ToUpperInvariant(part[0]) + part[1..]));
    }

    private static bool IsSection(string key) => PolicyDocument.Descriptor.Fields.InDeclarationOrder().Any(field => field.JsonName == key);

    /// <summary>The canonical JSON of a document (tests compare documents through it).</summary>
    internal static string Json(PolicyDocument document) => Formatter.Format(document);
}
