// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using V2Shapes = ArcForges.Contracts.Sandbox.V2.Shapes.ContractShapeValidation;

namespace ArcForges.CommandLine;

internal static class SandboxCommands
{
    private const string DeleteMethod = "SandboxService.Delete";
    private static readonly TimeSpan UnaryDeadline = TimeSpan.FromSeconds(10);

    internal static Command Build(Func<ParseResult, Cli> factory)
    {
        var command = new Command("sandbox", "Manage your local Sandboxes");
        command.Subcommands.Add(Create(factory));
        command.Subcommands.Add(Configure(factory, repair: false));
        command.Subcommands.Add(Rename(factory));
        command.Subcommands.Add(Configure(factory, repair: true));
        command.Subcommands.Add(List(factory));
        command.Subcommands.Add(Inspect(factory));
        command.Subcommands.Add(Delete(factory));
        return command;
    }

    private static Command Create(Func<ParseResult, Cli> factory)
    {
        var name = new Argument<string>("name") { Description = "Sandbox display name" };
        var file = ConfigFile();
        var mutation = new V2MutationOptions();
        var command = new Command("create", "Create an owned Sandbox with a complete configuration") { name, file };
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var config = await V2Cli.ReadJsonAsync(result.GetValue(file)!, SandboxConfig.Parser, cancellationToken).ConfigureAwait(false);
            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var connection = session.PinConnection();
            var deadline = cli.Deadline(UnaryDeadline);
            var identity = await mutation.BeginAsync(result, session, deadline, cancellationToken).ConfigureAwait(false);
            var request = new SandboxServiceCreateRequest
            {
                Meta = identity.Meta,
                OwnerEpoch = identity.OwnerEpoch,
                DisplayName = result.GetValue(name)!,
                Config = config,
            };
            var response = await V2Cli.SendAsync(cli, "SandboxService.Create", identity,
                () => session.Sandboxes.CreateAsync(request, deadline: deadline, cancellationToken: cancellationToken)).ConfigureAwait(false);
            var created = V2Cli.Require(response.Value, response.Error, identity);
            RedactEnvironment(created.Sandbox);
            return V2Cli.Print(cli, created, identity);
        });
        return command;
    }

    private static Command Configure(Func<ParseResult, Cli> factory, bool repair)
    {
        var id = SandboxId();
        var file = ConfigFile();
        var expected = new Option<long>("--expected-revision") { Required = true, Description = "Expected Sandbox configuration revision" };
        var mutation = new V2MutationOptions();
        var command = repair ? new Command("repair", "Repair a Sandbox in ERROR after checking its owned root")
            : new Command("configure", "Replace a Sandbox configuration");
        command.Arguments.Add(id);
        command.Options.Add(file);
        command.Options.Add(expected);
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var sandbox = V2Cli.ReadId(result.GetValue(id), "Sandbox ID");
            var revision = PositiveRevision(result.GetValue(expected));
            var config = await V2Cli.ReadJsonAsync(result.GetValue(file)!, SandboxConfig.Parser, cancellationToken).ConfigureAwait(false);
            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var connection = session.PinConnection();
            var deadline = cli.Deadline(UnaryDeadline);
            var identity = await mutation.BeginAsync(result, session, deadline, cancellationToken).ConfigureAwait(false);
            var request = new SandboxServiceConfigureRequest
            {
                SandboxId = sandbox,
                Config = config,
            };
            if (repair)
            {
                request.RepairError = true;
            }

            return await ConfigureAsync(cli, session, request, identity, revision, deadline, cancellationToken).ConfigureAwait(false);
        });
        return command;
    }

    private static Command Rename(Func<ParseResult, Cli> factory)
    {
        var id = SandboxId();
        var name = new Argument<string>("name") { Description = "New Sandbox display name" };
        var expected = new Option<long>("--expected-revision") { Required = true, Description = "Expected Sandbox configuration revision" };
        var originalConfig = new Option<string?>("--file") { Description = "Complete original config file for an exact replay" };
        var mutation = new V2MutationOptions();
        var command = new Command("rename", "Rename a Sandbox using its current configuration") { id, name, expected, originalConfig };
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var idValue = V2Cli.ReadId(result.GetValue(id), "Sandbox ID");
            var revision = PositiveRevision(result.GetValue(expected));
            var file = result.GetValue(originalConfig);
            if (mutation.IsReplay(result) != (file is not null))
            {
                throw new UsageException("An exact rename replay requires --file with the complete original configuration. Use operation inspect to read the original receipt without replay.");
            }

            var config = file is null ? null : await V2Cli.ReadJsonAsync(file, SandboxConfig.Parser, cancellationToken).ConfigureAwait(false);
            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var connection = session.PinConnection();
            var deadline = cli.Deadline(UnaryDeadline);
            if (config is null)
            {
                var current = await InspectAsync(session, idValue, deadline, cancellationToken).ConfigureAwait(false);
                if (current.Revision.Value != revision.Value)
                {
                    return V2Cli.Fail(cli, new ArcError
                    {
                        Category = ErrorCategory.Conflict,
                        Code = "revision_mismatch",
                        MessageKey = "sandbox.revision_mismatch",
                        Effect = EffectCertainty.DidNotHappen,
                        Retry = new RetryAdvice { Mode = RetryMode.Never },
                        Details = new ErrorDetails
                        {
                            Revision = new RevisionConflict { Expected = revision, Actual = current.Revision },
                        },
                    });
                }

                config = V2Cli.Require(current.Config, null);
            }

            var identity = await mutation.BeginAsync(result, session, deadline, cancellationToken).ConfigureAwait(false);
            var request = new SandboxServiceConfigureRequest
            {
                SandboxId = idValue,
                Config = config,
                DisplayName = result.GetValue(name)!,
            };
            return await ConfigureAsync(cli, session, request, identity, revision, deadline, cancellationToken).ConfigureAwait(false);
        });
        return command;
    }

    private static async Task<int> ConfigureAsync(Cli cli, V2CliSession session, SandboxServiceConfigureRequest request,
        V2CommandIdentity identity, Revision revision, DateTime deadline, CancellationToken cancellationToken)
    {
        identity.Meta.ExpectedRev = revision;
        request.Meta = identity.Meta;
        request.OwnerEpoch = identity.OwnerEpoch;
        var response = await V2Cli.SendAsync(cli, "SandboxService.Configure", identity,
            () => session.Sandboxes.ConfigureAsync(request, deadline: deadline, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var configured = V2Cli.Require(response.Value, response.Error, identity);
        RedactEnvironment(configured.Sandbox);
        return V2Cli.Print(cli, configured, identity);
    }

    private static Command List(Func<ParseResult, Cli> factory)
    {
        var limit = new Option<uint?>("--limit") { Description = "Page size from 1 to 200 (default 50)" };
        var cursor = new Option<string?>("--cursor") { Description = "Opaque continuation from the previous page" };
        var command = new Command("list", "List the current owner's Sandboxes") { limit, cursor };
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var request = new SandboxServiceListRequest { Meta = Cli.Meta() };
            if (result.GetValue(limit) is uint pageSize)
            {
                request.Limit = PageSize(pageSize);
            }

            if (result.GetValue(cursor) is { } next)
            {
                request.Cursor = next;
            }

            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var call = session.Sandboxes.ListAsync(request, deadline: cli.Deadline(UnaryDeadline), cancellationToken: cancellationToken);
            var response = await call.ResponseAsync.ConfigureAwait(false);
            var page = V2Cli.Require(response.Value, response.Error);
            foreach (var sandbox in page.Sandboxes)
            {
                RedactEnvironment(sandbox);
            }

            return V2Cli.Print(cli, page);
        });
        return command;
    }

    private static Command Inspect(Func<ParseResult, Cli> factory)
    {
        var id = SandboxId();
        var command = new Command("inspect", "Show a Sandbox, its revision and capabilities") { id };
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var sandbox = V2Cli.ReadId(result.GetValue(id), "Sandbox ID");
            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            var found = await InspectAsync(session, sandbox, cli.Deadline(UnaryDeadline), cancellationToken).ConfigureAwait(false);
            RedactEnvironment(found);
            return V2Cli.Print(cli, new SandboxServiceInspectValue { Sandbox = found });
        });
        return command;
    }

    private static Command Delete(Func<ParseResult, Cli> factory)
    {
        var sandboxId = SandboxId();
        var preview = new Option<bool>("--plan-only") { Description = "Preview deletion and list the current blockers" };
        var planId = new Option<string?>("--plan") { Description = "Apply this reviewed deletion plan" };
        var originalCommand = new Option<string?>("--resume") { Description = "Continue this original accepted deletion command" };
        var expected = new Option<long?>("--expected-revision") { Description = "Expected Sandbox revision for the plan or continuation" };
        var mutation = new V2MutationOptions();
        var command = new Command("delete", "Preview, apply or resume deletion of owned Sandbox data")
        {
            sandboxId, preview, planId, originalCommand, expected,
        };
        mutation.AddTo(command);
        V2Cli.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var sandbox = V2Cli.ReadId(result.GetValue(sandboxId), "Sandbox ID");
            string? plan = result.GetValue(planId);
            string? original = result.GetValue(originalCommand);
            long? revision = result.GetValue(expected);
            if (result.GetValue(preview))
            {
                if (plan is not null || original is not null || revision is not null || mutation.IsReplay(result))
                {
                    throw new UsageException("--plan-only takes just the Sandbox ID and display options.");
                }

                return await PlanDeleteAsync(cli, sandbox, cancellationToken).ConfigureAwait(false);
            }

            if ((plan is null) == (original is null) || revision is null)
            {
                throw new UsageException("Use --plan-only, or select exactly one of --plan and --resume with --expected-revision.");
            }

            var sandboxRevision = PositiveRevision(revision.Value);
            var selectedPlan = plan is null ? null : V2Cli.ReadId(plan, "Deletion plan ID");
            var resume = original is null ? null : V2Cli.ReadId(original, "Original deletion command ID");
            if (selectedPlan is not null && !await ConfirmDeleteAsync(cli, sandbox, selectedPlan, sandboxRevision, cancellationToken).ConfigureAwait(false))
            {
                return V2Cli.Fail(cli, V2Cli.Error(ErrorCategory.Validation, "invalid_argument", "sandbox_deletion_confirmation_declined"));
            }

            await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
            using var connection = session.PinConnection();
            var deadline = cli.Deadline(UnaryDeadline);
            var identity = await mutation.BeginAsync(result, session, deadline, cancellationToken).ConfigureAwait(false);
            if (identity.CommandId.Equals(resume))
            {
                throw new UsageException("A deletion successor command ID must differ from the original deletion command ID.");
            }

            identity.Meta.ExpectedRev = sandboxRevision;
            var request = new SandboxServiceDeleteRequest
            {
                Meta = identity.Meta,
                OwnerEpoch = identity.OwnerEpoch,
                SandboxId = sandbox,
                PlanId = selectedPlan,
                ResumeCommandId = resume,
            };
            cancellationToken.ThrowIfCancellationRequested();
            var response = await V2Cli.SendAsync(cli, DeleteMethod, identity,
                () => session.Sandboxes.DeleteAsync(request, deadline: deadline, cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (!identity.Meta.CorrelationId.Equals(response.Meta?.CorrelationId))
            {
                return V2Cli.Fail(cli, V2Cli.UnknownEffect("deletion_response_unconfirmed", identity.Meta.CorrelationId), identity);
            }

            return PrintDeletion(cli, sandbox, V2Cli.Require(response.Value, response.Error, identity), identity);
        });
        return command;
    }

    private static async Task<int> PlanDeleteAsync(Cli cli, Id sandbox, CancellationToken cancellationToken)
    {
        await using var session = await V2CliSession.OpenAsync(cli, cancellationToken).ConfigureAwait(false);
        var request = new SandboxServicePlanDeleteRequest { Meta = Cli.Meta(), SandboxId = sandbox };
        using var call = session.Sandboxes.PlanDeleteAsync(request, deadline: cli.Deadline(UnaryDeadline), cancellationToken: cancellationToken);
        var response = await call.ResponseAsync.ConfigureAwait(false);
        if (request.Meta.CorrelationId.Equals(response.Meta?.CorrelationId))
        {
            var value = V2Cli.Require(response.Value, response.Error);
            if (V2Shapes.IsValid(value.Plan) && sandbox.Equals(value.Plan.SandboxId))
            {
                return V2Cli.Print(cli, value);
            }
        }

        return V2Cli.Fail(cli, V2Cli.Error(ErrorCategory.State, "node_unavailable", "deletion_plan_response_unconfirmed"));
    }

    private static async Task<bool> ConfirmDeleteAsync(Cli cli, Id sandbox, Id plan, Revision revision, CancellationToken cancellationToken)
    {
        if (cli.Yes)
        {
            return true;
        }

        if (cli.Output.Json || Console.IsInputRedirected || Console.IsErrorRedirected)
        {
            throw new UsageException("Review the deletion plan and pass --yes to confirm it in a non-interactive command.");
        }

        string sandboxText = IdText.Format(sandbox);
        cli.Output.Error.WriteLine(FormattableString.Invariant(
            $"Delete owned data for local Sandbox {sandboxText} using reviewed plan {IdText.Format(plan)} at revision {revision.Value}?"));
        cli.Output.Error.WriteLine("Type the Sandbox ID to confirm.");
        var answer = await Console.In.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        return string.Equals(answer?.Trim(), sandboxText, StringComparison.OrdinalIgnoreCase);
    }

    private static int PrintDeletion(Cli cli, Id sandbox, SandboxServiceDeleteValue value, V2CommandIdentity identity)
    {
        var operation = value.Operation;
        if (!V2Shapes.IsValid(operation) || !identity.CommandId.Equals(operation.CommandId) || !identity.OwnerEpoch.Equals(operation.OwnerEpoch)
            || !sandbox.Equals(operation.AggregateId) || operation.Method != DeleteMethod)
        {
            return V2Cli.Fail(cli, V2Cli.UnknownEffect("deletion_receipt_unconfirmed", identity.Meta.CorrelationId), identity);
        }

        if (operation.ResponseCompacted)
        {
            var compacted = V2Cli.Error(ErrorCategory.State, "receipt_compacted", "original_response_compacted");
            compacted.Effect = operation.Effect;
            compacted.Retry.ReconciliationOperation = "NodeService.GetOperation";
            return V2Cli.Fail(cli, compacted, identity, value);
        }

        if (operation.State is OperationState.Accepted or OperationState.Succeeded)
        {
            return V2Cli.Print(cli, value, identity);
        }

        if (operation.Effect == EffectCertainty.Unknown)
        {
            return V2Cli.Fail(cli, operation.Error is { Effect: EffectCertainty.Unknown } failure ? failure
                : V2Cli.UnknownEffect("deletion_effect_unconfirmed", identity.Meta.CorrelationId), identity, value);
        }

        var error = operation.Error?.Clone() ?? V2Cli.Error(ErrorCategory.State, "busy", "deletion_did_not_complete");
        error.Effect = operation.Effect;
        return V2Cli.Fail(cli, error, identity, value);
    }

    internal static async Task<Sandbox> InspectAsync(V2CliSession session, Id id, DateTime deadline, CancellationToken cancellationToken)
    {
        using var call = session.Sandboxes.InspectAsync(new SandboxServiceInspectRequest { Meta = Cli.Meta(), SandboxId = id },
            deadline: deadline, cancellationToken: cancellationToken);
        var response = await call.ResponseAsync.ConfigureAwait(false);
        var sandbox = V2Cli.Require(response.Value, response.Error).Sandbox;
        return V2Cli.Require(id.Equals(sandbox?.SandboxId) ? sandbox : null, null);
    }

    internal static Revision PositiveRevision(long value) => value is > 0 and < long.MaxValue
        ? new Revision { Value = value }
        : throw new UsageException("--expected-revision must be a positive revision below the maximum signed 64-bit value.");

    internal static uint PageSize(uint size) => size is >= 1 and <= 200 ? size
        : throw new UsageException("--limit must be from 1 to 200.");

    private static void RedactEnvironment(Sandbox? sandbox)
    {
        if (sandbox?.Config is not { } config)
        {
            return;
        }

        foreach (var entry in config.Environment)
        {
            entry.ClearValue();
            entry.ClearSecretRef();
        }
    }

    private static Argument<string> SandboxId() => new("id") { Description = "Sandbox ID" };

    private static Option<string> ConfigFile() => new("--file") { Required = true, Description = "Path to the complete Sandbox JSON configuration" };
}
