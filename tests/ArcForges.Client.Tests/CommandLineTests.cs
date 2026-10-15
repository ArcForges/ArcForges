// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Text.Json;
using ArcForges.CommandLine;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.Client.Tests;

/// <summary>The CLI grammar, global options, output modes, exit codes and completion (experience/cli.md).</summary>
public sealed class CommandLineTests
{
    private static readonly NodeRunner NoNode = (_, _) => throw new InvalidOperationException("These tests never run the node role.");

    [Fact]
    public void TheClientTimeoutHandOffCountsFromTheCliStart()
    {
        // The caller's timer started with the CLI: connecting, an auto-start and the submission use part of the budget (cli.md, run).
        using var self = System.Diagnostics.Process.GetCurrentProcess();
        var started = self.StartTime.ToUniversalTime();
        var at = RunCommand.HandoffAt(TimeSpan.FromMinutes(10));
        Assert.Equal(started + TimeSpan.FromMinutes(10) - RunCommand.HandoffMargin, at);
        Assert.Equal(started, RunCommand.HandoffAt(TimeSpan.FromSeconds(10)));
        Assert.True(RunCommand.HandoffAt(TimeSpan.FromMinutes(10)) < DateTime.UtcNow + TimeSpan.FromMinutes(10) - RunCommand.HandoffMargin,
            "The hand-off time does not restart when the attach begins.");
    }

    [Theory]
    [InlineData("status")]
    [InlineData("status --json")]
    [InlineData("--json status")]
    [InlineData("-q -v --no-color -y --timeout 30s status")]
    [InlineData("node run --background")]
    [InlineData("node run --systemd")]
    [InlineData("node stop --cancel-running --timeout 2m --reason upgrade")]
    [InlineData("node wait-ready --timeout 30s")]
    [InlineData("node info")]
    [InlineData("node health --json")]
    [InlineData("node capabilities --reevaluate")]
    [InlineData("node rename build-box")]
    [InlineData("config list")]
    [InlineData("config get logLevel")]
    [InlineData("config set telemetryOptIn false")]
    [InlineData("events --topic node --topic jobs --since v1.2.40")]
    [InlineData("jobs list --state running --state pending --limit 20")]
    [InlineData("jobs show 01m4zr")]
    [InlineData("jobs cancel 01m4zrxnr8e7d81pn7xnwfqw14")]
    [InlineData("version")]
    [InlineData("completion bash")]
    [InlineData("status --test-mode")]
    public void TheSpecifiedGrammarParses(string line)
    {
        var result = Root().Parse(line.Split(' '));
        Assert.Empty(result.Errors);
    }

    [Theory]
    [InlineData("frobnicate")]
    [InlineData("node rename")]
    [InlineData("config get colour")]
    [InlineData("events --topic everything")]
    [InlineData("jobs list --state lost")]
    [InlineData("completion tcsh")]
    [InlineData("status --bogus")]
    public async Task UsageErrorsExitWithTwo(string line)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exit = await CliApplication.RunAsync(line.Split(' '), NoNode, output, error);

        Assert.Equal(ExitCodes.Usage, exit);
        Assert.StartsWith("error: ", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task AnInvalidDurationIsAUsageError()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exit = await CliApplication.RunAsync(["--timeout", "soon", "version"], NoNode, output, error);

        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("--timeout", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ACommandIsRequired()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(ExitCodes.Usage, await CliApplication.RunAsync([], NoNode, output, error));
    }

    [Fact]
    public async Task HelpAndVersionSucceedWithoutANode()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        Assert.Equal(0, await CliApplication.RunAsync(["--help"], NoNode, output, error));
        Assert.Contains("status", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("--test-mode", output.ToString(), StringComparison.Ordinal);
        using var version = new StringWriter();
        Assert.Equal(0, await CliApplication.RunAsync(["--version"], NoNode, version, error));
        Assert.Equal(NodeContract.ProductVersion, version.ToString().Trim());
    }

    [Theory]
    [InlineData("90s", 90)]
    [InlineData("5m", 300)]
    [InlineData("2h", 7200)]
    [InlineData("1d", 86_400)]
    public void DurationsParse(string text, int seconds)
    {
        Assert.True(Durations.TryParse(text, out var duration));
        Assert.Equal(TimeSpan.FromSeconds(seconds), duration);
    }

    [Theory]
    [InlineData("")]
    [InlineData("5")]
    [InlineData("0s")]
    [InlineData("-5s")]
    [InlineData("5w")]
    [InlineData("1.5h")]
    public void InvalidDurationsAreRefused(string text) => Assert.False(Durations.TryParse(text, out _));

    [Theory]
    [InlineData(ErrorCategory.Validation, "invalid_argument", ExitCodes.Usage)]
    [InlineData(ErrorCategory.Validation, "invalid_cursor", ExitCodes.Usage)]
    [InlineData(ErrorCategory.State, "not_found", ExitCodes.NotFound)]
    [InlineData(ErrorCategory.Authorization, "permission_denied", ExitCodes.PermissionDenied)]
    [InlineData(ErrorCategory.Authorization, "approval_required", ExitCodes.ApprovalPending)]
    [InlineData(ErrorCategory.Conflict, "revision_conflict", ExitCodes.Conflict)]
    [InlineData(ErrorCategory.Conflict, "command_id_reused", ExitCodes.Conflict)]
    [InlineData(ErrorCategory.Entitlement, "feature_not_entitled", ExitCodes.EntitlementRequired)]
    [InlineData(ErrorCategory.State, "invalid_state", ExitCodes.Failed)]
    [InlineData(ErrorCategory.State, "node_stopping", ExitCodes.Failed)]
    public void NodeErrorsMapToTheSpecifiedExitCodes(ErrorCategory category, string code, int exit) =>
        Assert.Equal(exit, ExitCodes.For(new ArcError { Category = category, Code = code }));

    [Theory]
    [InlineData(NodeUnavailableReason.NotRunning, 75)]
    [InlineData(NodeUnavailableReason.AutoStartRefused, 75)]
    [InlineData(NodeUnavailableReason.AutoStartFailed, 75)]
    [InlineData(NodeUnavailableReason.NotReady, 75)]
    [InlineData(NodeUnavailableReason.Busy, 75)]
    [InlineData(NodeUnavailableReason.AccessDenied, 5)]
    [InlineData(NodeUnavailableReason.Incompatible, 1)]
    public void UnreachableNodesMapToTheSpecifiedExitCodes(NodeUnavailableReason reason, int exit) =>
        Assert.Equal(exit, ExitCodes.For(new NodeUnavailableException(reason, "x", "y")));

    [Fact]
    public void TheRefusedAutoStartPrintsTheSpecifiedGuidance()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var cli = new CliOutput(output, error, json: false, quiet: false, color: false, verbose: false, width: 120);

        var exit = cli.Fail(new NodeUnavailableException(NodeUnavailableReason.AutoStartRefused, "refused (CI job (CI))", "ignored"));

        Assert.Equal(75, exit);
        Assert.Equal("arcforges: node not running; start it with 'arcforges node run --background' or the Desktop" + Environment.NewLine, error.ToString());
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public void AnUnreachableNodeInJsonModePrintsOnlyTheErrorObject()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var cli = new CliOutput(output, error, json: true, quiet: false, color: false, verbose: false, width: 120);

        var exit = cli.Fail(new NodeUnavailableException(NodeUnavailableReason.AutoStartRefused, "refused (CI job (CI))", "ignored"));

        // cli.md section 2: stdout is exactly {"error": <ArcError JSON>}; nothing beside it.
        Assert.Equal(75, exit);
        using var document = System.Text.Json.JsonDocument.Parse(output.ToString());
        var property = Assert.Single(document.RootElement.EnumerateObject());
        Assert.Equal("error", property.Name);
        Assert.Equal("node_not_running", property.Value.GetProperty("code").GetString());
        Assert.Equal("error.state.node_not_running", property.Value.GetProperty("messageKey").GetString());
        Assert.Contains("node not running", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void ABusyNodeInJsonModeIsOverloadedNotNotRunning()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var cli = new CliOutput(output, error, json: true, quiet: false, color: false, verbose: false, width: 120);

        var exit = cli.Fail(new NodeUnavailableException(NodeUnavailableReason.Busy, "the node is busy", "retry later"));

        Assert.Equal(75, exit);
        using var document = System.Text.Json.JsonDocument.Parse(output.ToString());
        var json = document.RootElement.GetProperty("error");
        Assert.Equal("overloaded", json.GetProperty("code").GetString());
        Assert.Equal("ERROR_CATEGORY_RESOURCE", json.GetProperty("category").GetString());
        Assert.Equal("RETRY_MODE_AFTER_TIME", json.GetProperty("retry").GetProperty("mode").GetString());
        Assert.Contains("busy", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void ErrorsGoToStderrInHumanModeAndToStdoutAsJson()
    {
        var correlation = CommandIds.New();
        var error = new ArcError
        {
            Category = ErrorCategory.State,
            Code = "not_found",
            Details = new ErrorDetails { State = new StateFailure { Reason = "job" } },
        };
        using (var output = new StringWriter())
        using (var stderr = new StringWriter())
        {
            var exit = new CliOutput(output, stderr, json: false, quiet: false, color: false, verbose: false, width: 120).Fail(error, correlation);
            Assert.Equal(4, exit);
            Assert.Equal($"error: not found: job (STATE/not_found, correlation {IdText.Format(correlation)})" + Environment.NewLine, stderr.ToString());
            Assert.Equal(string.Empty, output.ToString());
        }

        using (var output = new StringWriter())
        using (var stderr = new StringWriter())
        {
            new CliOutput(output, stderr, json: true, quiet: false, color: false, verbose: false, width: 120).Fail(error, correlation);
            using var document = JsonDocument.Parse(output.ToString());
            Assert.Equal("not_found", document.RootElement.GetProperty("error").GetProperty("code").GetString());
            Assert.Equal("ERROR_CATEGORY_STATE", document.RootElement.GetProperty("error").GetProperty("category").GetString());
            Assert.Equal(string.Empty, stderr.ToString());
        }
    }

    [Fact]
    public void JsonUsesTheCanonicalMappingWithBase32Ids()
    {
        var id = CommandIds.New();
        var job = new JobView { JobId = id, Kind = JobKind.Doctor, State = JobState.Running };
        job.RequestedBy = new ActorRef { Origin = Origin.Human, SessionId = id };
        var value = new NodeServiceListJobsValue { Jobs = { job } };

        var node = CliOutput.ToJsonNode(value);

        Assert.Equal(IdText.Format(id), node["jobs"]![0]!["jobId"]!.GetValue<string>());
        Assert.Equal(IdText.Format(id), node["jobs"]![0]!["requestedBy"]!["sessionId"]!.GetValue<string>());
        Assert.Equal("JOB_STATE_RUNNING", node["jobs"]![0]!["state"]!.GetValue<string>());
        Assert.Equal("JOB_KIND_DOCTOR", node["jobs"]![0]!["kind"]!.GetValue<string>());
        Assert.Null(node["page"]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TheFastNodeInfoWriterEmitsTheCanonicalMapping(bool full)
    {
        var info = new NodeInfo { Node = new NodeRef { NodeId = CommandIds.New(), Name = "box" }, State = NodeLifecycleState.Degraded };
        if (full)
        {
            info.Node.Role = NodeRole.Guest;
            info.Node.HostNodeId = CommandIds.New();
            info.Node.Os = OsFamily.Linux;
            info.Node.Arch = CpuArchitecture.Arm64;
            info.Version = "0.1.0-dev+abc";
            info.ContractMajor = 1;
            info.ContractMinor = 0;
            info.Features.Add("a");
            info.Features.Add("b");
            info.DataRoot = "C:\\data \"root\"";
            info.Endpoint = "arcforges-x-node";
            info.StartedAt = ProtoTime.ToInstant(new DateTimeOffset(1969, 12, 31, 23, 59, 59, TimeSpan.Zero).AddTicks(5));
            info.StoreBytes = ulong.MaxValue;
            info.Capabilities = new CapabilityReport
            {
                Cpu = CpuControl.EnforcedShareAndCap,
                CpuReason = "r1",
                Memory = MemoryControl.EnforcedSoftAndHard,
                MemoryReason = "",
                Pids = ProcessCountControl.ObserveOnly,
                Io = IoControl.Enforced,
                Pause = PauseSupport.Unsupported,
                PauseReason = "windows",
                KillTree = KillTreeGuarantee.BestEffort,
                Adopt = AdoptSupport.Limited,
                RestartSurvival = false,
                RestartSurvivalReason = "x",
                EvaluatedAt = new Instant { UnixSeconds = 0, Nanos = 0 },
                PlatformFacts = { new KeyValue { Name = "os", Value = "Linux" }, new KeyValue { Name = "secret", Redacted = true } },
            };
            info.UpdateChannel = "beta";
            info.AccountLinked = false;
            info.LanEnabled = true;
            info.GuestLinks = 0;
            info.Edition = Edition.Pro;
            info.State = (NodeLifecycleState)99;
        }

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            NodeInfoJson.Write(writer, info);
        }

        var fast = System.Text.Json.Nodes.JsonNode.Parse(buffer.ToArray());
        var canonical = CliOutput.ToJsonNode(info);
        Assert.True(System.Text.Json.Nodes.JsonNode.DeepEquals(canonical, fast), $"canonical {canonical!.ToJsonString()} fast {fast!.ToJsonString()}");
    }

    [Fact]
    public void NarrowTerminalsGetKeyValueLinesAndStatesCarryWords()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var narrow = new CliOutput(output, error, json: false, quiet: false, color: true, verbose: false, width: 40);

        narrow.Table(["ID", "STATE"], [["abc", "RUNNING"]]);
        narrow.KeyValues([("node", "box")]);

        Assert.Equal("id: abc" + Environment.NewLine + "state: RUNNING" + Environment.NewLine + Environment.NewLine + "node: box" + Environment.NewLine, output.ToString());
        Assert.Equal("\u001b[32mREADY\u001b[0m", narrow.State(NodeLifecycleState.Ready));
        Assert.Equal("READY", new CliOutput(output, error, false, false, color: false, false, 120).State(NodeLifecycleState.Ready));
    }

    [Fact]
    public void WideTablesAlignColumns()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        new CliOutput(output, error, json: false, quiet: false, color: false, verbose: false, width: 120).Table(["ID", "STATE"], [["a", "RUNNING"], ["bbbb", "SUCCEEDED"]]);

        Assert.Equal(["ID    STATE", "a     RUNNING", "bbbb  SUCCEEDED"], output.ToString().TrimEnd().Split(Environment.NewLine));
    }

    [Fact]
    public void QuietSuppressesHumanLinesButNotEssentialOutput()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var quiet = new CliOutput(output, error, json: false, quiet: true, color: false, verbose: false, width: 120);

        quiet.Line("noise");
        quiet.KeyValues([("a", "b")]);
        quiet.Essential("01m4zr");

        Assert.Equal("01m4zr" + Environment.NewLine, output.ToString());
    }

    [Theory]
    [InlineData("bash", "complete -o default -F _arcforges_complete arcforges")]
    [InlineData("zsh", "compdef _arcforges arcforges")]
    [InlineData("fish", "complete -c arcforges -f -a '(__arcforges_complete)'")]
    [InlineData("pwsh", "Register-ArgumentCompleter -Native -CommandName arcforges, arcforges.exe")]
    public async Task CompletionScriptsRegisterForEachShell(string shell, string registration)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        Assert.Equal(0, await CliApplication.RunAsync(["completion", shell], NoNode, output, error));
        Assert.Contains(registration, output.ToString(), StringComparison.Ordinal);
        Assert.Contains("[suggest:", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain('\r', output.ToString());
    }

    [Theory]
    [InlineData("arcforges no", "node")]
    [InlineData("arcforges node ", "wait-ready")]
    [InlineData("arcforges config get ", "telemetryOptIn")]
    [InlineData("arcforges events --topic no", "notifications")]
    [InlineData("arcforges completion ", "pwsh")]
    public async Task TheSuggestDirectiveCompletesTheGrammar(string line, string expected)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exit = await CliApplication.RunAsync([$"[suggest:{line.Length}]", line], NoNode, output, error);

        Assert.Equal(0, exit);
        Assert.Contains(expected, output.ToString().Split('\n', StringSplitOptions.TrimEntries));
    }

    private static RootCommand Root()
    {
        var globals = new GlobalOptions();
        return CliApplication.Build(globals, NoNode, TextWriter.Null, TextWriter.Null);
    }
}
