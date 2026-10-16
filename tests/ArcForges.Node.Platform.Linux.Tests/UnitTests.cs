// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Platform.Linux.Tests;

/// <summary>Pure units of the Linux platform: they run on every OS.</summary>
public sealed class UnitTests
{
    private static readonly int[] PriorityWeights = [9, 7, 5, 3, 1];

    [Fact]
    public void SignalNamesFromSystemdMapToNumbers()
    {
        Assert.Equal(9, LinuxRecords.SignalNumber("KILL"));
        Assert.Equal(15, LinuxRecords.SignalNumber("SIGTERM"));
        Assert.Equal(1, LinuxRecords.SignalNumber("HUP"));
        Assert.Equal(3, LinuxRecords.SignalNumber("3"));
        Assert.Equal(0, LinuxRecords.SignalNumber("NOPE"));
        Assert.Equal(0, LinuxRecords.SignalNumber(null));
        Assert.Equal("TERM", LinuxRecords.SignalName(15));
        Assert.Equal("99", LinuxRecords.SignalName(99));
        Assert.Equal(0, LinuxRecords.SignalNumber("65"));
    }

    [Theory]
    [InlineData("RTMIN", 34)]
    [InlineData("SIGRTMIN", 34)]
    [InlineData("RTMIN+3", 37)]
    [InlineData("SIGRTMIN+3", 37)]
    [InlineData("RTMAX", 64)]
    [InlineData("RTMAX-2", 62)]
    [InlineData("40", 40)]
    [InlineData("RTMIN+31", 0)]
    [InlineData("RTMIN-1", 0)]
    [InlineData("RTMINX", 0)]
    public void RealTimeSignalsMapToTheGlibcNumbers(string name, int number)
    {
        // systemd writes real-time signals in $EXIT_STATUS as RTMIN+n; a stop_signal may use either end. glibc's SIGRTMIN is 34, SIGRTMAX 64.
        Assert.Equal(number, LinuxRecords.SignalNumber(name));
        if (number > 0)
        {
            Assert.Equal(number, LinuxRecords.SignalNumber(LinuxRecords.SignalName(number)));
        }
    }

    [Theory]
    [InlineData(1334, 1334, "9", "/usr/lib/systemd/systemd-executor", true)] // systemd 255.4: the executor, named "9", exe readable
    [InlineData(1334, 1334, "systemd-executo", "/usr/lib/systemd/systemd-executor (deleted)", true)]
    [InlineData(232, 232, "systemd", null, true)] // systemd 257: a fork of the manager, exe unreadable
    [InlineData(232, 232, "(arcforges)", null, true)] // a fork renamed before its execve
    [InlineData(232, 232, "sleep", "/usr/bin/sleep", false)] // a paused attempt's own main process
    [InlineData(232, 232, "systemd", "/usr/local/bin/systemd", false)] // an attempt command merely named systemd
    [InlineData(232, 232, "(x)", "/usr/bin/x", false)]
    [InlineData(232, 232, "9", null, false)] // an unreadable process with another name
    [InlineData(500, 232, "9", "/usr/lib/systemd/systemd-executor", false)] // not the manager's child
    [InlineData(232, 0, "systemd", null, false)] // the manager is unknown
    [SupportedOSPlatform("linux")]
    public void TheManagersSpawnIsRecognizedStructurally(int parent, int manager, string name, string? executable, bool spawn)
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "The Linux platform.");
        Assert.Equal(spawn, UnitControl.IsManagerSpawn(parent, manager, name, executable));
    }

    [Fact]
    public void AKilledResultWithAnUnknownSignalIsNeverASuccess()
    {
        var record = LinuxRecords.FromServiceEnvironment("a1", "killed", "RTMIN", "success", null, null, DateTimeOffset.UnixEpoch);
        Assert.Equal(("killed", 34), (record.ExitCodeKind, record.ExitStatus));
    }

    [Fact]
    [SupportedOSPlatform("linux")]
    public void TheUnitEnvironmentAlwaysSetsTheCarrierAndCarriesACallersOwnCarrierVariable()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "The Linux platform.");
        Assert.Equal(["A=1", ExecLaunchRole.CarrierVariable + "="], LinuxExecutionPlatform.UnitEnvironment(["A=1"]));
        var unit = LinuxExecutionPlatform.UnitEnvironment(["A=1", ExecLaunchRole.CarrierVariable + "=caller's own"]);
        Assert.Equal(2, unit.Length);
        Assert.Equal("A=1", unit[0]);
        var carried = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(unit[1][(ExecLaunchRole.CarrierVariable.Length + 1)..]));
        Assert.Equal(ExecLaunchRole.CarrierVariable + "=caller's own", carried);
    }

    [Theory]
    [InlineData("exited", "0", "success", "exited", 0, "success")]
    [InlineData("exited", "3", "success", "exited", 3, "exit-code")]
    [InlineData("killed", "TERM", "success", "killed", 15, "signal")]
    [InlineData("dumped", "SEGV", "core-dump", "dumped", 11, "core-dump")]
    [InlineData("killed", "KILL", "oom-kill", "killed", 9, "oom-kill")]
    [InlineData(null, null, null, "exited", -1, "exit-code")]
    public void TheExitRecordTakesTheResultFromExitCodeAndExitStatus(string? code, string? status, string? result, string kind, int value, string serviceResult)
    {
        // Every exit status is a success status of the unit (so its end steps run), which makes SERVICE_RESULT 'success' for ordinary exits.
        var record = LinuxRecords.FromServiceEnvironment("A", code, status, result, null, null, DateTimeOffset.UnixEpoch);
        Assert.Equal(kind, record.ExitCodeKind);
        Assert.Equal(value, record.ExitStatus);
        Assert.Equal(serviceResult, record.ServiceResult);
        Assert.Equal("exit-record", record.RecordedBy);
    }

    [Fact]
    public void TheAccountingAndTheLeftoversGoIntoTheExitRecord()
    {
        var accounting = new CgroupAccounting(120, 30, 64L << 20, 1 << 20, 0, 4096, 8192, 0, 2, 1, 1, 0);
        var record = LinuxRecords.FromServiceEnvironment("A", "killed", "KILL", "success", accounting, new StopRecord { Leftovers = ["sleep", "sleep"] },
            DateTimeOffset.UnixEpoch);
        Assert.Equal(120, record.CpuUserMs);
        Assert.Equal(30, record.CpuKernelMs);
        Assert.Equal(64L << 20, record.MemPeakBytes);
        Assert.Equal(0, record.SwapPeakBytes);
        Assert.Equal(4096, record.IoReadBytes);
        Assert.Equal(1, record.OomKills);
        Assert.Equal(["memory_high", "memory_max", "oom_kill"], record.LimitViolations);
        Assert.Equal(["sleep", "sleep"], record.LeftoversTerminated);
    }

    [Fact]
    public void AFailedUnitIsRecordedFromItsOwnProperties()
    {
        var state = new UnitState("failed", "failed", "oom-kill", 0, string.Empty, 2, 9, 64UL << 20, 0, 1_500_000_000, 0, 1234, 0);
        var record = LinuxRecords.FromUnit("A", state, null, DateTimeOffset.UnixEpoch);
        Assert.Equal("killed", record.ExitCodeKind);
        Assert.Equal(9, record.ExitStatus);
        Assert.Equal("oom-kill", record.ServiceResult);
        Assert.Equal("unit", record.RecordedBy);
        Assert.Equal(1, record.OomKills);
        Assert.Equal(64L << 20, record.MemPeakBytes);
        Assert.Equal(1500, record.CpuUserMs);
    }

    [Fact]
    public void AWaitStatusDecodesToExitedOrSignalled()
    {
        Assert.Equal(("exited", 3), Kind(LinuxRecords.FromWaitStatus("A", 3 << 8, [], DateTimeOffset.UnixEpoch)));
        Assert.Equal(("killed", 15), Kind(LinuxRecords.FromWaitStatus("A", 15, [], DateTimeOffset.UnixEpoch)));
        Assert.Equal(("dumped", 11), Kind(LinuxRecords.FromWaitStatus("A", 11 | 0x80, [], DateTimeOffset.UnixEpoch)));
        Assert.Equal("node", LinuxRecords.FromWaitStatus("A", 0, [], DateTimeOffset.UnixEpoch).RecordedBy);

        static (string, int) Kind(ExitRecord record) => (record.ExitCodeKind, record.ExitStatus);
    }

    [Fact]
    [SupportedOSPlatform("linux")]
    public void ThePriorityWeightMapsToCpuWeight()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "The Linux platform.");
        // 03 section 5.2: INTERACTIVE 9, HIGH 7, NORMAL 5, LOW 3, BACKGROUND 1 -> 400, 200, 100, 50, 10.
        Assert.Equal([400, 200, 100, 50, 10], PriorityWeights.Select(LinuxExecutionPlatform.CpuWeight));
    }

    [Fact]
    public void TheRoleArgumentsKeepEverythingAfterTheSeparatorAsTheyAre()
    {
        var parsed = RoleArguments.Parse(["--attempt", "A", "--unset", "X", "--unset", "Y", "--", "prog", "--attempt", "--", "$$"])!;
        Assert.Equal("A", parsed.One("--attempt"));
        Assert.Equal(["X", "Y"], parsed.All("--unset"));
        Assert.Null(parsed.One("--unset"));
        Assert.Equal(["prog", "--attempt", "--", "$$"], parsed.Rest);
        Assert.Null(RoleArguments.Parse(["--attempt"]));
        Assert.Null(RoleArguments.Parse(["attempt", "A"]));
    }

    [Fact]
    public void TheStepsAndStopFilesRoundTripAndOldRecordsStillParse()
    {
        var steps = new StepsFile
        {
            AttemptId = "A",
            LaunchSteps = [new StepSpec { Name = "s", Application = "/bin/true", Argv = ["true", "x"], TimeoutMs = 5 }],
            EndSteps = [new StepSpec { Name = "e", Application = "/bin/false" }],
            LeftoverGraceMs = 1_000,
            EnvironmentNames = ["PATH", "WITH SPACE"],
        };
        var parsed = StepsFile.Parse(steps.ToJson());
        Assert.Equal(["PATH", "WITH SPACE"], parsed.EnvironmentNames);
        Assert.Null(StepsFile.Parse("""{"schema":1,"attempt_id":"A"}""").EnvironmentNames);
        Assert.Equal(["true", "x"], parsed.LaunchSteps[0].Argv);
        Assert.Equal(1_000, parsed.LeftoverGraceMs);
        Assert.Equal(10_000, parsed.EndStepBudgetMs);
        Assert.Contains("\"launch_steps\"", steps.ToJson(), StringComparison.Ordinal);

        var stop = StopRecord.Parse(new StopRecord { AttemptId = "A", Leftovers = ["sleep"], EndSteps = [new StepOutcome { Name = "e", Outcome = "timed_out" }] }.ToJson());
        Assert.Equal("timed_out", stop.EndSteps[0].Outcome);

        // exit.json schema 1 is additive: a Windows record without the Linux fields parses, and the new fields are optional.
        var old = ExitRecord.Parse("""{"schema":1,"attempt_id":"A","exit_code_kind":"exited","exit_status":2,"service_result":"exit-code","recorded_at":"x"}""");
        Assert.Null(old.SwapPeakBytes);
        Assert.Null(old.RecordedBy);
        Assert.DoesNotContain("swap_peak_bytes", old.ToJson(), StringComparison.Ordinal);
    }

    [Fact]
    [SupportedOSPlatform("linux")]
    public void ArgvResolutionFollowsExecvp()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "PATH with colons and execute bits.");
        var root = Directory.CreateTempSubdirectory("arcforges-resolve-").FullName;
        try
        {
            var bin = Directory.CreateDirectory(Path.Combine(root, "bin")).FullName;
            var tool = Path.Combine(bin, "tool");
            File.WriteAllText(tool, "#!/bin/sh\n");
            var local = Path.Combine(root, "local");
            File.WriteAllText(local, "#!/bin/sh\n");
            File.SetUnixFileMode(tool, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            File.SetUnixFileMode(local, UnixFileMode.UserRead | UnixFileMode.UserExecute);

            var environment = new Dictionary<string, string> { ["PATH"] = bin };
            Assert.Equal(tool, LinuxCommands.Resolve("tool", root, environment));
            Assert.Null(LinuxCommands.Resolve("local", root, environment));

            // A program with a slash is taken as it is, relative to the working directory; an empty PATH entry is the working directory.
            Assert.Equal(local, LinuxCommands.Resolve("./local", root, environment));
            Assert.Equal(local, LinuxCommands.Resolve("local", root, new Dictionary<string, string> { ["PATH"] = ":" + bin }));
            Assert.Null(LinuxCommands.Resolve("missing", root, environment));

            var refused = Assert.Throws<CommandRefusedException>(() => LinuxCommands.Prepare(new CommandRequest
            {
                Argv = ["missing"],
                WorkingDirectory = root,
                Environment = environment,
            }));
            Assert.Equal("program_not_found", refused.Code);
            var prepared = LinuxCommands.Prepare(new CommandRequest { Argv = ["tool", "a b", "$$"], WorkingDirectory = root, Environment = environment });
            Assert.Equal(tool, prepared.Application);
            Assert.Equal(["tool", "a b", "$$"], prepared.Argv);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData(ShellKind.Cmd)]
    [InlineData(ShellKind.Powershell)]
    public void WindowsShellsAreRefused(ShellKind kind)
    {
        var refused = Assert.Throws<CommandRefusedException>(() => LinuxCommands.Prepare(new CommandRequest
        {
            Shell = kind,
            Script = "echo",
            WorkingDirectory = Path.GetTempPath(),
            Environment = new Dictionary<string, string>(),
        }));
        Assert.Equal("unsupported_shell", refused.Code);
    }

    [Fact]
    [SupportedOSPlatform("linux")]
    public void ShellScriptsRunThroughShAndLongOnesFromAFile()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "/bin/sh.");
        var environment = new Dictionary<string, string> { ["PATH"] = "/usr/bin:/bin" };
        var inline = LinuxCommands.Prepare(new CommandRequest { Shell = ShellKind.SystemDefault, Script = "echo $HOME", WorkingDirectory = "/", Environment = environment });
        Assert.Equal("/bin/sh", inline.Application);
        Assert.Equal(["sh", "-c", "echo $HOME"], inline.Argv);
        var script = new string('x', LinuxCommands.ScriptInlineLimit + 1);
        var temp = Path.GetTempPath();
        var file = LinuxCommands.Prepare(new CommandRequest { Shell = ShellKind.Sh, Script = script, WorkingDirectory = "/", Environment = environment, TempDirectory = temp });
        Assert.Equal(Path.Combine(temp, "command.sh"), file.ScriptFile);
        Assert.Equal(script, file.ScriptContent);
        Assert.Equal(["sh", Path.Combine(temp, "command.sh")], file.Argv);
    }

    [Fact]
    [SupportedOSPlatform("linux")]
    public void UnitObjectPathsUseSystemdsLabelEscaping()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "The systemd client.");
        Assert.Equal("/org/freedesktop/systemd1/unit/arcforges_2da_2d01m5_2eservice", SystemdManager.UnitPath("arcforges-a-01m5.service"));
        Assert.Equal("/org/freedesktop/systemd1/unit/_31x_2eslice", SystemdManager.UnitPath("1x.slice"));
    }
}
