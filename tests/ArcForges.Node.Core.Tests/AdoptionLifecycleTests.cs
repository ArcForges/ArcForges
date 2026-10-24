// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Tests;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// The ADOPTED task's life (04 section 10; R-RES-013; AF-SEC-01), on the real platform of each operating system: a HUMAN adopts a same-user
/// process outside every container; it is a RUNNING task of kind ADOPTED whose process is labelled ADOPTED. When the process ends by
/// itself the task ends LOST with "no exit status: the node is not the adopted process's parent". After a node restart, an adoption
/// container the node cannot re-open follows the SM-TASK recovery rule "container missing -> LOST": on Windows an adoption job has no holder
/// (L-14), so its name is gone once the node's handle closed, even while the process runs; on Linux the scope is gone once its process ended
/// while the node was down.
/// </summary>
public sealed class AdoptionLifecycleTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 180_000)]
    public async Task AnAdoptedProcessThatEndsByItselfEndsItsTaskLostWithoutAnExitStatus()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequirePlatform();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var pid = StartOutsideAnyContainer();
        try
        {
            var taskId = await AdoptAsync(human, pid);
            var task = await Tasks.GetAsync(human, taskId, full: true);
            Assert.Equal((TaskState.Running, TaskKind.Adopted), (task.State, task.Spec.Kind));
            var listed = await human.Resources.ListProcessesAsync(new ResourceServiceListProcessesRequest
            {
                Meta = new RequestMeta(),
                Filter = new ProcessFilter { Labels = { ProcessLabel.Adopted } },
            }, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
            Assert.Null(listed.Error);
            Assert.Contains(listed.Value.Processes, process => process.Process.Pid == (uint)pid && process.TaskId.Equals(taskId));

            Kill(pid);
            var ended = await Tasks.WaitAsync(human, taskId);
            Assert.Equal((TaskState.Lost, Adoptions.NoExitStatus), (ended.State, ended.StateReason));
        }
        finally
        {
            Kill(pid);
        }
    }

    [Fact(Timeout = 180_000)]
    public async Task AnAdoptionContainerTheNodeCannotReopenAfterARestartIsLost()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequirePlatform();
        await using var node = await InProcessNode.Create().StartAsync();
        var pid = StartOutsideAnyContainer();
        try
        {
            Id taskId;
            await using (var human = await node.ChannelAsync(helloAsHuman: true))
            {
                taskId = await AdoptAsync(human, pid);
                Assert.Equal(TaskState.Running, (await Tasks.GetAsync(human, taskId)).State);
            }

            Assert.Equal(0, await node.StopAsync());
            if (!OperatingSystem.IsWindows())
            {
                // Linux: the scope outlives the node while its process runs; it is gone once the process ended while the node was down.
                Kill(pid);
            }

            await node.StartAsync();
            await using var channel = await node.ChannelAsync(helloAsHuman: true);
            var ended = await Tasks.WaitAsync(channel, taskId);
            Assert.Equal(TaskState.Lost, ended.State);
            Assert.StartsWith(Adoptions.ContainerMissing + ":", ended.StateReason, StringComparison.Ordinal);
        }
        finally
        {
            Kill(pid);
        }
    }

    /// <summary>
    /// Linux (04 section 10; L-29): another user's process is refused with <c>adopt_not_permitted</c> before systemd is asked, while a same-user
    /// process is adopted wherever it runs, outside the user manager's subtree too (this test's own children, when the test runs from a
    /// system service).
    /// </summary>
    [Fact(Timeout = 120_000)]
    public async Task AnotherUsersProcessIsRefusedAndASameUserProcessOutsideTheSubtreeIsAdopted()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux only: adoption through the systemd user manager (04 section 10; L-29).");
        RequirePlatform();
        Assert.SkipWhen(Environment.UserName == "root", "The test runs as root.");
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var refused = await human.Resources.AdoptProcessAsync(new ResourceServiceAdoptProcessRequest { Meta = Tasks.Meta(), Process = ClientProcess.Identity(1) },
            deadline: DateTime.UtcNow.AddSeconds(20), cancellationToken: Ct);
        Assert.Equal("adopt_not_permitted", refused.Error?.Code);
        Assert.Contains("another user", refused.Error!.Details.State.Reason, StringComparison.Ordinal);

        var pid = StartOutsideAnyContainer();
        try
        {
            var before = File.ReadAllText($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/cgroup").Trim();
            var taskId = await AdoptAsync(human, pid);
            var after = File.ReadAllText($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/cgroup").Trim();
            Assert.Contains("/arcforges-x-", after, StringComparison.Ordinal);
            Assert.Equal(TaskState.Running, (await Tasks.GetAsync(human, taskId)).State);
            TestContext.Current.TestOutputHelper?.WriteLine($"cgroup before adoption {before}; after {after}"
                + (before.Contains("/user@", StringComparison.Ordinal) ? string.Empty : " (it was outside the user manager's subtree)"));
        }
        finally
        {
            Kill(pid);
        }
    }

    private static void RequirePlatform() =>
        Assert.SkipWhen(!OperatingSystem.IsWindows() && SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);

    private static async Task<Id> AdoptAsync(NodeChannel human, int pid)
    {
        var identity = ClientProcess.Identity(pid);
        Assert.NotNull(identity);
        var adopted = await human.Resources.AdoptProcessAsync(new ResourceServiceAdoptProcessRequest { Meta = Tasks.Meta(), Process = identity, Title = "adopted by a test" },
            deadline: DateTime.UtcNow.AddSeconds(20), cancellationToken: Ct);
        if (OperatingSystem.IsWindows() && adopted.Error?.Code == "adopt_not_permitted"
            && adopted.Error.Details?.State?.Reason?.Contains("already in a job", StringComparison.Ordinal) == true)
        {
            // 04 section 10 refuses a process in any job; on some machines every process of the session is in one (WMI-created ones too).
            Kill(pid);
            Assert.Skip($"The process this test created through WMI (Win32_Process.Create) is in a job, and 04 section 10 refuses a process in any job: "
                + $"AdoptProcess answered adopt_not_permitted ({adopted.Error.Details.State.Reason}).");
        }

        Assert.True(adopted.Error is null, $"AdoptProcess: {adopted.Error?.Category}/{adopted.Error?.Code} {adopted.Error?.Details}");
        return adopted.Value.TaskId;
    }

    /// <summary>
    /// Starts <c>arcforges-testload hold</c> outside every container: on Linux as a child of the test; on Windows through WMI
    /// <c>Win32_Process.Create</c>, because the test process itself may run in a job (V-W01).
    /// </summary>
    private static int StartOutsideAnyContainer()
    {
        if (!OperatingSystem.IsWindows())
        {
            using var child = Process.Start(new ProcessStartInfo(Tasks.TestLoad, ["hold", "--hold-ms", "150000"]) { RedirectStandardOutput = true })!;
            return child.Id;
        }

        var powerShell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        var line = ("\"" + Tasks.TestLoad + "\" hold --hold-ms 150000").Replace("'", "''", StringComparison.Ordinal);
        using var wmi = Process.Start(new ProcessStartInfo(powerShell, ["-NoProfile", "-NonInteractive", "-Command",
            "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = '" + line + "' }; if ($r.ReturnValue -ne 0) { exit 1 }; $r.ProcessId"])
        {
            RedirectStandardOutput = true,
            CreateNoWindow = true,
        })!;
        var output = wmi.StandardOutput.ReadToEnd();
        Assert.True(wmi.WaitForExit(60_000) && wmi.ExitCode == 0, $"WMI did not create the process: {output}");
        return int.Parse(output.Trim(), NumberStyles.None, CultureInfo.InvariantCulture);
    }

    private static void Kill(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            if (process.ProcessName.StartsWith("arcforges-testl", StringComparison.OrdinalIgnoreCase))
            {
                process.Kill();
                process.WaitForExit(30_000);
            }
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
        }
    }
}
