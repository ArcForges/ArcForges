// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store.Migrations;
using ArcForges.Tests;
using Microsoft.Win32.SafeHandles;
using ProcessIdentity = ArcForges.Tests.ProcessIdentity;

namespace ArcForges.Node.Store.Tests;

public sealed class MigrationContractionNativeScopeTests
{
    private const string NativeRefusal = "node_contraction_native_scope_refused: ";
    private static readonly TimeSpan CommandBound = TimeSpan.FromSeconds(10);

    [Fact(Timeout = 90_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [Trait("env", "windows-real")]
    public async Task AFinishedAttemptWithALiveWindowsJobCannotBeContracted()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Requires the Windows Job API."); return; }
        using var root = new TemporaryDataRoot();
        string name = SeedFinishedAttempt(root, windows: true);
        string[] before = StoreInventory(root);
        nint kernel = NativeLibrary.Load("kernel32.dll", typeof(MigrationContractionNativeScopeTests).Assembly, DllImportSearchPath.System32);
        try
        {
            var createJob = Marshal.GetDelegateForFunctionPointer<CreateJob>(NativeLibrary.GetExport(kernel, "CreateJobObjectW"));
            var assignJob = Marshal.GetDelegateForFunctionPointer<AssignJob>(NativeLibrary.GetExport(kernel, "AssignProcessToJobObject"));
            using var job = createJob(0, name);
            int createError = Marshal.GetLastPInvokeError();
            Assert.False(job.IsInvalid, $"CreateJobObjectW failed with {createError}.");
            Assert.NotEqual(183, createError); // ERROR_ALREADY_EXISTS: this test must own the new job.

            using var child = Process.Start(new ProcessStartInfo(
                Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
                ["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 60"]) { UseShellExecute = false, CreateNoWindow = true })!;
            try
            {
                Assert.True(assignJob(job, child.SafeHandle), $"AssignProcessToJobObject failed with {Marshal.GetLastPInvokeError()}.");
                Assert.False(child.HasExited);
                RequireRefusal(root, before, "legacy_windows_job_live_or_unconfirmed");
                Assert.False(child.HasExited);
            }
            finally
            {
                if (!child.HasExited)
                {
                    child.Kill();
                }

                using var cleanup = new CancellationTokenSource(CommandBound);
                await child.WaitForExitAsync(cleanup.Token);
            }
        }
        finally
        {
            NativeLibrary.Free(kernel);
        }

        RequireReleasedScope(root, before);
    }

    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [Trait("env", "linux-real")]
    public async Task AFinishedAttemptWithALiveLinuxUnitCannotBeContracted()
    {
        if (!OperatingSystem.IsLinux()) { Assert.Skip("Requires the Linux systemd user manager."); return; }
        string? skip = SystemdTestEnvironment.SkipReason;
        Assert.SkipWhen(skip is not null, skip ?? string.Empty);
        using var root = new TemporaryDataRoot();
        string unit = SeedFinishedAttempt(root, windows: false);
        using (var lease = new FileStream(Path.Combine(root.Path, "node.lock"), new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        }))
        {
        }

        string[] before = StoreInventory(root);
        string description = "ArcForges migration fixture " + Guid.NewGuid().ToString("N");
        Assert.Equal("not-found", SystemdTestEnvironment.Property(unit, "LoadState"));
        string? invocation = null;
        ProcessIdentity? identity = null;
        try
        {
            await StartLinuxUnitAsync(unit, description, TestContext.Current.CancellationToken);
            Assert.Equal(description, SystemdTestEnvironment.Property(unit, "Description"));
            invocation = SystemdTestEnvironment.Property(unit, "InvocationID");
            Assert.True(Guid.TryParseExact(invocation, "N", out var unitId) && unitId != Guid.Empty);
            int pid = int.Parse(SystemdTestEnvironment.Property(unit, "MainPID"), CultureInfo.InvariantCulture);
            identity = Assert.IsType<ProcessIdentity>(ProcessIdentity.Capture(pid));
            string cgroup = Assert.IsType<string>(SystemdTestEnvironment.CgroupDirectory(unit));
            Assert.EndsWith("/" + unit, cgroup, StringComparison.Ordinal);
            Assert.Contains(pid.ToString(CultureInfo.InvariantCulture), File.ReadLines(Path.Combine(cgroup, "cgroup.procs")));
            RequireRefusal(root, before, "legacy_unit_live_or_unconfirmed");
            Assert.True(identity.Value.IsRunning());
        }
        finally
        {
            if (SystemdTestEnvironment.Property(unit, "Description") == description &&
                (invocation is null || SystemdTestEnvironment.Property(unit, "InvocationID") == invocation))
            {
                var (exit, diagnostic) = SystemdTestEnvironment.Systemctl("stop", "--", unit);
                Assert.True(exit == 0, diagnostic);
            }
        }

        Assert.False(Assert.IsType<ProcessIdentity>(identity).IsRunning());
        RequireReleasedScope(root, before);
    }

    private static string SeedFinishedAttempt(TemporaryDataRoot root, bool windows)
    {
        var clock = new ManualClock();
        string boot = NodeContractionScope.ReadCurrentBootIdentity();
        using var store = root.Open(clock, StoreMigrations.Expanded, boot);
        Assert.Equal(19, store.Metadata.SchemaVersion);
        byte[] node = store.Metadata.NodeId.ToArray();
        byte[] attempt = StoreIds.NewUuid7(clock);
        string container = windows
            ? @"Local\ArcForges." + LegacyId(node) + "." + LegacyId(attempt)
            : "arcforges-a-" + LegacyId(attempt) + ".service";
        store.Write(tx =>
        {
            byte[] task = Rows.InsertTask(tx, spec: new TaskSpec { Title = "Native contraction fixture" });
            tx.Execute("UPDATE task SET state=$state WHERE task_id=$task;", ("$state", (int)TaskState.Succeeded), ("$task", task));
            tx.Execute("""
                INSERT INTO attempt(attempt_id,task_id,number,kind,state,executor_node_id,container_name,boot_identity,
                    request_cpu_millicores,request_mem_expected_bytes,request_mem_ceiling_bytes,request_source,
                    accounted_mem_bytes,created_at,finished_at,termination_reason,effect,rev)
                VALUES($attempt,$task,1,1,$state,$node,$container,$boot,25,1024,2048,1,1024,0,1,$reason,$effect,0);
                """, ("$attempt", attempt), ("$task", task), ("$state", (int)AttemptState.Finished), ("$node", node),
                ("$container", container), ("$boot", boot), ("$reason", (int)TerminationReason.Exited), ("$effect", (int)EffectCertainty.Happened));
        }, CommitDurability.Full);
        return container;
    }

    private static void RequireRefusal(TemporaryDataRoot root, string[] before, string reason)
    {
        var refusal = Assert.Throws<StoreIncompatibleException>(() => NodeContractionScope.Acquire(root.Path));
        Assert.Equal(NativeRefusal + reason, refusal.Message);
        Assert.Equal(before, StoreInventory(root));
    }

    private static void RequireReleasedScope(TemporaryDataRoot root, string[] before)
    {
        using var scope = NodeContractionScope.Acquire(root.Path);
        scope.VerifyHeld();
        Assert.Equal(before, StoreInventory(root));
    }

    private static string[] StoreInventory(TemporaryDataRoot root) =>
        [.. Directory.EnumerateFiles(Path.GetDirectoryName(root.Database)!).Order(StringComparer.Ordinal).Select(path =>
        {
            using var file = File.OpenRead(path);
            return Path.GetFileName(path) + " " + Convert.ToHexStringLower(SHA256.HashData(file));
        })];

    private static async Task StartLinuxUnitAsync(string name, string description, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo("/usr/bin/systemd-run",
        [
            "--user", "--quiet", "--service-type=exec", "--unit=" + name, "--description=" + description,
            "--property=Restart=no", "--property=KillMode=control-group", "--", "/usr/bin/sleep", "60",
        ]) { UseShellExecute = false, RedirectStandardError = true };
        using var child = Process.Start(start)!;
        using var bound = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bound.CancelAfter(CommandBound);
        var error = child.StandardError.ReadToEndAsync(bound.Token);
        try
        {
            await child.WaitForExitAsync(bound.Token);
            Assert.True(child.ExitCode == 0, await error);
        }
        catch (OperationCanceledException)
        {
            if (!child.HasExited)
            {
                child.Kill();
            }

            throw;
        }
    }

    // The predecessor names its native scopes with the 26-character Crockford representation of each UUID.
    private static string LegacyId(byte[] id)
    {
        var value = new UInt128(BinaryPrimitives.ReadUInt64BigEndian(id), BinaryPrimitives.ReadUInt64BigEndian(id.AsSpan(8)));
        Span<char> text = stackalloc char[26];
        for (int index = text.Length - 1; index >= 0; index--, value >>= 5)
        {
            text[index] = "0123456789abcdefghjkmnpqrstvwxyz"[(int)(value & 31)];
        }

        return new string(text);
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate SafeFileHandle CreateJob(nint attributes, string name);

    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool AssignJob(SafeFileHandle job, SafeProcessHandle process);
}
