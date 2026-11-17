// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Mxc.Sdk.V1;

namespace ArcForges.MxcProbe;

internal static class Program
{
    internal const string NativeSource = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2";
    internal const string PackageHash = "d47b1f70c3fcaaed1705a0c3872807e2878fe8c1b778c0dd9eb9325bf421a672";
    internal const string ReleaseHash = "0e832239454ba7fcd338ff56218a287eef4c0a01c1484084b869f55feff8abe9";
    internal static readonly Dictionary<string, string> WindowsNative = new(StringComparer.Ordinal)
    {
        ["mxc_ffi.dll"] = "bd45522f06dc9cc8001dcd5d7320bc2bf303fb08a39bf10f3404bd9a8001812c",
        ["plm.exe"] = "beffc9c9ab974ca9e7455089fd8ecb36eb8c92811ddd1705db91370a689692c3",
        ["wslcsdk.dll"] = "8d4d55d4283fb32a5909b57e78b576d01363d7b28bb9b2595115e80faf61db5b",
        ["wxc-wslc-daemon.exe"] = "84f61c1bc13abde8da1c3f2ff100e6d59368ecaabdbfeca939e6fdb696202d0c",
        ["wxc-exec.exe"] = "090f5d1f7bb93104ab08dcd4e8034ef954aeefcdaf6658dde5f7dff4cfc12f3a",
    };

    public static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--linux-profile")
            return await Linux.LinuxQualification.RunAsync(args[1..]).ConfigureAwait(false);
        if (args.Length == 2 && args[0] == "--linux-owner")
            return await Linux.LinuxQualification.RunOwnerAsync(args[1]).ConfigureAwait(false);
        if (args.Length > 0 && args[0] == "--linux-workload")
            return await Linux.LinuxWorkload.RunAsync(args[1..]).ConfigureAwait(false);
        if (args.Length == 2 && args[0] == "--linux-admission-child")
        {
            if (!OperatingSystem.IsLinux())
            {
                Console.Error.WriteLine("linux_admission_child:linux_host_required");
                return 77;
            }
            return await Linux.LinuxAdmissionCases.RunChildAsync(args[1]).ConfigureAwait(false);
        }
        if (args.Length == 2 && args[0] == "--linux-node-client")
        {
            if (!OperatingSystem.IsLinux())
            {
                Console.Error.WriteLine("linux_node_client:linux_host_required");
                return 77;
            }
            return await Linux.LinuxOwnerChannel.RunNodeClientAsync(args[1]).ConfigureAwait(false);
        }
        var report = new ProbeReport
        {
            Host = Environment.MachineName,
            Os = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            ProcessId = Environment.ProcessId,
            StartedUtc = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture)
        };
        string? reportPath = null;
        try
        {
            if (args.Length != 6 || args[0] != "--manifest" || args[2] != "--work" || args[4] != "--report")
            {
                throw new ArgumentException("Usage: arcforges-mxc-probe --manifest <private-stage/mxc-manifest.json> --work <new-fixture-directory> --report <outside-stage/report.json>");
            }

            reportPath = Path.GetFullPath(args[5]);
            var manifestPath = Path.GetFullPath(args[1]);
            var stage = Path.GetDirectoryName(manifestPath)!;
            var work = Path.GetFullPath(args[3]);
            Require(!IsWithin(reportPath, stage) && !IsWithin(work, stage), "Evidence and fixtures must be outside the immutable stage.");
            Require(!Directory.Exists(work) && !File.Exists(work), "Fixture directory already exists; choose a fresh owned path.");
            ValidateStage(manifestPath);
            report.StageVerified = true;
            Directory.CreateDirectory(work);
            report.ResourceScope = OperatingSystem.IsLinux() ? File.ReadAllText("/proc/self/cgroup").Trim() : "owned outer Job; inherited Job is recorded by the launcher";
            await RunNativeAsync(report, stage, work).ConfigureAwait(false);
            report.Ok = true;
        }
        catch (Exception ex)
        {
            // The request and its environment are deliberately never included in errors.
            report.Failure = ex.GetType().Name + ": " + ex.Message;
        }

        report.FinishedUtc = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        var json = JsonSerializer.Serialize(report, ProbeJson.Default.ProbeReport);
        if (reportPath is not null)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
            await File.WriteAllTextAsync(reportPath, json).ConfigureAwait(false);
        }

        Console.WriteLine(json);
        return report.Ok ? 0 : 1;
    }

    private static bool IsWithin(string path, string root) => path.StartsWith(root + Path.DirectorySeparatorChar, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    internal static void ValidateStage(string path)
    {
        foreach (var key in new[] { "MXC_FFI_DIR", "MXC_FORCE_TIER", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH" })
        {
            Require(string.IsNullOrEmpty(Environment.GetEnvironmentVariable(key)), "Loader/tier override is forbidden: " + key);
        }

        var manifest = JsonSerializer.Deserialize(File.ReadAllText(path), ProbeJson.Default.StageManifest) ?? throw new InvalidDataException("Missing manifest.");
        var rid = OperatingSystem.IsWindows() ? "win-x64" : OperatingSystem.IsLinux() ? "linux-x64" : "unsupported";
        Require(System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.X64 && manifest.Rid == rid, "Unqualified RID.");
        Require(manifest.Version == "1.0.1" && manifest.Schema == "1.0.0" && manifest.Source == NativeSource && manifest.PackageSha256 == PackageHash && manifest.ReleaseSha256 == ReleaseHash, "Incompatible artifact manifest.");
        var stage = Path.GetDirectoryName(path)!;
        Require(Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar).Equals(stage, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal), "Run the published executable inside its verified stage.");
        var actual = Directory.GetFiles(stage, "*", SearchOption.AllDirectories).Select(x => Path.GetRelativePath(stage, x).Replace('\\', '/')).Order(StringComparer.Ordinal).ToArray();
        var expected = manifest.Files.Select(x => x.Path).Append(Path.GetFileName(path)).Order(StringComparer.Ordinal).ToArray();
        Require(actual.SequenceEqual(expected, StringComparer.Ordinal), "Missing or unexpected stage files.");
        Require(expected.Distinct(StringComparer.OrdinalIgnoreCase).Count() == expected.Length, "Duplicate stage member.");
        foreach (var member in manifest.Files)
        {
            Require(!member.Path.Contains('/', StringComparison.Ordinal) && member.Path is not "." and not "..", "Invalid stage member.");
            var file = Path.Combine(stage, member.Path);
            Require((File.GetAttributes(file) & FileAttributes.ReparsePoint) == 0, "Stage symlinks/reparse points are forbidden.");
            using var stream = File.OpenRead(file);
            Require(Convert.ToHexStringLower(SHA256.HashData(stream)) == member.Sha256, "Stage hash mismatch: " + member.Path);
        }

        var native = OperatingSystem.IsWindows() ? WindowsNative : new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["libmxc_ffi.so"] = "18a1cba8f2980af79570141c4eec9cd3982872162ae6b63634d45862913002bc",
        };
        foreach (var member in native)
        {
            Require(manifest.Files.Any(x => x.Path == member.Key && x.Sha256 == member.Value), "Official native unit mismatch: " + member.Key);
        }
    }

    private static async Task RunNativeAsync(ProbeReport report, string stage, string work)
    {
        var watch = Stopwatch.StartNew();
        report.NativeVersion = MxcPlatform.NativeVersion;
        var support = MxcPlatform.GetPlatformSupport();
        report.PlatformSupported = support.IsSupported;
        report.SupportReason = support.Reason;
        report.AvailableMethods = support.AvailableMethods.Select(x => x.ToString()).ToArray();
        report.Backends = MxcPlatform.GetAvailableBackends().Select(x => new BackendReport(x.Backend.ToString(), x.Tier?.ToString(), x.Capabilities.Select(y => y.ToString()).ToArray(), x.Warnings.ToArray())).ToArray();
        report.DiscoveryMs = watch.Elapsed.TotalMilliseconds;
        Require(report.NativeVersion == "1.0.1", "Native version does not match the admitted SDK.");
        Require(report.PlatformSupported, "MXC reports this host unsupported.");
        using (var owner = Process.GetCurrentProcess())
        {
            var cpu = owner.TotalProcessorTime;
            var idle = Stopwatch.StartNew();
            await Task.Delay(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            owner.Refresh();
            report.IdleObservation = new IdleReport(idle.Elapsed.TotalMilliseconds, (owner.TotalProcessorTime - cpu).TotalMilliseconds, owner.WorkingSet64,
                "Probe owner after discovery, before workloads; 1 second idle observation, not a product budget");
        }
        if (OperatingSystem.IsLinux())
        {
            Require(report.AvailableMethods.Contains("Bubblewrap", StringComparer.Ordinal) && report.Backends.Any(x => x.Name == "Bubblewrap"), "Bubblewrap not discovered; no workload started.");
            foreach (var pty in new[] { false, true })
            {
                report.Cases.Add(await LinuxCaseAsync(work, pty).ConfigureAwait(false));
            }

            var cleanup = await LinuxCleanupAsync(work).ConfigureAwait(false);
            report.Cases.Add(cleanup);
            Require(cleanup.Ok, "Linux kill/wait cleanup did not complete within the native deadline.");
        }
        else if (OperatingSystem.IsWindows())
        {
            Require(report.Backends.Any(x => x.Name == "ProcessContainer" && x.Tier == "BaseContainer"), "Native BaseContainer not discovered; no executor workload started.");
            report.Cases.Add(await WindowsLauncher.RunAsync(stage, work).ConfigureAwait(false));
        }
    }

    private static ContainerRequest LinuxRequest(string work, string command) => new(command)
    {
        Containment = new Containment.Bubblewrap(),
        WorkingDirectory = work,
        TimeoutMs = 10_000,
        Environment = new Dictionary<string, string>(StringComparer.Ordinal) { ["PATH"] = "/usr/bin:/bin", ["LANG"] = "C.UTF-8", ["AFV2_SYNTHETIC_SECRET"] = "mxc-probe-secret-not-for-logs" },
        Filesystem = new FilesystemPolicy { ReadwritePaths = { work }, ReadonlyPaths = { "/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache" } },
        Network = new NetworkPolicy { Egress = new NetworkEgressPolicy { Default = NetworkAction.Deny }, Ingress = new NetworkIngressPolicy { Default = NetworkAction.Deny } },
    };

    private static async Task<CaseReport> LinuxCaseAsync(string work, bool pty)
    {
        var watch = Stopwatch.StartNew();
        var marker = pty ? "afv2-pty-ok" : "afv2-pipe-ok";
        var request = LinuxRequest(work, pty ? "test -t 0 && test -t 1 && printf 'afv2-pty-ok\\n'" : "printf 'afv2-pipe-ok\\n'; printf 'afv2-stderr-ok\\n' >&2");
        using MxcProcess process = pty
            ? MxcContainer.SpawnWithPty(request, new SpawnWithPtyOptions { Telemetry = new TelemetryConfig { Enabled = false }, Size = new MxcPtySize(24, 80) })
            : MxcContainer.Spawn(request, new SpawnOptions { Telemetry = new TelemetryConfig { Enabled = false } });
        var pid = process.Id;
        var spawnedMs = watch.Elapsed.TotalMilliseconds;
        using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        process.StandardInput?.Dispose();
        var output = await process.WaitForExitWithOutputAsync(bound.Token).ConfigureAwait(false);
        var stdout = Encoding.UTF8.GetString(output.Stdout);
        var stderr = Encoding.UTF8.GetString(output.Stderr);
        Require(output.Result.ExitCode == 0 && !output.Result.TimedOut && stdout.Contains(marker, StringComparison.Ordinal), "Linux " + (pty ? "PTY" : "pipe") + " native execution failed.");
        Require(pty || stderr.Contains("afv2-stderr-ok", StringComparison.Ordinal), "Pipe stderr was not captured.");
        Require(!stdout.Contains("mxc-probe-secret", StringComparison.Ordinal) && !stderr.Contains("mxc-probe-secret", StringComparison.Ordinal), "Synthetic secret leaked into output.");
        Require(!Directory.Exists("/proc/" + pid.ToString(CultureInfo.InvariantCulture)), "Linux process remains after wait.");
        return new CaseReport(pty ? "linux-pty" : "linux-pipe", true, pid, output.Result.ExitCode, false, spawnedMs, watch.Elapsed.TotalMilliseconds, "official_sdk", "SDK native process ID; wait completed and /proc PID absent", process.Warnings.ToArray());
    }

    private static async Task<CaseReport> LinuxCleanupAsync(string work)
    {
        var watch = Stopwatch.StartNew();
        using var process = MxcContainer.Spawn(LinuxRequest(work, "exec /bin/sleep 5"), new SpawnOptions { Telemetry = new TelemetryConfig { Enabled = false } });
        var pid = process.Id;
        var secretInArgv = OwnedArgvContainsSecret(pid);
        process.Kill();
        using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = await process.WaitAsync(bound.Token).ConfigureAwait(false);
        var absent = !Directory.Exists("/proc/" + pid.ToString(CultureInfo.InvariantCulture));
        Require(absent, "Killed Linux process remains after wait.");
        return new CaseReport("linux-kill-wait", !result.TimedOut && absent, pid, result.ExitCode, result.TimedOut, 0, watch.Elapsed.TotalMilliseconds, "official_sdk", "Owned argv visibility recorded by the trusted host user; Kill/native wait result and /proc absence recorded", process.Warnings.ToArray(), secretInArgv, absent);
    }

    private static bool OwnedArgvContainsSecret(uint pid)
    {
        var pending = new Queue<uint>();
        pending.Enqueue(pid);
        var visited = new HashSet<uint>();
        var found = false;
        while (pending.Count > 0)
        {
            Require(visited.Count < 32, "Owned argv observation exceeded bounded fixture process count.");
            var current = pending.Dequeue();
            if (!visited.Add(current)) continue;
            var proc = "/proc/" + current.ToString(CultureInfo.InvariantCulture);
            try
            {
                found |= Encoding.UTF8.GetString(File.ReadAllBytes(proc + "/cmdline")).Contains("mxc-probe-secret-not-for-logs", StringComparison.Ordinal);
                foreach (var child in File.ReadAllText(proc + "/task/" + current.ToString(CultureInfo.InvariantCulture) + "/children").Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    pending.Enqueue(uint.Parse(child, CultureInfo.InvariantCulture));
                }
            }
            catch (IOException) when (!Directory.Exists(proc)) { /* A bounded owned child already exited. */ }
        }

        return found;
    }

    internal static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidDataException(message);
    }
}

internal sealed class StageManifest
{
    public string Version { get; set; } = "";
    public string Schema { get; set; } = "";
    public string Rid { get; set; } = "";
    public string Source { get; set; } = "";
    public string PackageSha256 { get; set; } = "";
    public string ReleaseSha256 { get; set; } = "";
    public StageMember[] Files { get; set; } = [];
}
internal sealed record StageMember(string Path, string Sha256);
internal sealed record BackendReport(string Name, string? Tier, string[] Capabilities, string[] Warnings);
internal sealed record IdleReport(double ElapsedMs, double OwnerCpuMs, long OwnerWorkingSetBytes, string Scope);
internal sealed record CaseReport(string Name, bool Ok, uint ProcessId, int ExitCode, bool TimedOut, double SpawnMs, double ElapsedMs, string ExitSource, string Evidence, string[] Warnings, bool? ArgvSentinelObserved = null, bool? ProcessAbsentAfterWait = null);
internal sealed class ProbeReport
{
    public string Experiment { get; set; } = "MXC-AOT-01";
    public string Host { get; set; } = "";
    public string Os { get; set; } = "";
    public int ProcessId { get; set; }
    public string StartedUtc { get; set; } = "";
    public string FinishedUtc { get; set; } = "";
    public bool StageVerified { get; set; }
    public bool Ok { get; set; }
    public string? Failure { get; set; }
    public string? ResourceScope { get; set; }
    public string? NativeVersion { get; set; }
    public bool PlatformSupported { get; set; }
    public string? SupportReason { get; set; }
    public string[] AvailableMethods { get; set; } = [];
    public BackendReport[] Backends { get; set; } = [];
    public double DiscoveryMs { get; set; }
    public IdleReport? IdleObservation { get; set; }
    public List<CaseReport> Cases { get; set; } = [];
}
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(StageManifest))]
[JsonSerializable(typeof(ProbeReport))]
internal sealed partial class ProbeJson : JsonSerializerContext;
