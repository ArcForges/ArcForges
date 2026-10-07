// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using ArcForges.ContentSandbox.Broker;
using ArcForges.ContentSandbox.Broker.Native;
using ArcForges.ContentSandbox.Broker.Windows;
using ArcForges.ContentSandbox.Contracts;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>
/// The opt-in operating-system checks: a real signed-in-place AOT child, launched into a real AppContainer and Job Object, attacks the boundary
/// with a deliberately hostile first-party script. They never run by default or in hosted CI. To run them once on a Windows machine:
/// <c>dotnet publish src/DesktopHelpers/ArcForges.ContentSandbox/Fixture/ArcForges.ContentSandbox.HostileFixture.csproj -c Release -r win-x64</c>,
/// then set <c>ARCFORGES_CONTENTSANDBOX_OS=1</c> and <c>ARCFORGES_CONTENTSANDBOX_FIXTURE</c> to that publish directory. Every
/// result is evidence only for the machine, the operating system build and the fixture that ran.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class OsIsolationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void RequireOptIn() =>
        Assert.SkipUnless(OsHarness.IsEnabled, "Set ARCFORGES_CONTENTSANDBOX_OS=1 and ARCFORGES_CONTENTSANDBOX_FIXTURE to a published hostile fixture on Windows.");

    [Fact]
    public async Task TheRealChildReadsAnImageThroughARestrictedProcessAndExitsCleanly()
    {
        RequireOptIn();
        using var os = OsHarness.Create();
        await using var launcher = os.NewLauncher();
        var launched = await launcher.LaunchAsync(Fixtures.Script("image 300 200"), Ct);
        Assert.True(launched.IsSuccess, launched.Failure?.Code + " " + launched.Detail);
        await using var invocation = launched.Value!;
        Assert.NotEqual(Environment.ProcessId, invocation.HelperProcess.ProcessId);
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        using var tile = (await invocation.ReadImageTileAsync(image, 10, 20, 64, 32, Ct)).Value!;
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(tile.Bytes.Span)), tile.Sha256);
        Assert.Equal((byte)10, tile.Bytes.Span[0]);
        Assert.Equal((byte)20, tile.Bytes.Span[1]);
        await invocation.CloseAsync();
        Assert.Equal(ContentSandboxContract.ExitClean, await invocation.WaitForExitAsync(Ct));
    }

    [Fact]
    public async Task AHelperCannotReadPrivateStorageLeftByThePreviousOwnerOfItsPooledIdentity()
    {
        RequireOptIn();
        using var os = OsHarness.Create();
        await using var launcher = new ContentSandboxLauncher(os.Options() with
        {
            AppContainerName = "ArcForges.Storage." + Guid.NewGuid().ToString("N")[..24],
        });
        await using (var first = (await launcher.LaunchAsync(Fixtures.Script("image 8 8", "attack storage-write"), Ct)).Value!)
        {
            var image = (await first.OpenImageAsync(0, 0, 1, Ct)).Value;
            Assert.Contains("storage-write:WRITTEN", (await first.GetImageInfoAsync(image, Ct)).Value!.Warnings);
            await first.CloseAsync();
            _ = await first.WaitForExitAsync(Ct);
        }

        await using var next = (await launcher.LaunchAsync(Fixtures.Script("image 8 8", "attack storage-read"), Ct)).Value!;
        var opened = (await next.OpenImageAsync(0, 0, 1, Ct)).Value;
        Assert.Contains("storage-read:ABSENT", (await next.GetImageInfoAsync(opened, Ct)).Value!.Warnings);
        await next.CloseAsync();
    }

    [Fact]
    public async Task RecoveryChecksTheActualContainerProcessInstanceAndRefusesReuseUntilItExits()
    {
        RequireOptIn();
        using var os = OsHarness.Create();
        var prefix = "ArcForges.Instance." + Guid.NewGuid().ToString("N")[..24];
        await using var launcher = new ContentSandboxLauncher(os.Options() with { AppContainerName = prefix });
        await using var invocation = (await launcher.LaunchAsync(Fixtures.Script("image 8 8"), Ct)).Value!;
        using var process = Process.GetProcessById(invocation.HelperProcess.ProcessId);
        var name = prefix + ".0";
        Assert.Equal(0, WindowsNative.DeriveAppContainerSidFromAppContainerName(name, out var sid));
        var path = Path.Combine(Path.GetTempPath(), "ArcForges-instance-" + Guid.NewGuid().ToString("N") + ".lock");
        try
        {
            await using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            {
                AppContainerSlots.WriteLifetime(stream, new AppContainerSlots.LifetimeRecord(1, "active", process.Id,
                    process.StartTime.ToUniversalTime().Ticks, new SecurityIdentifier(sid).Value));
                Assert.False(AppContainerSlots.PriorLifetimeEnded(stream, name));
                await invocation.CloseAsync();
                _ = await invocation.WaitForExitAsync(Ct);
                await process.WaitForExitAsync(Ct);
                Assert.True(AppContainerSlots.PriorLifetimeEnded(stream, name));
            }
        }
        finally
        {
            _ = WindowsNative.FreeSid(sid);
            File.Delete(path);
        }
    }

    [Fact]
    public async Task TheHostileChildCannotReadProductFilesReachTheNetworkOrTouchProcessesAndCannotSpawn()
    {
        RequireOptIn();
        using var os = OsHarness.Create();
        var productStore = os.PlantFile("product.db");
        var tokenCache = os.PlantFile("tokens.cache");
        using var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var tcpAccepted = listener.AcceptTcpClientAsync(Ct).AsTask();
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        var udpPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        var udpReceived = udp.ReceiveAsync(Ct).AsTask();
        var lan = OsHarness.LanAddress();

        await using var launcher = new ContentSandboxLauncher(os.Options() with { Limits = new ContentSandboxLimits { TimeoutMs = 25000, MaxWidth = 4096, MaxHeight = 4096 } });
        await using var sibling = (await launcher.LaunchAsync(Fixtures.Script("image 8 8"), Ct)).Value!;
        var script = Fixtures.Script(
            "image 32 32",
            "attack file " + productStore,
            "attack file " + tokenCache,
            "attack tcp 127.0.0.1 " + port.ToString(CultureInfo.InvariantCulture),
            "attack tcp " + lan + " " + port.ToString(CultureInfo.InvariantCulture),
            "attack udp 127.0.0.1 " + udpPort.ToString(CultureInfo.InvariantCulture),
            "attack udp " + lan + " " + udpPort.ToString(CultureInfo.InvariantCulture),
            "attack process " + Environment.ProcessId.ToString(CultureInfo.InvariantCulture),
            "attack process " + sibling.HelperProcess.ProcessId.ToString(CultureInfo.InvariantCulture),
            "attack spawn " + Path.Combine(Environment.SystemDirectory, "cmd.exe"),
            "attack input-write",
            "attack env",
            "attack identity");
        var launched = await launcher.LaunchAsync(script, Ct);
        Assert.True(launched.IsSuccess, launched.Failure?.Code + " " + launched.Detail);
        await using var attacker = launched.Value!;
        var opened = await attacker.OpenImageAsync(0, 0, 1, Ct);
        Assert.True(opened.IsSuccess, opened.Failure?.Code + " " + attacker.HelperDiagnostics);
        var report = (await attacker.GetImageInfoAsync(opened.Value, Ct)).Value!.Warnings.ToList();
        OsHarness.Evidence("attack report", report);

        Assert.Equal(["file:DENIED:UnauthorizedAccessException", "file:DENIED:UnauthorizedAccessException"], report.Where(line => line.StartsWith("file:", StringComparison.Ordinal)));
        Assert.All(report.Where(line => line.StartsWith("tcp:", StringComparison.Ordinal)), line => Assert.StartsWith("tcp:DENIED:", line, StringComparison.Ordinal));
        Assert.All(report.Where(line => line.StartsWith("process:", StringComparison.Ordinal)), line => Assert.StartsWith("process:DENIED:", line, StringComparison.Ordinal));
        Assert.Single(report, line => line.StartsWith("spawn:", StringComparison.Ordinal));
        Assert.StartsWith("spawn:DENIED:", report.Single(line => line.StartsWith("spawn:", StringComparison.Ordinal)), StringComparison.Ordinal);
        Assert.Equal("input-write:DENIED:AccessDenied", report.Single(line => line.StartsWith("input-write:", StringComparison.Ordinal)));
        Assert.Equal("env:DENIED:OnlySystemRoot", report.Single(line => line.StartsWith("env:", StringComparison.Ordinal)));

        // What the child did not do is observed from the other side too: the listeners saw nothing.
        await Task.Delay(TimeSpan.FromSeconds(1), Ct);
        Assert.False(tcpAccepted.IsCompleted, "the child reached the TCP listener");
        Assert.False(udpReceived.IsCompleted, "the child delivered a datagram");
        Assert.Equal(ReadOnlyHash(productStore), os.PlantedHash(productStore));
        await attacker.CloseAsync();
    }

    [Fact]
    public async Task TheRestrictedChildHoldsNoListeningSocketAndNoConnection()
    {
        RequireOptIn();
        using var os = OsHarness.Create();
        await using var launcher = os.NewLauncher();
        await using var invocation = (await launcher.LaunchAsync(Fixtures.Script("image 8 8"), Ct)).Value!;
        var pid = invocation.HelperProcess.ProcessId;
        var lines = await OsHarness.NetstatAsync(Ct);
        var owned = lines.Where(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() == pid.ToString(CultureInfo.InvariantCulture)).ToArray();
        OsHarness.Evidence("netstat lines owned by the helper", owned);
        Assert.Empty(owned);
        _ = IPGlobalProperties.GetIPGlobalProperties();
    }

    [Fact]
    public async Task ANativeCrashEndsOnlyTheHelperAndTheParentCarriesOnAndLaunchesAgain()
    {
        RequireOptIn();
        using var os = OsHarness.Create();
        await using var launcher = os.NewLauncher();
        await using (var invocation = (await launcher.LaunchAsync(Fixtures.Script("image 8 8", "crash-on-open"), Ct)).Value!)
        {
            var opened = await invocation.OpenImageAsync(0, 0, 1, Ct);
            Assert.Equal("resource.parser_failed", opened.Failure!.Code);
            var code = await invocation.WaitForExitAsync(Ct);
            Assert.NotEqual(0, code);
            OsHarness.Evidence("exit code after a native access violation", [code.ToString("x", CultureInfo.InvariantCulture)]);
        }

        await using var again = (await launcher.LaunchAsync(Fixtures.Script("image 8 8"), Ct)).Value!;
        Assert.True((await again.OpenImageAsync(0, 0, 1, Ct)).IsSuccess);
    }

    [Fact]
    public async Task AParserThatSpinsForeverIsTerminatedAtTheDeadlineAndItsProcessIsGone()
    {
        RequireOptIn();
        using var os = OsHarness.Create();
        var options = os.Options() with { Limits = new ContentSandboxLimits { TimeoutMs = 1500, MaxWidth = 4096, MaxHeight = 4096 } };
        await using var launcher = new ContentSandboxLauncher(options);
        await using var invocation = (await launcher.LaunchAsync(Fixtures.Script("image 64 64", "hang-on-tile"), Ct)).Value!;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        var watch = Stopwatch.StartNew();
        var tile = await invocation.ReadImageTileAsync(image, 0, 0, 8, 8, Ct);
        Assert.Equal("resource.parser_failed", tile.Failure!.Code);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(20), watch.Elapsed.ToString());
        _ = await invocation.WaitForExitAsync(Ct);
        Assert.Throws<ArgumentException>(() => Process.GetProcessById(invocation.HelperProcess.ProcessId));
    }

    [Fact]
    public async Task MemoryExhaustionIsBoundedByTheJobAndEndsOnlyTheHelper()
    {
        RequireOptIn();
        using var os = OsHarness.Create();
        var options = os.Options() with { Limits = new ContentSandboxLimits { MaxMemoryBytes = 256UL * 1024 * 1024, TimeoutMs = 20000, MaxWidth = 4096, MaxHeight = 4096 } };
        await using var launcher = new ContentSandboxLauncher(options);
        await using var invocation = (await launcher.LaunchAsync(Fixtures.Script("image 8 8", "oom-on-open"), Ct)).Value!;
        var opened = await invocation.OpenImageAsync(0, 0, 1, Ct);
        Assert.Equal("resource.parser_failed", opened.Failure!.Code);
        var code = await invocation.WaitForExitAsync(Ct);
        Assert.NotEqual(0, code);
        OsHarness.Evidence("exit code after exhausting the 256 MiB job memory limit", [code.ToString("x", CultureInfo.InvariantCulture)]);
        Assert.True(GC.GetTotalMemory(false) < 256L * 1024 * 1024 * 4);
    }

    [Fact]
    public async Task CancellationStopsASlowParserAndTheHelperAcknowledgesThroughTheControlSlot()
    {
        RequireOptIn();
        using var os = OsHarness.Create();
        await using var launcher = os.NewLauncher();
        await using var invocation = (await launcher.LaunchAsync(Fixtures.Script("image 64 64", "slow-on-tile 20000"), Ct)).Value!;
        var image = (await invocation.OpenImageAsync(0, 0, 1, Ct)).Value;
        using var source = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var pending = invocation.ReadImageTileAsync(image, 0, 0, 8, 8, source.Token).AsTask();
        await Task.Delay(1000, Ct);
        var watch = Stopwatch.StartNew();
        await source.CancelAsync();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pending);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(8), watch.Elapsed.ToString());
    }

    [Fact]
    public async Task TheHelperDiesWithItsParent()
    {
        RequireOptIn();
        using var os = OsHarness.Create();
        var info = new ProcessStartInfo(Environment.ProcessPath!)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
        };
        info.Environment["ARCFORGES_CS_PARENT_MODE"] = "1";
        info.Environment["ARCFORGES_CS_HELPER"] = os.ExecutablePath;
        info.Environment["ARCFORGES_CS_ROOT"] = Fixtures.NewRoot();
        using var parent = Process.Start(info)!;
        var line = await parent.StandardOutput.ReadLineAsync(Ct) ?? string.Empty;
        Assert.StartsWith("HELPER ", line, StringComparison.Ordinal);
        var helperId = int.Parse(line["HELPER ".Length..], CultureInfo.InvariantCulture);
        using var helper = Process.GetProcessById(helperId);
        Assert.False(helper.HasExited);
        parent.Kill(entireProcessTree: false);
        await parent.WaitForExitAsync(Ct);
        using var wait = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await helper.WaitForExitAsync(wait.Token);
        Assert.True(helper.HasExited);
        OsHarness.Evidence("helper outlived its killed parent", ["no"]);
    }

    [Fact]
    public async Task AHelperThatIsNotThePinnedBuildIsNeverStarted()
    {
        RequireOptIn();
        using var os = OsHarness.Create();
        var options = os.Options() with { HelperSha256 = SHA256.HashData("another build"u8) };
        await using var launcher = new ContentSandboxLauncher(options);
        var before = Process.GetProcessesByName("ArcForges.ContentSandbox.HostileFixture").Length;
        var launched = await launcher.LaunchAsync(Fixtures.Script("image 8 8"), Ct);
        Assert.Equal("resource.integrity_failed", launched.Failure!.Code);
        Assert.Equal(before, Process.GetProcessesByName("ArcForges.ContentSandbox.HostileFixture").Length);
    }

    private static string ReadOnlyHash(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
}

/// <summary>The machine side of the opt-in checks: a copy of the published fixture whose directory the AppContainer may read, and planted files.</summary>
[SupportedOSPlatform("windows")]
internal sealed class OsHarness : IDisposable
{
    private readonly string _directory;
    private readonly string _plantedDirectory;
    private readonly Dictionary<string, string> _hashes = [];

    private OsHarness(string directory, string executable, byte[] digest)
    {
        _directory = directory;
        ExecutablePath = executable;
        Digest = digest;
        _plantedDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "arcforges-cs-os-" + Guid.NewGuid().ToString("N")[..8]);
        _ = Directory.CreateDirectory(_plantedDirectory);
    }

    internal static bool IsEnabled =>
        OperatingSystem.IsWindows()
        && Environment.GetEnvironmentVariable("ARCFORGES_CONTENTSANDBOX_OS") == "1"
        && Directory.Exists(Environment.GetEnvironmentVariable("ARCFORGES_CONTENTSANDBOX_FIXTURE"));

    internal string ExecutablePath { get; }

    internal byte[] Digest { get; }

    internal static OsHarness Create(bool production = false)
    {
        var published = Environment.GetEnvironmentVariable(production ? "ARCFORGES_CONTENTSANDBOX_PRODUCTION" : "ARCFORGES_CONTENTSANDBOX_FIXTURE")!;
        var directory = Path.Combine(Path.GetTempPath(), "arcforges-cs-os-fixture-" + Guid.NewGuid().ToString("N")[..8]);
        _ = Directory.CreateDirectory(directory);
        foreach (var file in Directory.GetFiles(published))
        {
            File.Copy(file, Path.Combine(directory, Path.GetFileName(file)));
        }

        // The AppContainer reads the helper through the ACE for ALL APPLICATION PACKAGES, which an installed helper under Program Files already has.
        var info = new DirectoryInfo(directory);
        var security = info.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier("S-1-15-2-1"),
            FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        info.SetAccessControl(security);
        var executable = Path.Combine(directory, production ? "ArcForges.ContentSandbox.exe" : "ArcForges.ContentSandbox.HostileFixture.exe");
        return new OsHarness(directory, executable, SHA256.HashData(File.ReadAllBytes(executable)));
    }

    internal ContentSandboxLaunchOptions Options() => new()
    {
        HelperPath = ExecutablePath,
        HelperSha256 = Digest,
        ParserProfile = HostileFixture.HostileProfile.ProfileId,
        LocalUnsignedFixture = true,
        RuntimeRoot = Fixtures.NewRoot(),
        Limits = new ContentSandboxLimits { TimeoutMs = 10000, MaxWidth = 4096, MaxHeight = 4096 },
        SlotCapacityBytes = 1024 * 1024,
        LaunchTimeout = TimeSpan.FromSeconds(60),
    };

    internal ContentSandboxLauncher NewLauncher() => new(Options());

    internal string PlantFile(string name)
    {
        var path = Path.Combine(_plantedDirectory, name);
        File.WriteAllText(path, "product secret " + name);
        _hashes[path] = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
        return path;
    }

    internal string PlantedHash(string path) => _hashes[path];

    internal static string LanAddress() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .SelectMany(adapter => adapter.GetIPProperties().UnicastAddresses)
            .Select(address => address.Address)
            .First(address => address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(address))
            .ToString();

    internal static async Task<string[]> NetstatAsync(CancellationToken cancellationToken)
    {
        using var process = Process.Start(new ProcessStartInfo("netstat", "-ano") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!;
        var text = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        return text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.Trim()).ToArray();
    }

    internal static void Evidence(string title, IEnumerable<string> lines) =>
        Console.Error.WriteLine("[os-evidence] " + title + ": " + string.Join(" | ", lines));

    public void Dispose()
    {
        TryDelete(_directory);
        TryDelete(_plantedDirectory);
    }

    private static void TryDelete(string directory)
    {
        try
        {
            Directory.Delete(directory, recursive: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A helper may still hold a file for a moment; the directory is under the temporary or profile folder and is harmless.
        }
    }
}

/// <summary>
/// Lets the test assembly act as the launching parent of a real helper for the parent-death check: when the marker variable is set, the
/// assembly launches the helper, reports its process id and waits to be killed.
/// </summary>
internal static class ParentMode
{
    [ModuleInitializer]
    internal static void RunWhenAParent()
    {
        if (Environment.GetEnvironmentVariable("ARCFORGES_CS_PARENT_MODE") != "1" || !OperatingSystem.IsWindows())
        {
            return;
        }

        var executable = Environment.GetEnvironmentVariable("ARCFORGES_CS_HELPER")!;
        var production = Environment.GetEnvironmentVariable("ARCFORGES_CS_PARENT_PRODUCTION") == "1";
        var options = new ContentSandboxLaunchOptions
        {
            HelperPath = executable,
            HelperSha256 = SHA256.HashData(File.ReadAllBytes(executable)),
            ParserProfile = production ? Host.ProductionParserProfile.ProfileId : HostileFixture.HostileProfile.ProfileId,
            LocalUnsignedFixture = true,
            RuntimeRoot = Environment.GetEnvironmentVariable("ARCFORGES_CS_ROOT")!,
            SlotCapacityBytes = 1024 * 1024,
            LaunchTimeout = TimeSpan.FromSeconds(60),
        };
        var launcher = new ContentSandboxLauncher(options);
        var result = launcher.LaunchAsync(production ? FirstPartyPdfFixture.Bytes() : Encoding.UTF8.GetBytes("HOSTILE1\nimage 8 8\n")).AsTask().GetAwaiter().GetResult();
        if (!result.IsSuccess)
        {
            Console.Out.WriteLine("FAILED " + result.Failure!.Code + " " + result.Detail);
            Environment.Exit(3);
        }

        Console.Out.WriteLine("HELPER " + result.Value!.HelperProcess.ProcessId.ToString(CultureInfo.InvariantCulture));
        Console.Out.Flush();
        Thread.Sleep(Timeout.Infinite);
    }
}
