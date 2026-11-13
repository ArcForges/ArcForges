// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual Host process rejects a directly launched worker before taking a descriptor or performing an effect.</summary>
[Trait("feature", "file-guard-helper")]
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class LinuxWorkerBootstrapTests
{
    [Fact(Timeout = 30_000)]
    public async Task UnrelatedParentCannotBootstrapTheHostWorker()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux worker parent checks.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        var name = "arcforges-test-" + Guid.NewGuid().ToString("N");
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint("\0" + name));
        listener.Listen(1);
        var host = Path.Combine(AppContext.BaseDirectory, "arcforges");
        Assert.True(File.Exists(host));
        var start = new ProcessStartInfo(host)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add("node");
        start.ArgumentList.Add("file-effect-worker");
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Could not start the owned Host process.");
        var secret = RandomNumberGenerator.GetBytes(32);
        try
        {
            var address = Encoding.ASCII.GetBytes(name);
            try
            {
                child.StandardInput.BaseStream.WriteByte(checked((byte)address.Length));
                child.StandardInput.BaseStream.Write(address);
                child.StandardInput.BaseStream.Write(secret);
                child.StandardInput.BaseStream.Flush();
            }
            catch (IOException) { } // The refusal can close stdin before the attempted bootstrap write.
            child.StandardInput.Close();
            await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.Equal(2, child.ExitCode);
            Assert.False(listener.Poll(100_000, SelectMode.SelectRead));
            Assert.Empty(await child.StandardOutput.ReadToEndAsync(ct));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            if (!child.HasExited)
            {
                child.Kill();
                Assert.True(child.WaitForExit(10_000), "The owned Host process did not exit after termination.");
            }
        }
    }

    [Theory(Timeout = 30_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HostBootstrapSelfTestRequiresTestModeAndHasNoEffectArguments(bool testMode)
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux worker bootstrap self-test.");
            return;
        }
        var ct = TestContext.Current.CancellationToken;
        var host = Path.Combine(AppContext.BaseDirectory, "arcforges");
        var start = new ProcessStartInfo(host)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add("node");
        start.ArgumentList.Add("file-effect-selftest");
        if (testMode) start.ArgumentList.Add("--test-mode");
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Could not start the owned Host process.");
        child.StandardInput.Close();
        try
        {
            await child.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(20), ct);
            Assert.Equal(testMode ? 0 : 2, child.ExitCode);
            Assert.Empty(await child.StandardOutput.ReadToEndAsync(ct));
        }
        finally
        {
            if (!child.HasExited) Assert.True(child.WaitForExit(8000), "The owned Host self-test did not exit.");
        }
    }
}
