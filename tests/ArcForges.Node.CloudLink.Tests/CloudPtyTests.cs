// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text;
using ArcForges.Client;
using ArcForges.Node.Api;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>The local authentication PTY coverage retained from the retired V1 proxy's test source at 076e9e6.</summary>
public sealed class CloudPtyTests
{
    [Fact(Timeout = 60000)]
    public async Task AnExitedPtyCannotBeInterruptedThroughAReusedProcessId()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux() && File.Exists("/usr/bin/script"), "actual PTY control requires Linux and script");
        var ct = TestContext.Current.CancellationToken;
        using var pty = Process.Start(new ProcessStartInfo("/usr/bin/script")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            ArgumentList = { "-qefc", "exit 0", "/dev/null" },
        }) ?? throw new InvalidOperationException("Could not start the owned PTY.");
        await pty.WaitForExitAsync(ct);
        Assert.Equal(0, pty.ExitCode);
        await Assert.ThrowsAsync<InvalidOperationException>(() => SendInterruptAsync(pty, ct));
    }

    [Fact(Timeout = 60000)]
    public async Task AClosedPtyInputFailsWithoutSignallingAProcess()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux() && File.Exists("/usr/bin/script"), "actual PTY control requires Linux and script");
        var ct = TestContext.Current.CancellationToken;
        using var pty = Process.Start(new ProcessStartInfo("/usr/bin/script")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            ArgumentList = { "-qefc", "exec /bin/sleep 2", "/dev/null" },
        }) ?? throw new InvalidOperationException("Could not start the owned PTY.");
        Assert.False(pty.HasExited);
        pty.StandardInput.Close();
        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => SendInterruptAsync(pty, ct));
        await pty.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task ThePtyHelperDeliversCtrlCToTheActualCliLogin()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux() && File.Exists("/usr/bin/script"), "actual CLI Ctrl+C control requires the Linux PTY fixture");
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var started = new TaskCompletionSource<Process>(TaskCreationOptions.RunContinuationsAsynchronously);
        var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cli = fixture.CliInPtyUntilAsync(started, waiting, "Waiting for the approval", "login", "--device-code");
        try
        {
            var first = await Task.WhenAny(waiting.Task, cli, Task.Delay(TimeSpan.FromSeconds(10), ct));
            if (first == cli)
            {
                var early = await cli;
                var category = System.Text.RegularExpressions.Regex.Match(early.Stdout, @"[A-Z_]+/[a-z_]+").Value;
                TestContext.Current.TestOutputHelper?.WriteLine("login control early exit=" + early.ExitCode + "; stdoutChars=" + early.Stdout.Length
                    + "; category=" + category + "; nodeMessage=" + early.Stdout.Contains("node", StringComparison.OrdinalIgnoreCase)
                    + "; stderrChars=" + early.Stderr.Length);
            }
            Assert.True(first == waiting.Task, "the login PTY must reach the waiting screen before it is interrupted");
            Assert.False(cli.IsCompleted);
            await SendInterruptAsync(await started.Task.WaitAsync(ct), ct);
            var result = await cli;
            Assert.Equal(130, result.ExitCode);
            Assert.Contains("Sign-in cancelled.", result.Stdout, StringComparison.Ordinal);
        }
        finally
        {
            if (!cli.IsCompleted)
            {
                await SendInterruptAsync(await started.Task.WaitAsync(ct), ct);
                var result = await cli;
                TestContext.Current.TestOutputHelper?.WriteLine("login control cleanup exit=" + result.ExitCode
                    + "; stdoutChars=" + result.Stdout.Length + "; waiting=" + result.Stdout.Contains("Waiting for the approval", StringComparison.Ordinal)
                    + "; error=" + result.Stdout.Contains("error", StringComparison.OrdinalIgnoreCase));
            }
        }
    }

    private static Task SendInterruptAsync(Process pty, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Keep the owned process/pipe alive until the byte is flushed, even if the CLI exits concurrently.
        lock (pty)
        {
            if (pty.HasExited)
            {
                throw new InvalidOperationException("The owned PTY has already exited.");
            }

            // The terminal sends SIGINT to its own foreground group. A closed pipe fails safely; no numeric PID is looked up or signalled.
            pty.StandardInput.Write('\u0003');
            pty.StandardInput.Flush();
        }

        return Task.CompletedTask;
    }

    private sealed class Fixture(FakeCenter center, CloudNode node) : IAsyncDisposable
    {
        public FakeCenter Center { get; } = center;

        public CloudNode Node { get; } = node;

        public static async Task<Fixture> StartAsync()
        {
            var center = await FakeCenter.StartAsync();
            var node = CloudNode.Create(center.Endpoint.Url);
            node.TestMode = true;
            var previous = Environment.GetEnvironmentVariable(ClientImages.TestVariable);
            try
            {
                Environment.SetEnvironmentVariable(ClientImages.TestVariable, CloudNode.HelperExecutable);
                await node.StartAsync();
                return new Fixture(center, node);
            }
            catch
            {
                await node.DisposeAsync();
                await center.DisposeAsync();
                throw;
            }
            finally
            {
                Environment.SetEnvironmentVariable(ClientImages.TestVariable, previous);
            }
        }

        public async Task<(int ExitCode, string Stdout, string Stderr)> CliInPtyUntilAsync(TaskCompletionSource<Process> started,
            TaskCompletionSource ready, string marker, params string[] args)
        {
            var start = new ProcessStartInfo("/usr/bin/script")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                CreateNoWindow = true,
            };
            // Reset the inherited SIGINT disposition so the actual CLI receives the terminal's Ctrl+C.
            static string Quote(string value) => "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";
            start.ArgumentList.Add("-qefc");
            start.ArgumentList.Add("exec env --default-signal=INT " + string.Join(" ",
                new[] { CloudNode.HelperExecutable, NodeLocations.TestModeOption }.Concat(args).Select(Quote)));
            start.ArgumentList.Add("/dev/null");

            start.Environment.Clear();
            start.Environment["DOTNET_ROOT"] = new DirectoryInfo(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory())
                .Parent!.Parent!.Parent!.FullName;
            start.Environment["HOME"] = Node.Root;
            start.Environment["TMP"] = Node.Root;
            start.Environment["TEMP"] = Node.Root;
            start.Environment["TMPDIR"] = Node.Root;
            start.Environment["PATH"] = "/usr/bin:/bin";
            Node.BindCli(start);

            var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the test CLI.");
            try
            {
                started.TrySetResult(process);
                var stdout = ReadUntilAsync(process.StandardOutput, ready, marker);
                var stderr = ReadUntilAsync(process.StandardError, ready, marker);
                try
                {
                    await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(40));
                }
                catch (TimeoutException)
                {
                    process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync();
                    throw;
                }

                return (process.ExitCode, await stdout, await stderr);
            }
            finally
            {
                lock (process)
                {
                    process.Dispose();
                }
            }
        }

        private static async Task<string> ReadUntilAsync(StreamReader reader, TaskCompletionSource ready, string marker)
        {
            var text = new StringBuilder();
            var buffer = new char[4096];
            int count;
            while ((count = await reader.ReadAsync(buffer)) > 0)
            {
                text.Append(buffer, 0, count);
                if (text.ToString().Contains(marker, StringComparison.Ordinal))
                {
                    ready.TrySetResult();
                }
            }

            return text.ToString();
        }

        public async ValueTask DisposeAsync()
        {
            await Node.DisposeAsync();
            await Center.DisposeAsync();
        }
    }
}
