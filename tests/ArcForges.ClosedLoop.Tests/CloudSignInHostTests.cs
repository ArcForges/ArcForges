// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// N2-16 and N2-17: the sign-in of a REAL <c>arcforges node run --test-mode</c> process whose center is FakeCenter (MOCKED center, compiled
/// in from the cloud-link test project) through <c>ARCFORGES_TEST_CENTER_URL</c>, the browser played by the test (MOCKED browser: the node
/// writes the derived URL to <c>ARCFORGES_TEST_BROWSER_FILE</c> and starts nothing; the test approves on FakeCenter and sends the
/// redirect to the node's REAL loopback receiver), and the REAL CLI: a SCRIPT caller is refused on both systems, a HUMAN CLI in a pty
/// (<c>script -qefc</c>, Linux only: Windows has no pseudo-terminal path here, H-C14) signs in, follows the flow and cancels it with Ctrl+C.
/// </summary>
[Trait("loop", "local")]
public sealed class CloudSignInHostTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task TheNodeProcessSignsInThroughItsReceiverAndKeepsTheCredentialAcrossARestart()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = TestNode.Create();
        var browserFile = Path.Combine(node.Root, "browser.txt");
        var connectLog = Path.Combine(node.Root, "connect.log");
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        node.Environment[CloudLinkTestHooks.BrowserFile] = browserFile;
        node.Environment[CloudLinkTestHooks.ConnectLog] = connectLog;
        await node.StartNodeAsync();
        string fingerprint;
        await using (var human = await node.HumanChannelAsync())
        {
            var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = Command(), Method = SignInMethod.Browser }, cancellationToken: Ct);
            Assert.Null(begun.Error);
            var flow = begun.Value.Flow;
            await TestNode.WaitAsync(() => File.Exists(browserFile), TimeSpan.FromSeconds(10), "the browser file");
            Assert.Equal(flow.AuthorizeUrl + "\n", File.ReadAllText(browserFile));
            Assert.Equal("HTTP/1.1 200 OK", await ScriptedBrowser.GetAsync(center.ApproveFlow()));
            await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status.SignedIn,
                TimeSpan.FromSeconds(20), "signed in");
            var status = (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status;
            fingerprint = status.NodeKeyFingerprint;
            Assert.Equal(flow.NodeKeyFingerprint, fingerprint);
            Assert.Equal(SignInFlowState.SignedIn, (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flow.FlowId }, cancellationToken: Ct)).Value.Flow.State);
            Assert.Contains("account.sign_in.v1", (await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), cancellationToken: Ct)).Value.Node.Features);
        }

        await node.StopNodeAsync();
        await node.StartNodeAsync();
        await using (var human = await node.HumanChannelAsync())
        {
            var status = (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status;
            Assert.True(status.SignedIn);
            Assert.Equal(fingerprint, status.NodeKeyFingerprint);
        }

        await using (var human = await node.HumanChannelAsync())
        {
            Assert.Null((await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = Command() }, cancellationToken: Ct)).Error);
        }

        await node.StopNodeAsync();
        Assert.All(File.ReadAllLines(connectLog), line => Assert.StartsWith("127.0.0.1:" + center.Endpoint.Port + " sent ", line, StringComparison.Ordinal));
        var log = TestNode.ReadShared(node.NodeLog);
        foreach (var secret in new[] { "afr1.", "afa1.", center.LatestDelivered! })
        {
            Assert.DoesNotContain(secret, log, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("/connect#flow=", log, StringComparison.Ordinal);
        Assert.Contains("cloud.sign_in.ended", log, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADeviceSignInOfTheNodeProcessAndARestartThatCancelsAFlow()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        await node.StartNodeAsync();
        Id flowId;
        int port;
        await using (var human = await node.HumanChannelAsync())
        {
            // A browser flow without the test hook opens nothing (warned), and a restart cancels it: its receiver is gone.
            var begun = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = Command(), Method = SignInMethod.Browser }, cancellationToken: Ct);
            Assert.Contains("browser_not_opened", begun.Meta.Warnings);
            flowId = begun.Value.Flow.FlowId;
            port = new Uri(center.ApproveFlow()).Port;
        }

        await node.StopNodeAsync();
        await node.StartNodeAsync();
        await using (var human = await node.HumanChannelAsync())
        {
            Assert.Equal("not_found", (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flowId }, cancellationToken: Ct)).Error.Code);
            await Assert.ThrowsAnyAsync<Exception>(() => ScriptedBrowser.RawAsync("127.0.0.1", port, "GET / HTTP/1.1\r\n\r\n", TimeSpan.FromSeconds(2)));

            var device = (await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = Command(), Method = SignInMethod.DeviceCode }, cancellationToken: Ct)).Value.Flow;
            Assert.Equal(center.LatestUserCode, device.UserCode);
            Assert.Equal(center.Endpoint.ActivateCompleteUrl(device.UserCode), device.VerificationUriComplete);
            center.ApproveDevice();
            await TestNode.WaitAsync(async () => (await human.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status.SignedIn,
                TimeSpan.FromSeconds(30), "signed in by the device code");
            Assert.Null((await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = Command() }, cancellationToken: Ct)).Error);
        }

        await node.StopNodeAsync();
        var log = TestNode.ReadShared(node.NodeLog);
        Assert.DoesNotContain(center.LatestUserCode!, log, StringComparison.Ordinal);
        Assert.DoesNotContain("afr1.", log, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AScriptCallerOfTheCliIsRefusedWithTheExplanation()
    {
        await using var center = await FakeCenter.StartAsync();
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        await node.StartNodeAsync();
        var login = await node.CliAsync("login", "--device-code");
        Assert.Equal(5, login.ExitCode);
        Assert.Contains("interactive terminal", login.Error, StringComparison.Ordinal);
        var logout = await node.CliAsync("logout");
        Assert.Equal(5, logout.ExitCode);
        var set = await node.CliAsync("center", "set", "https://other.example.test");
        Assert.Equal(5, set.ExitCode);
        var status = await node.CliAsync("account", "status", "--json");
        Assert.Equal(0, status.ExitCode);
        Assert.False(status.Json().TryGetProperty("signedIn", out var signedIn) && signedIn.GetBoolean());
        Assert.Equal(0, center.DeviceCount);
    }

    [Fact]
    public async Task TheCliInAPtySignsInFollowsTheFlowAndCancelsOnCtrlC()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux() && File.Exists("/usr/bin/script"), "no pseudo-terminal path on this system (H-C14): the HUMAN CLI runs in a pty on Linux only");
        await using var center = await FakeCenter.StartAsync();
        await using var node = TestNode.Create();
        node.Environment[CloudLinkTestHooks.CenterUrl] = center.Endpoint.Url;
        await node.StartNodeAsync();

        // Ctrl+C: CancelSignIn, exit 130; the center change is accepted again afterwards.
        using (var cli = Pty(node, "login --device-code"))
        {
            var text = await cli.WaitForAsync("Waiting for the approval");
            Assert.Contains("open " + center.Endpoint.ActivateUrl + " on any device", text, StringComparison.Ordinal);
            Assert.Contains(SignInUrls.DisplayUserCode(center.LatestUserCode!), text, StringComparison.Ordinal);
            Assert.Contains("Key fingerprint: ", text, StringComparison.Ordinal);
            Assert.Contains("The page asks for the last group of the fingerprint: ", text, StringComparison.Ordinal);
            Assert.Contains("Center:          127.0.0.1:" + center.Endpoint.Port, text, StringComparison.Ordinal);

            // While it runs, a center change from a HUMAN CLI is refused (here first by the test-center override, G-6), exit 1.
            using (var set = Pty(node, "center set https://other.example.test"))
            {
                Assert.Equal(1, await set.ExitAsync());
                Assert.Contains("(STATE/invalid_state)", set.Text, StringComparison.Ordinal);
            }

            cli.Interrupt();
            Assert.Equal(130, await cli.ExitAsync());
            Assert.Contains("Sign-in cancelled.", cli.Text, StringComparison.Ordinal);
        }

        // A sign-in that the account approves: exit 0.
        using (var cli = Pty(node, "login --device-code"))
        {
            await cli.WaitForAsync("Waiting for the approval");
            center.ApproveDevice();
            Assert.Equal(0, await cli.ExitAsync());
            Assert.Contains("Signed in.", cli.Text, StringComparison.Ordinal);
        }

        // Signed in: login and center set exit 1 with what to do; logout signs out (exit 0).
        using (var cli = Pty(node, "login"))
        {
            Assert.Equal(1, await cli.ExitAsync());
            Assert.Contains("already signed in", cli.Text, StringComparison.Ordinal);
        }

        using (var set = Pty(node, "center set https://other.example.test"))
        {
            Assert.Equal(1, await set.ExitAsync());
            Assert.Contains("(STATE/invalid_state)", set.Text, StringComparison.Ordinal);
        }

        using (var cli = Pty(node, "--json login --device-code"))
        {
            Assert.Equal(1, await cli.ExitAsync());
        }

        using (var cli = Pty(node, "logout"))
        {
            Assert.Equal(0, await cli.ExitAsync());
            Assert.Contains("Signed out.", cli.Text, StringComparison.Ordinal);
        }

        Assert.Single(center.CallsOf("SignOutNode"));

        // --json: JSON Lines, the begun flow first (with its code), the end last.
        using (var cli = Pty(node, "--json login --device-code"))
        {
            await cli.WaitForAsync("\"userCode\"");
            center.DenyDevice();
            Assert.Equal(1, await cli.ExitAsync());
            var lines = cli.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Where(line => line.StartsWith('{')).ToList();
            Assert.True(lines.Count >= 2, cli.Text);
            Assert.Contains("SIGN_IN_FLOW_STATE_PENDING", lines[0], StringComparison.Ordinal);
            Assert.Contains("SIGN_IN_FLOW_STATE_DENIED", lines[^1], StringComparison.Ordinal);
        }
    }

    private static RequestMeta Command() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };

    /// <summary>Starts <c>arcforges --test-mode &lt;arguments&gt;</c> inside a pseudo-terminal (<c>script -qefc</c>): a HUMAN CLI.</summary>
    internal static PtyProcess Pty(TestNode node, string arguments)
    {
        var start = new ProcessStartInfo("/usr/bin/script")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
        };
        start.ArgumentList.Add("-qefc");
        start.ArgumentList.Add("'" + TestNode.Host + "' --test-mode " + arguments);
        start.ArgumentList.Add("/dev/null");
        foreach (var (name, value) in node.Environment)
        {
            if (value is null)
            {
                start.Environment.Remove(name);
            }
            else
            {
                start.Environment[name] = value;
            }
        }

        start.Environment.Remove(ArcForges.Security.Secrets.OsSecretStoreGuard.OptInVariable);
        return new PtyProcess(Process.Start(start) ?? throw new InvalidOperationException("script did not start."));
    }

    internal sealed class PtyProcess : IDisposable
    {
        private readonly Process _process;
        private readonly StringBuilder _text = new();
        private readonly Task _reader;

        public PtyProcess(Process process)
        {
            _process = process;
            _reader = Task.Run(async () =>
            {
                var buffer = new char[4096];
                int read;
                while ((read = await process.StandardOutput.ReadAsync(buffer)) > 0)
                {
                    lock (_text)
                    {
                        _text.Append(buffer, 0, read);
                    }
                }
            });
        }

        public string Text
        {
            get
            {
                lock (_text)
                {
                    return _text.ToString();
                }
            }
        }

        public async Task<string> WaitForAsync(string marker)
        {
            await TestNode.WaitAsync(() => Text.Contains(marker, StringComparison.Ordinal), TimeSpan.FromSeconds(30), "the CLI to print " + marker);
            return Text;
        }

        /// <summary>
        /// The interrupt the CLI handles like Ctrl+C: SIGTERM to the CLI under the pty (found by process IDs only). SIGTERM, because a test run
        /// started in the background of a non-interactive shell inherits SIGINT as ignored, and the CLI treats both signals alike.
        /// </summary>
        public void Interrupt()
        {
            // The shell script starts may or may not exec the CLI: every descendant gets the signal (as the terminal's foreground group would).
            var descendants = new List<string>();
            var pending = new Queue<string>([_process.Id.ToString(System.Globalization.CultureInfo.InvariantCulture)]);
            while (pending.Count > 0)
            {
                var pid = pending.Dequeue();
                foreach (var task in Directory.EnumerateDirectories($"/proc/{pid}/task"))
                {
                    foreach (var child in File.ReadAllText(Path.Combine(task, "children")).Split(' ', StringSplitOptions.RemoveEmptyEntries))
                    {
                        descendants.Add(child);
                        pending.Enqueue(child);
                    }
                }
            }

            Assert.NotEmpty(descendants);
            foreach (var child in descendants)
            {
                using var kill = Process.Start(new ProcessStartInfo("/bin/kill") { ArgumentList = { "-TERM", child }, UseShellExecute = false })!;
                kill.WaitForExit();
            }
        }

        public Task<int> ExitAsync() => WaitExitAsync(TimeSpan.FromSeconds(60));

        public async Task<int> WaitExitAsync(TimeSpan timeout)
        {
            using var deadline = new CancellationTokenSource(timeout);
            try
            {
                await _process.WaitForExitAsync(deadline.Token);
            }
            catch (OperationCanceledException)
            {
                throw new TimeoutException("the CLI did not exit; it printed: " + Text);
            }

            await _reader;
            return _process.ExitCode;
        }

        public void Dispose()
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
            }

            _process.Dispose();
        }
    }
}
