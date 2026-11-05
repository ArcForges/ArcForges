// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.CommandLine;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Client.Tests;

/// <summary>
/// N2-6 and N2-8: the sign-in commands' grammar, hidden aliases, completion, the exit code of a flow's end and the CLI's method choice
/// (node-11 corrected fix items 3-4). REAL parser; no node (the behaviour against a node is the closed loop's).
/// </summary>
public sealed class SignInCommandLineTests
{
    private static readonly NodeRunner NoNode = (_, _) => throw new InvalidOperationException("These tests never run the node role.");

    [Theory]
    [InlineData("login")]
    [InlineData("login --device-code")]
    [InlineData("login --json")]
    [InlineData("logout")]
    [InlineData("logout --local")]
    [InlineData("logout --local --yes")]
    [InlineData("center show")]
    [InlineData("center show --json")]
    [InlineData("center set https://center.example.test/api")]
    [InlineData("center set --default")]
    [InlineData("account status")]
    [InlineData("account status --json")]
    [InlineData("account login")]
    [InlineData("account login --device")]
    [InlineData("account login --device-code")]
    [InlineData("account logout --local")]
    public void TheSignInGrammarParses(string line)
    {
        var result = Root().Parse(line.Split(' '));
        Assert.Empty(result.Errors);
    }

    [Theory]
    [InlineData("login --device")]
    [InlineData("login extra")]
    [InlineData("logout --remote")]
    [InlineData("center")]
    [InlineData("center reset")]
    [InlineData("center set a b")]
    [InlineData("account")]
    public async Task TheSignInGrammarRefusesOtherForms(string line)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(ExitCodes.Usage, await CliApplication.RunAsync(line.Split(' '), NoNode, output, error));
    }

    [Theory]
    [InlineData("arcforges lo", "login")]
    [InlineData("arcforges lo", "logout")]
    [InlineData("arcforges cen", "center")]
    [InlineData("arcforges center ", "set")]
    [InlineData("arcforges account ", "status")]
    public async Task TheSignInCommandsAreSuggested(string line, string expected)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(0, await CliApplication.RunAsync([$"[suggest:{line.Length}]", line], NoNode, output, error));
        Assert.Contains(expected, output.ToString().Split('\n', StringSplitOptions.TrimEntries));
    }

    [Fact]
    public async Task TheHiddenAliasesAreNotSuggested()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var line = "arcforges account ";
        Assert.Equal(0, await CliApplication.RunAsync([$"[suggest:{line.Length}]", line], NoNode, output, error));
        var suggestions = output.ToString().Split('\n', StringSplitOptions.TrimEntries);
        Assert.DoesNotContain("login", suggestions);
        Assert.DoesNotContain("logout", suggestions);
    }

    [Theory]
    [InlineData(SignInFlowState.SignedIn, 0)]
    [InlineData(SignInFlowState.Denied, 1)]
    [InlineData(SignInFlowState.Expired, 1)]
    [InlineData(SignInFlowState.Failed, 1)]
    [InlineData(SignInFlowState.Cancelled, 1)]
    public void AFlowsEndDecidesTheExitCode(SignInFlowState state, int exit)
    {
        Assert.True(LoginCommands.Ended(state));
        Assert.Equal(exit, LoginCommands.ExitFor(state));
        Assert.False(LoginCommands.Ended(SignInFlowState.Pending));
        Assert.False(LoginCommands.Ended(SignInFlowState.Completing));
    }

    [Theory]
    [InlineData(true, false, null, null, null, null, true, SignInMethod.DeviceCode)]
    [InlineData(false, false, "1.2.3.4 1 5.6.7.8 22", null, ":0", null, true, SignInMethod.DeviceCode)]
    [InlineData(false, false, null, "/dev/pts/1", ":0", null, false, SignInMethod.DeviceCode)]
    [InlineData(false, false, null, null, null, null, true, SignInMethod.DeviceCode)]
    [InlineData(false, false, null, null, ":0", null, true, SignInMethod.Browser)]
    [InlineData(false, false, null, null, null, "wayland-0", true, SignInMethod.Browser)]
    [InlineData(false, false, null, null, null, null, false, SignInMethod.Browser)]
    [InlineData(false, true, "1.2.3.4 1 5.6.7.8 22", null, null, null, true, SignInMethod.Browser)]
    [InlineData(true, true, null, null, ":0", null, true, SignInMethod.DeviceCode)]
    public void LoginMethodSelectionTests(bool deviceCode, bool testMode, string? ssh, string? tty, string? display, string? wayland, bool linux, SignInMethod expected)
    {
        var environment = new Dictionary<string, string?>
        {
            ["SSH_CONNECTION"] = ssh,
            ["SSH_TTY"] = tty,
            ["DISPLAY"] = display,
            ["WAYLAND_DISPLAY"] = wayland,
        };
        Assert.Equal(expected, LoginCommands.Method(deviceCode, testMode, name => environment.GetValueOrDefault(name), linux));
    }

    [Theory]
    [InlineData("https://center.example.test/api/activate", true)]
    [InlineData("http://localhost:18080/connect#flow=f10e2d3c-4b5a-6978-8796-a5b4c3d2e10f", true)]
    [InlineData("file:///etc/passwd", false)]
    [InlineData("https://center.example.test/api/activate\u001b[2J", false)]
    [InlineData("https://center.example.test/a b", false)]
    [InlineData("", false)]
    public void OnlyShapedUrlsArePrinted(string url, bool printable) => Assert.Equal(printable, LoginCommands.Printable(url));

    [Fact]
    public void OnlyShapedCodesAndFingerprintsArePrinted()
    {
        Assert.True(LoginCommands.IsUserCode("BCDFGHJK"));
        Assert.False(LoginCommands.IsUserCode("BCDF-GHJK"));
        Assert.False(LoginCommands.IsUserCode("BCDF\u001bGHJ"));
        Assert.True(LoginCommands.Fingerprint("1A2B-3C4D-5E6F-7A8B-9C0D"));
        Assert.False(LoginCommands.Fingerprint("1a2b-3c4d-5e6f-7a8b-9c0d"));
        Assert.False(LoginCommands.Fingerprint("1A2B3C4D5E6F7A8B9C0D"));
    }

    [Theory]
    [InlineData("signed_in", "sign_in", "logout")]
    [InlineData("signed_out", "center_url", "center set")]
    [InlineData("signed_out", "credential_for_other_node", "logout --local")]
    [InlineData("signed_out", "credential_backend_changed", "logout --local")]
    [InlineData("signed_out", "credential_store_unavailable", "retries")]
    public void ARefusedSignInSaysWhatToDo(string state, string reason, string hint) =>
        Assert.Contains(hint, LoginCommands.StateText(state, reason), StringComparison.Ordinal);

    [Fact]
    public void CenterSuppliedErrorTextReachesTheTerminalOnlyAsPlainText()
    {
        // N2 review sec N-1 (SEC-24): a hostile center's ArcError text carries escape sequences, a line break and a bidirectional override.
        var error = new ArcForges.Contracts.Foundation.V1.ArcError
        {
            Category = ArcForges.Contracts.Foundation.V1.ErrorCategory.State,
            Code = "cloud\u001b[2Junreachable",
            MessageKey = "error.\u001b]0;owned\u0007key\nopen https://evil.example\u202e",
            Details = new ArcForges.Contracts.Foundation.V1.ErrorDetails { State = new ArcForges.Contracts.Foundation.V1.StateFailure { State = "x\u009b31m", Reason = "y\r\nz" } },
        };
        var text = Messages.For(error);
        Assert.DoesNotContain(text, c => char.IsControl(c) || char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format);
        Assert.Equal("cloud?[2Junreachable", Messages.Plain(error.Code));
        Assert.True(Messages.Plain(new string('a', 500)).Length <= 200);
        Assert.Equal(string.Empty, Messages.Plain(null));
        Assert.DoesNotContain(Messages.Plain(LoginCommands.StateText("center_refused", "\u001b[31mred")), char.IsControl);
    }

    private static System.CommandLine.RootCommand Root() => CliApplication.Build(new GlobalOptions(), NoNode, TextWriter.Null, TextWriter.Null);
}
