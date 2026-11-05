// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Runtime.InteropServices;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges login [--device-code]</c> (AF-CTR-04 CTR4-NODE-15 as amended; Q18; experience/cli.md C-09, whose <c>account login</c> is the
/// hidden alias): <c>BeginSignIn</c>, then <c>GetSignInFlow</c> every second until the flow ends. It prints the URL to open (browser) or the
/// code and the URL (device code), the center's host and the node key's full fingerprint, naming its last group, which the
/// <c>/activate</c> page asks for; no terminal QR (Q19). Ctrl+C cancels the flow (<c>CancelSignIn</c>) and exits 130. Exit 0 when signed
/// in, 1 when denied, expired, failed or cancelled elsewhere, 5 when the node refuses a caller without an interactive terminal.
/// </summary>
internal static class LoginCommands
{
    private static readonly TimeSpan BeginDeadline = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan ReadDeadline = TimeSpan.FromSeconds(5);

    /// <summary>The <c>login</c> command (also built as the hidden <c>account login</c>, which also takes <c>--device</c>).</summary>
    public static Command Build(Func<ParseResult, Cli> factory, string name = "login", bool alias = false)
    {
        var deviceCode = new Option<bool>("--device-code") { Description = "Sign in with a code entered on any device (no browser on this computer)" };
        if (alias)
        {
            deviceCode.Aliases.Add("--device");
        }

        var command = new Command(name, "Sign this node in to its center") { deviceCode };
        command.Hidden = alias;
        Actions.Set(command, factory, (cli, result, cancellationToken) => RunAsync(cli, result.GetValue(deviceCode), cancellationToken));
        return command;
    }

    /// <summary>
    /// The method the CLI asks for (node-11 corrected fix item 3): <c>--device-code</c>; else DEVICE_CODE when the CLI runs over SSH, or on
    /// Linux without a graphical session; else BROWSER. Under <c>--test-mode</c> the environment rule is skipped (item 4).
    /// </summary>
    public static SignInMethod Method(bool deviceCode, bool testMode, Func<string, string?> environment, bool linux)
    {
        ArgumentNullException.ThrowIfNull(environment);
        if (deviceCode)
        {
            return SignInMethod.DeviceCode;
        }

        if (testMode)
        {
            return SignInMethod.Browser;
        }

        static bool Set(string? value) => !string.IsNullOrEmpty(value);
        if (Set(environment("SSH_CONNECTION")) || Set(environment("SSH_TTY")))
        {
            return SignInMethod.DeviceCode;
        }

        return linux && !Set(environment("DISPLAY")) && !Set(environment("WAYLAND_DISPLAY")) ? SignInMethod.DeviceCode : SignInMethod.Browser;
    }

    /// <summary>The exit code of a flow's end state (the flow decides, not its error's category).</summary>
    public static int ExitFor(SignInFlowState state) => state == SignInFlowState.SignedIn ? ExitCodes.Success : ExitCodes.Failed;

    /// <summary>True for a state the flow does not leave.</summary>
    public static bool Ended(SignInFlowState state) =>
        state is SignInFlowState.SignedIn or SignInFlowState.Denied or SignInFlowState.Expired or SignInFlowState.Failed or SignInFlowState.Cancelled;

    private static async Task<int> RunAsync(Cli cli, bool deviceCode, CancellationToken cancellationToken)
    {
        using var interrupts = new Interrupts();
        var method = Method(deviceCode, cli.TestMode, Environment.GetEnvironmentVariable, OperatingSystem.IsLinux());
        await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
        var request = new AccountServiceBeginSignInRequest { Meta = Cli.Meta(), Method = method };
        var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
        var begun = await cli.MutateAsync("BeginSignIn", request.Meta.CommandId, action, r => session.Channel.Account.BeginSignInAsync(r,
            deadline: cli.Deadline(BeginDeadline), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
        if (begun.Error is { } error)
        {
            return Refused(cli, error, request.Meta.CorrelationId);
        }

        var printer = new FlowPrinter(cli);
        var flow = begun.Value.Flow;
        if (flow.Method != method && !flow.FellBackToDeviceCode)
        {
            cli.Output.Note("a sign-in is already in progress on this node; following it");
        }

        printer.Show(flow, begun.Meta.Warnings);
        while (!Ended(flow.State))
        {
            var tick = Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
            if (await Task.WhenAny(tick, interrupts.Next).ConfigureAwait(false) != tick)
            {
                return await CancelAsync(cli, session, flow, interrupts, printer).ConfigureAwait(false);
            }

            var (next, exit) = await ReadAsync(cli, session, flow.FlowId, CancellationToken.None).ConfigureAwait(false);
            if (next is null)
            {
                return exit;
            }

            flow = next;
            printer.Show(flow, []);
        }

        return printer.End(flow);
    }

    private static int Refused(Cli cli, ArcError error, Id? correlation)
    {
        if (!cli.Output.Json && error is { Category: ErrorCategory.Authorization, Code: "permission_denied" })
        {
            cli.Output.Error.WriteLine("error: signing in needs a person at an interactive terminal; run 'arcforges login' in a terminal (AUTHORIZATION/permission_denied)");
            return ExitCodes.PermissionDenied;
        }

        if (!cli.Output.Json && error is { Code: "invalid_state" } && error.Details?.State is { } state)
        {
            cli.Output.Error.WriteLine("error: " + StateText(state.State, state.Reason) + " (STATE/invalid_state)");
            return ExitCodes.Failed;
        }

        return cli.Output.Fail(error, correlation);
    }

    /// <summary>The words for BeginSignIn's <c>STATE/invalid_state</c> preconditions.</summary>
    internal static string StateText(string state, string reason) => (state, reason) switch
    {
        ("signed_in", _) => "this node is already signed in; run 'arcforges logout' first",
        ("signed_out", "center_url") => "this node has no center configured; run 'arcforges center set <url>' first",
        ("signed_out", "ending") => "the previous sign-out is still finishing; try again in a minute",
        ("signed_out", "credential_for_other_center") => "the node holds a credential of another center; set that center again, or run 'arcforges logout --local'",
        ("signed_out", "credential_backend_changed" or "credential_for_other_node") =>
            "the node holds a credential it cannot use (another secret store or node ID); restore it, or forget it with 'arcforges logout --local'",
        ("signed_out", "credential_store_unavailable") => "the secret store cannot be read now; the node retries it, try again later",
        ("center_refused", _) => "the center refused the sign-in request (" + reason + ")",
        _ => state + ": " + reason,
    };

    private static async Task<(SignInFlow? Flow, int Exit)> ReadAsync(Cli cli, NodeSession session, Id flowId, CancellationToken cancellationToken)
    {
        var meta = Cli.Meta();
        var response = await cli.CallAsync("GetSignInFlow", meta, () => session.Channel.Account.GetSignInFlowAsync(
            new AccountServiceGetSignInFlowRequest { Meta = meta, FlowId = flowId }, deadline: cli.Deadline(ReadDeadline), cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (response.Error is { } error)
        {
            if (error.Code == "not_found" && !cli.Output.Json)
            {
                cli.Output.Error.WriteLine("error: the sign-in is gone (the node restarted, which cancels a sign-in); run 'arcforges login' again (STATE/not_found)");
                return (null, ExitCodes.Failed);
            }

            var exit = cli.Output.Fail(error, meta.CorrelationId);
            return (null, error.Code == "not_found" ? ExitCodes.Failed : exit);
        }

        return (response.Value.Flow, ExitCodes.Success);
    }

    /// <summary>Ctrl+C: CancelSignIn; a completing flow is followed (a second Ctrl+C stops waiting); exit 130.</summary>
    private static async Task<int> CancelAsync(Cli cli, NodeSession session, SignInFlow flow, Interrupts interrupts, FlowPrinter printer)
    {
        interrupts.Reset();
        var request = new AccountServiceCancelSignInRequest { Meta = Cli.Meta(), FlowId = flow.FlowId };
        var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
        using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var response = await cli.MutateAsync("CancelSignIn", request.Meta.CommandId, action, r => session.Channel.Account.CancelSignInAsync(r,
            deadline: cli.Deadline(ReadDeadline), cancellationToken: bound.Token), bound.Token).ConfigureAwait(false);
        if (response.Error is null)
        {
            printer.Show(response.Value.Flow, []);
            if (!cli.Output.Json)
            {
                cli.Output.Error.WriteLine("Sign-in cancelled.");
            }

            return 130;
        }

        if (response.Error is { Code: "invalid_state" } refused && refused.Details?.State?.Reason == "completing")
        {
            if (!cli.Output.Json)
            {
                cli.Output.Error.WriteLine("The sign-in is completing; waiting for it (Ctrl+C again to stop waiting).");
            }

            var until = DateTime.UtcNow + TimeSpan.FromSeconds(20);
            while (DateTime.UtcNow < until)
            {
                var tick = Task.Delay(TimeSpan.FromSeconds(1));
                if (await Task.WhenAny(tick, interrupts.Next).ConfigureAwait(false) != tick)
                {
                    return 130;
                }

                var (next, exit) = await ReadAsync(cli, session, flow.FlowId, CancellationToken.None).ConfigureAwait(false);
                if (next is null)
                {
                    return exit;
                }

                printer.Show(next, []);
                if (Ended(next.State))
                {
                    return printer.End(next);
                }
            }

            return 130;
        }

        // The flow ended meanwhile: report how it ended.
        var (last, code) = await ReadAsync(cli, session, flow.FlowId, CancellationToken.None).ConfigureAwait(false);
        return last is null ? code : printer.End(last);
    }

    /// <summary>Prints the flow's instructions once per URL or code, and each state change in <c>--json</c> (JSON Lines).</summary>
    private sealed class FlowPrinter(Cli cli)
    {
        private string? _shown;
        private SignInFlowState? _state;
        private bool _ended;

        public void Show(SignInFlow flow, IEnumerable<string> warnings)
        {
            var output = cli.Output;
            var key = flow.Method + "|" + flow.AuthorizeUrl + "|" + flow.UserCode;
            if (output.Json)
            {
                if (_state != flow.State || _shown != key)
                {
                    output.JsonLine(flow);
                }

                _state = flow.State;
                _shown = key;
                return;
            }

            if (_shown != key && (Printable(flow.AuthorizeUrl) || IsUserCode(flow.UserCode)))
            {
                if (_shown is not null)
                {
                    output.Line(flow.Method == SignInMethod.DeviceCode
                        ? "The center asked for a new node key; the code changed:"
                        : "The center asked for a new node key; the sign-in link changed:");
                }

                if (flow.FellBackToDeviceCode)
                {
                    output.Line("This computer could not open a local port for the browser sign-in; using a device code instead.");
                }

                if (flow.Method == SignInMethod.DeviceCode && IsUserCode(flow.UserCode) && Printable(flow.VerificationUri) && Printable(flow.VerificationUriComplete))
                {
                    output.Line($"To sign this node in, open {flow.VerificationUri} on any device and enter the code:");
                    output.Line();
                    output.Essential("    " + flow.UserCode[..4] + "-" + flow.UserCode[4..]);
                    output.Line();
                    output.Line($"or open {flow.VerificationUriComplete}");
                    Common(flow, flow.VerificationUri);
                    output.Line("The page asks for the last group of the fingerprint: " + LastGroup(flow.NodeKeyFingerprint));
                }
                else if (Printable(flow.AuthorizeUrl))
                {
                    output.Line("Opening your browser to sign this node in. If it does not open, open this URL in a browser on THIS computer:");
                    output.Line();
                    output.Essential("    " + flow.AuthorizeUrl);
                    output.Line();
                    Common(flow, flow.AuthorizeUrl);
                }

                output.Line("Waiting for the approval (Ctrl+C cancels)...");
                _shown = key;
            }

            foreach (var warning in warnings)
            {
                if (warning == "browser_not_opened")
                {
                    output.Note("the browser did not open; open the URL above yourself");
                }
            }

            _state = flow.State;
        }

        public int End(SignInFlow flow)
        {
            if (_ended)
            {
                return ExitFor(flow.State);
            }

            _ended = true;
            if (cli.Output.Json)
            {
                Show(flow, []);
                return ExitFor(flow.State);
            }

            var text = flow.State switch
            {
                SignInFlowState.SignedIn => "Signed in.",
                SignInFlowState.Denied => "error: the sign-in was denied on the center's page",
                SignInFlowState.Expired => "error: the sign-in expired before it was approved; run 'arcforges login' again",
                SignInFlowState.Cancelled => "error: the sign-in was cancelled",
                _ => "error: the sign-in failed" + (flow.Error is { } error ? ": " + Failure(error) + $" ({error.Category.ToString().ToUpperInvariant()}/{error.Code})" : string.Empty),
            };
            if (flow.State == SignInFlowState.SignedIn)
            {
                cli.Output.Line(text);
            }
            else
            {
                cli.Output.Error.WriteLine(text);
            }

            return ExitFor(flow.State);
        }

        private void Common(SignInFlow flow, string url)
        {
            var host = Uri.TryCreate(url, UriKind.Absolute, out var parsed) ? parsed.Authority : string.Empty;
            cli.Output.Line("Center:          " + host);
            if (Fingerprint(flow.NodeKeyFingerprint))
            {
                cli.Output.Line("Key fingerprint: " + flow.NodeKeyFingerprint + (flow.Method == SignInMethod.Browser ? " (compare it with the page)" : string.Empty));
            }
        }

        private static string Failure(ArcError error) => (error.Code, error.Details?.State?.State, error.Details?.State?.Reason) switch
        {
            ("invalid_argument", _, { } reason) when reason.EndsWith("center_url_mismatch", StringComparison.Ordinal) =>
                "the center answered with a URL that does not match the configured center (a self-hosted center's public base URL must equal the URL its nodes are configured with)",
            ("unauthenticated", _, _) => "the center refused the node's proof (a self-hosted center's public base URL must equal the URL its nodes are configured with)",
            ("code_reused", _, _) => "the sign-in code was used twice; the center revoked this sign-in: sign in again",
            ("already_exists", "node", _) => "this node is enrolled in another account; revoke the device there",
            ("quota_exceeded", _, _) => "the account reached its node limit" + (error.Details?.Limit?.Maximum?.Value is { Length: > 0 } maximum ? " (" + maximum + ")" : string.Empty),
            ("cloud_unreachable", _, "complete_reply_lost" or "poll_reply_lost") => "the center's reply was lost; sign in again",
            ("cloud_unreachable", _, _) => "the center could not be reached",
            ("invalid_state", "signing_in", "center_url") => "the configured center changed during the sign-in",
            _ => Messages.For(error),
        };

        private static string LastGroup(string fingerprint) => Fingerprint(fingerprint) ? fingerprint[^4..] : string.Empty;
    }

    /// <summary>A flow field is printed only in its own shape (a defence in depth: never a control character).</summary>
    internal static bool Printable(string? url) =>
        url is { Length: > 0 and <= 512 } && (url.StartsWith("https://", StringComparison.Ordinal) || url.StartsWith("http://", StringComparison.Ordinal))
        && url.All(c => c is > ' ' and < (char)0x7f);

    /// <summary>8 letters of the user code alphabet.</summary>
    internal static bool IsUserCode(string? code) => code is { Length: 8 } && code.All(c => "BCDFGHJKLMNPQRSTVWXZ".Contains(c, StringComparison.Ordinal));

    /// <summary>The fingerprint shape <c>XXXX-XXXX-XXXX-XXXX-XXXX</c> (upper-case hex).</summary>
    internal static bool Fingerprint(string? value) =>
        value is { Length: 24 } && value.Select((c, i) => i % 5 == 4 ? c == '-' : char.IsAsciiHexDigitUpper(c)).All(ok => ok);

    /// <summary>Ctrl+C and SIGTERM as a signal to cancel the flow (they do not end the CLI by themselves).</summary>
    private sealed class Interrupts : IDisposable
    {
        private readonly List<PosixSignalRegistration> _registrations = [];
        private TaskCompletionSource _next = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Interrupts()
        {
            foreach (var signal in new[] { PosixSignal.SIGINT, PosixSignal.SIGTERM })
            {
                try
                {
                    _registrations.Add(PosixSignalRegistration.Create(signal, context =>
                    {
                        context.Cancel = true;
                        Volatile.Read(ref _next).TrySetResult();
                    }));
                }
                catch (PlatformNotSupportedException)
                {
                }
            }
        }

        public Task Next => Volatile.Read(ref _next).Task;

        public void Reset() => Interlocked.Exchange(ref _next, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));

        public void Dispose()
        {
            foreach (var registration in _registrations)
            {
                registration.Dispose();
            }
        }
    }
}
