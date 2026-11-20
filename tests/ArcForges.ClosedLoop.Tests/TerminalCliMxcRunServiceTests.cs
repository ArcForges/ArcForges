// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Security.Secrets;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    [Fact(Timeout = 150_000, DisableParallelization = true)]
    public async Task InstalledCliUsesTheNativeHostTerminalForTuiResizeDetachAndForegroundInterrupt()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        await using var fixture = await TerminalCliFixture.StartAsync();
        var marker = Path.Combine(fixture.Working, "cli-tui.log");

        Run tui;
        ulong cursor;
        using var tuiDeadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        tuiDeadline.CancelAfter(TimeSpan.FromSeconds(60));
        var tuiToken = tuiDeadline.Token;
        await using (var host = await fixture.OpenTerminalAsync(27, 93, tuiToken,
            fixture.StartArguments(fixture.Payload, "terminal", "tui", marker)))
        {
            await using var canvas = new TerminalCliCanvas(host.Output, tuiToken);
            await WaitMarkerAsync(marker, "ready 27 93");
            tui = await fixture.OnlyNewRunAsync(null, tuiToken);
            Assert.Equal(TerminalMode.Interactive, tui.TerminalMode);
            await canvas.WaitForAsync("CORE03", tuiToken);
            await host.RequireActiveModeAsync(tuiToken);
            host.Resize(35, 107);
            await WaitMarkerAsync(marker, "resize 35 107");
            await canvas.WaitForAsync("35x107", tuiToken);
            cursor = await CaptureTerminalCliCursorAsync(fixture.Runs, tui, "CORE03 redraw 星 35x107", tuiToken);
            await host.SendAsync("星"u8.ToArray(), tuiToken);
            await WaitMarkerAsync(marker, "unicode");
            await host.SendAsync(new byte[] { 3 }, tuiToken);
            await WaitMarkerAsync(marker, "raw-etx");

            await host.SendAsync(new byte[] { 29, (byte)'d' }, tuiToken);
            Assert.Equal(0, await host.WaitForExitAsync(tuiToken));
            await host.RequireRestoredModeAsync(tuiToken);
        }

        Assert.Equal(RunState.Running, (await InspectAsync(fixture.Runs, tui.RunId, tuiToken)).State);
        var original = ReadSupervisor(fixture.Node.DataRoot, tui);
        await using (var host = await fixture.OpenTerminalAsync(35, 107, tuiToken, "run", "attach", IdText.Format(tui.RunId),
            "--no-detach-escape", "--offset", cursor.ToString(CultureInfo.InvariantCulture)))
        {
            await using var canvas = new TerminalCliCanvas(host.Output, tuiToken);
            await canvas.WaitForLeaseAsync(IdText.Format(tui.RunId), tuiToken);
            Assert.Equal(original, ReadSupervisor(fixture.Node.DataRoot, tui));
            host.Resize(38, 112);
            await WaitMarkerAsync(marker, "resize 38 112");
            await canvas.WaitForAsync("38x112", tuiToken);
            Assert.False(canvas.Contains("35x107"), "Reattaching from a retained cursor replayed already delivered output.");
            await host.SendAsync(new byte[] { 29, (byte)'d' }, tuiToken);
            await WaitMarkerAsync(marker, "literal-detach");
            await host.SendAsync("q"u8.ToArray(), tuiToken);
            await WaitMarkerAsync(marker, "restored");
            await RequireUnconfirmedCliZeroAsync(await host.WaitForExitAsync(tuiToken), canvas, tuiToken);
            await host.RequireRestoredModeAsync(tuiToken);
        }

        var tuiExit = await fixture.WaitExitedAsync(tui.RunId, tuiToken);
        RequireObservedCliExit(tuiExit, 0);
        var transcript = await WatchAsync(fixture.Runs, tuiExit, StreamKind.Terminal);
        Assert.Null(transcript.Gap);
        var ownedCanvas = Encoding.UTF8.GetString(transcript.Bytes);
        Assert.Contains("\u001b[?1049h", ownedCanvas, StringComparison.Ordinal);
        Assert.Contains("\u001b[?1049l", ownedCanvas, StringComparison.Ordinal);
        Assert.Contains("CORE03 redraw 星 35x107", ownedCanvas, StringComparison.Ordinal);
        Assert.Contains("CORE03 redraw 星 38x112", ownedCanvas, StringComparison.Ordinal);
        await RequireCliJsonLogStreamsAsync(fixture.Node, tui.RunId, ["terminal"]);
        var settledAttach = await RunInstalledCliAsync(fixture.Node, "run", "attach", IdText.Format(tui.RunId));
        Assert.Equal(8, settledAttach.ExitCode);
        Assert.True(transcript.Bytes.AsSpan().SequenceEqual(settledAttach.Stdout));
        var settledError = Encoding.UTF8.GetString(settledAttach.Stderr);
        Assert.Contains("official executor reported exit 0", settledError, StringComparison.Ordinal);
        Assert.Contains("trustworthy_run_exit_unavailable", settledError, StringComparison.Ordinal);
        Assert.Contains("EXECUTION/terminal_ack_unavailable", settledError, StringComparison.Ordinal);

        var signalMarker = Path.Combine(fixture.Working, "cli-signal.log");
        string[] signal = OperatingSystem.IsLinux()
            ? ["/usr/bin/bash", "--noprofile", "--norc", "-i", "-c", "\"$0\" \"$@\"", fixture.Payload,
                "terminal", "signal", signalMarker]
            : [fixture.Payload, "terminal", "signal", signalMarker];
        await using var foreground = await fixture.OpenTerminalAsync(28, 97, token, fixture.StartArguments(signal));
        await using var foregroundCanvas = new TerminalCliCanvas(foreground.Output, token);
        await WaitMarkerAsync(signalMarker, "ready 28 97");
        await foreground.RequireActiveModeAsync(token);
        await foregroundCanvas.WaitForAsync("CORE03 foreground ready", token);
        var signalRun = await fixture.OnlyNewRunAsync(tui.RunId, token);
        await foreground.SendAsync(new byte[] { 3 }, token);
        var result = await fixture.WaitExitedAsync(signalRun.RunId, token);
        int status = await foreground.WaitForExitAsync(token).WaitAsync(NativeBound, token);
        await foreground.RequireRestoredModeAsync(token);
        var signalLines = ReadLines(signalMarker);
        Assert.DoesNotContain(signalLines, line => line.StartsWith("error ", StringComparison.Ordinal));
        Assert.NotEqual("user_stop", result.Exit.TerminationReason);
        Assert.NotEqual("pressure_preempted", result.Exit.TerminationReason);
        if (OperatingSystem.IsWindows() && !signalLines.Contains("sigint", StringComparer.Ordinal))
        {
            Assert.Equal(ExitSource.OfficialExecutor, result.Exit.Source);
            RequireObservedCliExit(result, unchecked((int)0xC000013A));
            Assert.Equal(result.Exit.RawCode, status);
        }
        else
        {
            Assert.Contains("sigint", signalLines);
            Assert.Contains("restored", signalLines);
            RequireObservedCliExit(result, 0);
            await RequireUnconfirmedCliZeroAsync(status, foregroundCanvas, token);
        }
    }

    private static async Task<ulong> CaptureTerminalCliCursorAsync(RunService.RunServiceClient runs, Run run,
        string displayed, CancellationToken token)
    {
        using var call = StartWatch(runs, run, StreamKind.Terminal, 0);
        using var output = new MemoryStream();
        ulong next = 0;
        while (await call.ResponseStream.MoveNext(token))
        {
            var frame = call.ResponseStream.Current;
            Assert.Null(frame.Error);
            Assert.Null(frame.Gap);
            var chunk = Assert.IsType<OutputChunk>(frame.Chunk);
            Assert.Equal(run.Epoch, chunk.Epoch);
            Assert.Equal(StreamKind.Terminal, chunk.Stream);
            Assert.Equal(next, chunk.Offset);
            Assert.True(chunk.NextOffset > chunk.Offset);
            Assert.InRange(output.Length + chunk.Data.Length, 1, 1_048_576);
            output.Write(chunk.Data.Span);
            next = chunk.NextOffset;
            if (Encoding.UTF8.GetString(output.GetBuffer().AsSpan(0, (int)output.Length)).Contains(displayed, StringComparison.Ordinal))
            {
                return next;
            }
        }

        throw new InvalidDataException("Typed output ended before the live terminal cursor was observed.");
    }

    private static void RequireObservedCliExit(Run run, int status)
    {
        var exit = run.Exit;
        Assert.True(exit.GroupEmptyVerified);
        Assert.True(exit.HasRawCode);
        Assert.Equal(status, exit.RawCode);
        Assert.True(exit.Source is ExitSource.Payload or ExitSource.OfficialExecutor);
        if (status == 0)
        {
            // The fixed official executor supplies a drained exit code, but no independent payload-start receipt.
            Assert.Equal(ExitSource.OfficialExecutor, exit.Source);
            Assert.Equal(PayloadStartEvidence.Unknown, exit.PayloadStarted);
            Assert.Equal(EffectCertainty.Unknown, exit.Effect);
        }
        else if (exit.Effect == EffectCertainty.Unknown)
        {
            Assert.Equal(ExitSource.OfficialExecutor, exit.Source);
        }
    }

    private static async Task RequireUnconfirmedCliZeroAsync(int status, TerminalCliCanvas diagnostics, CancellationToken token)
    {
        Assert.Equal(8, status);
        await diagnostics.WaitForAsync("official executor reported exit 0", token);
        await diagnostics.WaitForAsync("trustworthy_run_exit_unavailable", token);
        await diagnostics.WaitForAsync("EXECUTION/terminal_ack_unavailable", token);
        await diagnostics.WaitForAsync("effect Unknown", token);
    }

    [Fact(Timeout = 100_000, DisableParallelization = true)]
    public async Task InstalledCliPreservesBinaryPipesEofAndApplicationExit()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        await using var fixture = await TerminalCliFixture.StartAsync();
        var unavailable = await RunInstalledCliAsync(fixture.Node, "run", "start", fixture.SandboxText,
            "--terminal", "on", "--", fixture.Payload, "echo");
        Assert.Equal(5, unavailable.ExitCode);
        Assert.Contains("terminal_unavailable", Encoding.UTF8.GetString(unavailable.Stderr), StringComparison.Ordinal);
        Assert.Empty(await ListAsync(fixture.Runs, fixture.Sandbox.SandboxId));

        var eofMarker = Path.Combine(fixture.Working, "cli-pipe-eof");
        var resume = Path.Combine(fixture.Working, "cli-pipe-release");
        string[] workload = PipeWorkload(fixture, eofMarker, resume);
        Id? pipeRun = null;
        using var child = fixture.OpenPipes(fixture.StartArguments(workload, terminal: "off"));
        try
        {
            var run = await fixture.OnlyNewRunAsync(null, token);
            pipeRun = run.RunId;
            Assert.Equal(TerminalMode.Pipes, run.TerminalMode);
            await WaitForStateAsync(fixture.Node, fixture.Runs, run.RunId, RunState.Running, token);
            using var output = new MemoryStream();
            using var errors = new MemoryStream();
            var stderr = child.StandardError.BaseStream.CopyToAsync(errors, token);
            var bytes = new byte[65_536];
            for (int index = 0; index < bytes.Length; index++) bytes[index] = (byte)index;

            var prefix = new byte[1024];
            var sending = child.StandardInput.BaseStream.WriteAsync(bytes, token).AsTask();
            await child.StandardOutput.BaseStream.ReadExactlyAsync(prefix, token).AsTask().WaitAsync(NativeBound, token);
            output.Write(prefix);
            var stdout = child.StandardOutput.BaseStream.CopyToAsync(output, token);
            await sending.WaitAsync(NativeBound, token);
            await child.StandardInput.BaseStream.FlushAsync(token);
            Assert.True(prefix.AsSpan().SequenceEqual(bytes.AsSpan(0, prefix.Length)));
            Assert.False(File.Exists(eofMarker));
            Assert.Equal(RunState.Running, (await InspectAsync(fixture.Runs, run.RunId, token)).State);

            child.StandardInput.Close();
            await TestNode.WaitAsync(() => File.Exists(eofMarker), NativeBound, "the native payload's EOF marker");
            Assert.Equal(RunState.Running, (await InspectAsync(fixture.Runs, run.RunId, token)).State);
            await File.WriteAllTextAsync(resume, "release", token);
            await child.WaitForExitAsync(token).WaitAsync(NativeBound, token);
            await Task.WhenAll(stdout, stderr).WaitAsync(NativeBound, token);
            Assert.Equal(7, child.ExitCode);
            Assert.True(bytes.AsSpan().SequenceEqual(output.ToArray()), "CLI stdout did not preserve the native binary payload.");
            Assert.Contains("cli-pipe-stderr", Encoding.UTF8.GetString(errors.ToArray()), StringComparison.Ordinal);

            var final = await fixture.WaitExitedAsync(run.RunId, token);
            RequireObservedCliExit(final, 7);
            var retained = await WatchAsync(fixture.Runs, final, StreamKind.Stdout);
            Assert.Null(retained.Gap);
            Assert.Equal((ulong)bytes.Length, retained.Offset);
            Assert.True(bytes.AsSpan().SequenceEqual(retained.Bytes));
            var retainedError = await WatchAsync(fixture.Runs, final, StreamKind.Stderr);
            Assert.Null(retainedError.Gap);
            Assert.Equal("cli-pipe-stderr", Encoding.UTF8.GetString(retainedError.Bytes).TrimEnd('\r', '\n'));
            await RequireCliJsonLogStreamsAsync(fixture.Node, run.RunId, ["stderr", "stdout"]);
        }
        finally
        {
            await KillOwnedCliAsync(child);
        }

        await RequirePipesOnCallerTerminalAsync(fixture, Assert.IsType<Id>(pipeRun), token);
    }

    private static async Task RequireCliJsonLogStreamsAsync(TestNode fixture, Id run, string[] expected)
    {
        var output = await RunInstalledCliAsync(fixture, "--json", "run", "logs", IdText.Format(run));
        Assert.Equal(0, output.ExitCode);
        var finished = new HashSet<string>(StringComparer.Ordinal);
        var chunks = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in Encoding.UTF8.GetString(output.Stdout).Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            using var document = JsonDocument.Parse(line);
            var frame = document.RootElement;
            string stream = Assert.IsType<string>(frame.GetProperty("stream").GetString());
            Assert.Contains(stream, expected);
            Assert.DoesNotContain(stream, finished);
            if (frame.TryGetProperty("run", out _))
            {
                Assert.True(finished.Add(stream));
            }
            else
            {
                Assert.True(frame.TryGetProperty("chunk", out _));
                chunks.Add(stream);
            }
        }

        Assert.Equal(expected, finished.Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(expected, chunks.Order(StringComparer.Ordinal).ToArray());
    }

    private static async Task RequirePipesOnCallerTerminalAsync(TerminalCliFixture fixture, Id previous, CancellationToken token)
    {
        const string anchor = "cli-explicit-pipes-on-real-tty";
        var release = Path.Combine(fixture.Working, "cli-cooked-release");
        var arguments = fixture.StartArguments([fixture.Payload, "hold", "--ready-line", anchor, "--hold-ms", "20000",
            "--until-file", release], terminal: "off");
        await using var host = await fixture.OpenTerminalAsync(23, 100, token, arguments);
        await using var output = new TerminalCliCanvas(host.Output, token);
        var run = await fixture.OnlyNewRunAsync(previous, token);
        Assert.Equal(TerminalMode.Pipes, run.TerminalMode);
        await output.WaitForLeaseAsync(IdText.Format(run.RunId), token);
        await output.WaitForAsync(anchor, token);
        Assert.Equal(RunState.Running, (await InspectAsync(fixture.Runs, run.RunId, token)).State);
        await host.RequireUnmodifiedModeAsync(token);

        await File.WriteAllTextAsync(release, "release", token);
        await RequireUnconfirmedCliZeroAsync(await host.WaitForExitAsync(token).WaitAsync(NativeBound, token), output, token);
        await host.RequireRestoredModeAsync(token);
        var final = await fixture.WaitExitedAsync(run.RunId, token);
        RequireObservedCliExit(final, 0);
        var retained = await WatchAsync(fixture.Runs, final, StreamKind.Stdout);
        Assert.Null(retained.Gap);
        Assert.StartsWith(anchor, Encoding.UTF8.GetString(retained.Bytes), StringComparison.Ordinal);
    }

    private static string[] PipeWorkload(TerminalCliFixture fixture, string eofMarker, string resume)
    {
        if (OperatingSystem.IsLinux())
        {
            const string command = """
                "$1" echo || exit $?
                : > "$2" || exit $?
                printf '%s\n' 'cli-pipe-stderr' >&2
                "$1" hold --hold-ms 20000 --until-file "$3" >/dev/null || exit $?
                test -f "$3" || exit 9
                exit 7
                """;
            return ["/usr/bin/dash", "-c", command, "arcforges-cli-pipe-fixture", fixture.Payload, eofMarker, resume];
        }

        const string batch = """
            @echo off
            arcforges-testload.exe echo
            if not "%errorlevel%"=="0" exit /b %errorlevel%
            type nul > cli-pipe-eof
            if not exist cli-pipe-eof exit /b 9
            echo cli-pipe-stderr 1>&2
            arcforges-testload.exe hold --hold-ms 20000 --until-file cli-pipe-release >nul
            if not exist cli-pipe-release exit /b 9
            exit /b 7
            """;
        File.WriteAllText(Path.Combine(fixture.Working, "cli-pipes.cmd"), batch.ReplaceLineEndings("\r\n"));
        return [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c", "cli-pipes.cmd"];
    }

    [Fact(Timeout = 90_000, DisableParallelization = true)]
    public async Task InstalledCliReportsOutputGapOnStderrWithoutBlockingNativeExit()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        const ulong retainedBytes = 1024 * 1024;
        await using var fixture = await TerminalCliFixture.StartAsync(retainedBytes);
        var marker = Path.Combine(fixture.Working, "cli-output.log");
        var prefixGate = Path.Combine(fixture.Working, "cli-output-prefix");
        var tailGate = Path.Combine(fixture.Working, "cli-output-tail");
        var start = await InstalledCliSuccessAsync(fixture.Node, "run", "start", fixture.SandboxText, "--detach",
            "--terminal", "off", "--cwd", RelativeWorkdir, "--", fixture.Payload, "terminal", "slow-output", marker,
            prefixGate, tailGate);
        var runId = InstalledCliId(start.GetProperty("run"), "runId");
        await WaitMarkerAsync(marker, "started");
        using var viewer = fixture.OpenPipes("run", "logs", IdText.Format(runId), "--follow", "--stream", "stdout");
        viewer.StandardInput.Close();
        try
        {
            using var diagnostics = new MemoryStream();
            var stderr = viewer.StandardError.BaseStream.CopyToAsync(diagnostics, token);
            byte[] anchor = "CORE03 slow viewer \n"u8.ToArray();
            var first = new byte[anchor.Length];
            await viewer.StandardOutput.BaseStream.ReadExactlyAsync(first, token).AsTask().WaitAsync(NativeBound, token);
            Assert.True(anchor.AsSpan().SequenceEqual(first));

            Run settled;
            using (var paused = CancellationTokenSource.CreateLinkedTokenSource(token))
            {
                // Keep the actual CLI stdout backpressured while the independent Node client observes native drain.
                paused.CancelAfter(TimeSpan.FromSeconds(8));
                await File.WriteAllTextAsync(prefixGate, "prefix", paused.Token);
                await WaitSlowMarkerAsync(marker, "prefix-complete", paused.Token);
                await Task.Delay(350, paused.Token);
                await File.WriteAllTextAsync(tailGate, "tail", paused.Token);
                await WaitSlowMarkerAsync(marker, "finished", paused.Token);
                settled = await fixture.WaitExitedAsync(runId, paused.Token);
            }

            using var received = new MemoryStream();
            await viewer.StandardOutput.BaseStream.CopyToAsync(received, token).WaitAsync(NativeBound, token);
            await viewer.WaitForExitAsync(token).WaitAsync(NativeBound, token);
            await stderr.WaitAsync(NativeBound, token);
            Assert.Equal(0, viewer.ExitCode);
            var gapDiagnostics = Encoding.UTF8.GetString(diagnostics.ToArray());
            Assert.Contains("output GAP (stdout, slow_consumer)", gapDiagnostics, StringComparison.Ordinal);

            var fresh = await WatchAsync(fixture.Runs, settled, StreamKind.Stdout);
            Assert.NotNull(fresh.Gap);
            Assert.Equal("retention", fresh.Gap.Reason);
            Assert.Equal((ulong)(anchor.Length + 512 * 1024 + 3 * 1024 * 1024), fresh.Offset);
            Assert.InRange(fresh.Bytes.Length, 1, (int)retainedBytes);
            Assert.True(fresh.Bytes.AsSpan().IndexOfAnyExcept((byte)'T') < 0);
            var recovered = received.ToArray();
            Assert.True(recovered.AsSpan().IndexOfAnyExcept((byte)'P', (byte)'T') < 0);
            Assert.True(recovered.AsSpan().EndsWith(fresh.Bytes), "CLI stdout lost bytes from the stable retained suffix.");
            ulong omitted = CliGapBytes(gapDiagnostics, (ulong)anchor.Length, fresh.Gap.EarliestOffset);
            Assert.Equal(fresh.Offset, (ulong)(anchor.Length + recovered.Length) + omitted);
        }
        finally
        {
            await KillOwnedCliAsync(viewer);
        }
    }

    private static ulong CliGapBytes(string diagnostics, ulong earliest, ulong stableEarliest)
    {
        ulong omitted = 0;
        const string requested = " Requested offset ";
        const string advanced = ". First retained offset ";
        foreach (string line in diagnostics.Split('\n').Where(line => line.Contains("output GAP (stdout, ", StringComparison.Ordinal)))
        {
            int offsetStart = line.IndexOf(requested, StringComparison.Ordinal);
            int earliestStart = line.IndexOf(advanced, StringComparison.Ordinal);
            Assert.True(offsetStart >= 0 && earliestStart > offsetStart + requested.Length);
            ReadOnlySpan<char> initial = line.AsSpan((offsetStart + requested.Length)..earliestStart);
            ReadOnlySpan<char> next = line.AsSpan(earliestStart + advanced.Length).TrimEnd().TrimEnd('.');
            Assert.True(ulong.TryParse(initial, NumberStyles.None, CultureInfo.InvariantCulture, out ulong start));
            Assert.True(ulong.TryParse(next, NumberStyles.None, CultureInfo.InvariantCulture, out ulong end));
            Assert.InRange(start, earliest, stableEarliest - 1);
            Assert.InRange(end, start + 1, stableEarliest);
            omitted += end - start;
            earliest = end;
        }

        return omitted;
    }

    [Fact(Timeout = 150_000, DisableParallelization = true)]
    public async Task InstalledCliEnforcesWriterTakeoverExplicitDetachAndQuietInputPrivacy()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        await using var fixture = await TerminalCliFixture.StartAsync();
        var marker = Path.Combine(fixture.Working, "cli-quiet.log");
        var canary = Encoding.ASCII.GetBytes("quiet-cli-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)));
        byte[] literal = [29, (byte)'d', (byte)'x'];
        int expected = canary.Length + literal.Length;
        await using var first = await fixture.OpenTerminalAsync(29, 120, token, fixture.StartArguments(fixture.Payload,
            "terminal", "quiet", marker, expected.ToString(CultureInfo.InvariantCulture), "1200"));
        await using var firstOutput = new TerminalCliCanvas(first.Output, token);
        await WaitMarkerAsync(marker, "ready 29 120");
        var run = await fixture.OnlyNewRunAsync(null, token);
        var runText = IdText.Format(run.RunId);
        var original = ReadSupervisor(fixture.Node.DataRoot, run);
        var priorLease = await firstOutput.WaitForLeaseAsync(runText, token);
        await first.SendAsync(canary, token);
        await WaitMarkerAsync(marker, FormattableString.Invariant($"consumed {canary.Length}"));

        using var observer = fixture.OpenPipes("run", "attach", runText, "--read-only");
        observer.StandardInput.Close();
        try
        {
            using var observerBytes = new MemoryStream();
            var observerOutput = observer.StandardOutput.BaseStream.CopyToAsync(observerBytes, token);
            await using var observerStatus = new TerminalCliCanvas(observer.StandardError.BaseStream, token);
            await observerStatus.WaitForAsync(" observer", token);
            await RequireCliTakeoverAndDetachAsync(fixture, first, firstOutput, runText, priorLease, token);
            Assert.Equal(RunState.Running, (await InspectAsync(fixture.Runs, run.RunId, token)).State);
            Assert.Equal(original, ReadSupervisor(fixture.Node.DataRoot, run));
            await using (var next = await fixture.OpenTerminalAsync(29, 120, token, "run", "attach", runText, "--no-detach-escape"))
            {
                await using var nextOutput = new TerminalCliCanvas(next.Output, token);
                var nextLease = await nextOutput.WaitForLeaseAsync(runText, token);
                Assert.NotEqual(priorLease, nextLease);
                await next.SendAsync(literal, token);
                await WaitMarkerAsync(marker, FormattableString.Invariant($"consumed {expected}"));
                await WaitMarkerAsync(marker, "restored");
                await RequireUnconfirmedCliZeroAsync(await next.WaitForExitAsync(token).WaitAsync(NativeBound, token), nextOutput, token);
                await next.RequireRestoredModeAsync(token);
            }

            var final = await fixture.WaitExitedAsync(run.RunId, token);
            RequireObservedCliExit(final, 0);
            var retained = await WatchAsync(fixture.Runs, run, StreamKind.Terminal);
            Assert.Null(retained.Gap);
            Assert.True(retained.Bytes.AsSpan().IndexOf(canary) < 0);
            await observer.WaitForExitAsync(token).WaitAsync(NativeBound, token);
            await RequireUnconfirmedCliZeroAsync(observer.ExitCode, observerStatus, token);
            await observerOutput.WaitAsync(NativeBound, token);
            Assert.True(retained.Bytes.AsSpan().SequenceEqual(observerBytes.ToArray()));
            AssertNoDurableInput(fixture.Node, canary, []);
        }
        finally
        {
            await KillOwnedCliAsync(observer);
        }
    }

    private static async Task RequireCliTakeoverAndDetachAsync(TerminalCliFixture fixture, TerminalCliOuter first,
        TerminalCliCanvas firstOutput, string runText, string priorLease, CancellationToken token)
    {
        await using (var contender = await fixture.OpenTerminalAsync(29, 120, token, "run", "attach", runText))
        {
            await using var contenderOutput = new TerminalCliCanvas(contender.Output, token);
            await contenderOutput.WaitForAsync("busy", token);
            Assert.Equal(3, await contender.WaitForExitAsync(token).WaitAsync(NativeBound, token));
            await contender.RequireRestoredModeAsync(token);
        }

        await using var winner = await fixture.OpenTerminalAsync(29, 120, token, "run", "attach", runText, "--takeover");
        await using var winnerOutput = new TerminalCliCanvas(winner.Output, token);
        var currentLease = await winnerOutput.WaitForLeaseAsync(runText, token);
        Assert.NotEqual(priorLease, currentLease);
        await firstOutput.WaitForAsync("lease_stale", token);
        Assert.Equal(3, await first.WaitForExitAsync(token).WaitAsync(NativeBound, token));
        await first.RequireRestoredModeAsync(token);

        var detached = await InstalledCliSuccessAsync(fixture.Node, "run", "detach", runText, "--lease", currentLease);
        Assert.True(detached.GetProperty("detached").GetBoolean());
        Assert.Equal(0, await winner.WaitForExitAsync(token).WaitAsync(NativeBound, token));
        await winner.RequireRestoredModeAsync(token);
    }

    [Fact(Timeout = 110_000, DisableParallelization = true)]
    public async Task InstalledCliRefusesAnotherModeChangingAttachmentOnTheSameHostTerminal()
    {
        var token = TestContext.Current.CancellationToken;
        token.ThrowIfCancellationRequested();
        await using var fixture = await TerminalCliFixture.StartAsync();
        var independent = await fixture.CreateAuxiliarySandboxAsync(token);
        var first = await fixture.StartQuietProbeAsync(fixture.Sandbox, token);
        var second = await fixture.StartQuietProbeAsync(independent, token);
        Assert.NotEqual(first.Run.RunId, second.Run.RunId);
        string firstRun = IdText.Format(first.Run.RunId);
        string secondRun = IdText.Format(second.Run.RunId);
        string coordination = Directory.CreateDirectory(Path.Combine(fixture.Node.Root, "shared-caller")).FullName;
        await using var host = await TerminalCliOuter.StartSharedAsync(fixture.Node, firstRun, secondRun, coordination, token);
        await using var output = new TerminalCliCanvas(host.Output, token);
        await output.WaitForLeaseAsync(firstRun, token);
        await host.RequireActiveModeAsync(token);
        var runningMode = await host.ReadModeAsync(token);

        Assert.Equal(3, await host.ContendAsync(fixture.Node, secondRun, coordination, token));
        await output.WaitForAsync("caller_terminal_in_use", token);
        Assert.Equal(runningMode, await host.ReadModeAsync(token));
        Assert.DoesNotContain(ReadLines(first.Marker), line => line.StartsWith("consumed ", StringComparison.Ordinal));
        Assert.DoesNotContain(ReadLines(second.Marker), line => line.StartsWith("consumed ", StringComparison.Ordinal));
        Assert.Equal(RunState.Running, (await InspectAsync(fixture.Runs, second.Run.RunId, token)).State);

        await host.SendAsync("z"u8.ToArray(), token);
        await WaitMarkerAsync(first.Marker, "consumed 1");
        await WaitMarkerAsync(first.Marker, "restored");
        await RequireUnconfirmedCliZeroAsync(await host.WaitForExitAsync(token).WaitAsync(NativeBound, token), output, token);
        await host.RequireRestoredModeAsync(token);
        RequireObservedCliExit(await fixture.WaitExitedAsync(first.Run.RunId, token), 0);
        Assert.DoesNotContain(ReadLines(second.Marker), line => line.StartsWith("consumed ", StringComparison.Ordinal));
    }

    private static async Task KillOwnedCliAsync(Process process)
    {
        if (!process.HasExited)
        {
            try
            {
                process.Kill();
            }
            catch (InvalidOperationException) when (process.HasExited)
            {
                // The test-owned CLI exited before the cleanup signal.
            }
        }

        await process.WaitForExitAsync(CancellationToken.None).WaitAsync(NativeBound, CancellationToken.None);
    }

    private sealed class TerminalCliOuter(IAsyncDisposable owner, Stream input, Stream output, Action<ushort, ushort> resize,
        Func<CancellationToken, Task<int>> wait, Func<CancellationToken, Task<bool>> activeMode,
        Func<CancellationToken, Task> requireRestoredMode) : IAsyncDisposable
    {
        internal Stream Output { get; } = output;

        internal static async Task<TerminalCliOuter> StartAsync(string executable, string[] args, string cwd,
            IReadOnlyDictionary<string, string?> environment, ushort rows, ushort columns, CancellationToken token)
        {
            if (OperatingSystem.IsWindows())
            {
                string keeper = Environment.GetEnvironmentVariable("ARCFORGES_TESTLOAD_PATH")
                    ?? throw new InvalidOperationException("The native console mode keeper is required.");
                string observations = Path.Combine(cwd, "console-modes-" + Guid.NewGuid().ToString("N"));
                var terminal = await TerminalCliNativeWindows.StartWithModeKeeperAsync(executable, args, cwd, environment,
                    rows, columns, keeper, observations, token);
                return new(terminal, terminal.Input, terminal.Output, terminal.Resize, terminal.WaitForExitAsync,
                    async ct => OperatingSystem.IsWindows()
                        ? (await terminal.ReadModesAsync(ct)).Input != terminal.InitialModes.Input
                        : throw new PlatformNotSupportedException(), terminal.AssertModeRestoredAsync);
            }

            if (OperatingSystem.IsLinux())
            {
                return WrapLinux(TerminalCliNativeLinux.Start(executable, args, cwd, environment, rows, columns));
            }

            throw new PlatformNotSupportedException();
        }

        internal static async Task<TerminalCliOuter> StartSharedAsync(TestNode node, string first, string second, string control,
            CancellationToken token)
        {
            if (OperatingSystem.IsLinux())
            {
                string controller = Environment.GetEnvironmentVariable("ARCFORGES_TESTLOAD_PATH")
                    ?? throw new InvalidOperationException("The native Linux shared console controller is required.");
                return WrapLinux(TerminalCliNativeLinux.StartControlledPeers(controller, InstalledCliHost, first, second,
                    control, node.Environment, 30, 120));
            }

            return await StartAsync(InstalledCliHost, [NodeLocations.TestModeOption, "run", "attach", first], node.Root,
                node.Environment, 30, 120, token);
        }

        private static TerminalCliOuter WrapLinux(TerminalCliNativeLinux terminal)
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
            return new(terminal, terminal.Input, terminal.Output, terminal.Resize, terminal.WaitForExitAsync,
                _ => OperatingSystem.IsLinux()
                    ? Task.FromResult(terminal.ReadMode().LocalFlags != terminal.OriginalMode.LocalFlags)
                    : throw new PlatformNotSupportedException(), _ =>
                {
                    if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
                    terminal.AssertModeRestored();
                    return Task.CompletedTask;
                });
        }

        internal async Task<int> ContendAsync(TestNode node, string second, string control, CancellationToken token)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(NativeBound);
            if (OperatingSystem.IsWindows() && owner is TerminalCliNativeWindows windows)
            {
                return await windows.RunContenderAsync(InstalledCliHost, [NodeLocations.TestModeOption, "run", "attach", second],
                    node.Root, node.Environment, deadline.Token);
            }

            if (OperatingSystem.IsLinux() && owner is TerminalCliNativeLinux)
            {
                string result = Path.Combine(control, "contender.status");
                await File.WriteAllTextAsync(Path.Combine(control, "contend"), "ready", deadline.Token);
                while (!File.Exists(result)) await Task.Delay(20, deadline.Token);
                return int.Parse(await File.ReadAllTextAsync(result, deadline.Token), CultureInfo.InvariantCulture);
            }

            throw new PlatformNotSupportedException();
        }

        internal async Task<object> ReadModeAsync(CancellationToken token)
        {
            if (OperatingSystem.IsWindows() && owner is TerminalCliNativeWindows windows)
            {
                return await windows.ReadModesAsync(token);
            }

            if (OperatingSystem.IsLinux() && owner is TerminalCliNativeLinux linux)
            {
                return (linux.ReadMode(), linux.ReadSize());
            }

            throw new PlatformNotSupportedException();
        }

        internal void Resize(ushort rows, ushort columns) => resize(rows, columns);

        internal async Task SendAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
        {
            await input.WriteAsync(bytes, cancellationToken);
            await input.FlushAsync(cancellationToken);
        }

        internal Task<int> WaitForExitAsync(CancellationToken cancellationToken) => wait(cancellationToken);

        internal Task RequireRestoredModeAsync(CancellationToken token) => requireRestoredMode(token);

        internal async Task RequireUnmodifiedModeAsync(CancellationToken token)
        {
            if (OperatingSystem.IsWindows() && owner is TerminalCliNativeWindows windows)
            {
                var initial = windows.InitialModes;
                var current = await windows.ReadModesAsync(token);
                Assert.Equal(initial.Input, current.Input);
                Assert.Equal(initial.Output, current.Output);
                return;
            }

            if (OperatingSystem.IsLinux() && owner is TerminalCliNativeLinux linux)
            {
                linux.AssertModeRestored();
                return;
            }

            throw new PlatformNotSupportedException();
        }

        internal async Task RequireActiveModeAsync(CancellationToken token)
        {
            var clock = Stopwatch.StartNew();
            while (clock.Elapsed < NativeBound)
            {
                if (await activeMode(token)) return;
                await Task.Delay(40, token);
            }

            Assert.Fail("The CLI did not change its real host terminal input mode while attached.");
        }

        public ValueTask DisposeAsync() => owner.DisposeAsync();
    }

    private sealed class TerminalCliCanvas : IAsyncDisposable
    {
        private readonly CancellationTokenSource _stop;
        private readonly MemoryStream _captured = new();
        private readonly Task _reader;

        internal TerminalCliCanvas(Stream output, CancellationToken token)
        {
            _stop = CancellationTokenSource.CreateLinkedTokenSource(token);
            _reader = ReadAsync(output, _stop.Token);
        }

        internal async Task WaitForAsync(string text, CancellationToken token)
        {
            var clock = Stopwatch.StartNew();
            while (clock.Elapsed < NativeBound)
            {
                if (Contains(text)) return;

                if (_reader.IsCompleted)
                {
                    await _reader;
                    Assert.Fail($"The CLI host terminal closed before rendering '{text}'.");
                }

                await Task.Delay(30, token);
            }

            Assert.Fail($"The CLI host terminal did not render '{text}' within the native test bound.");
        }

        internal bool Contains(string text)
        {
            lock (_captured)
            {
                return Encoding.UTF8.GetString(_captured.GetBuffer().AsSpan(0, (int)_captured.Length))
                    .Contains(text, StringComparison.Ordinal);
            }
        }

        internal async Task<string> WaitForLeaseAsync(string run, CancellationToken token)
        {
            string prefix = $"attached run {run} lease ";
            await WaitForAsync(prefix, token);
            await WaitForAsync(" writer", token);
            lock (_captured)
            {
                string text = Encoding.UTF8.GetString(_captured.GetBuffer().AsSpan(0, (int)_captured.Length));
                int start = text.IndexOf(prefix, StringComparison.Ordinal) + prefix.Length;
                var lease = text.Substring(start, 26);
                Assert.True(IdText.TryParse(lease, out var bytes));
                Assert.Equal(lease, IdText.Format(bytes));
                return lease;
            }
        }

        private async Task ReadAsync(Stream output, CancellationToken token)
        {
            var block = new byte[4096];
            int count;
            while ((count = await output.ReadAsync(block, token)) != 0)
            {
                lock (_captured)
                {
                    Assert.InRange(_captured.Length + count, 1, 1_048_576);
                    _captured.Write(block, 0, count);
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            try
            {
                await _reader;
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested)
            {
                // Stopping the outer display reader does not signal the terminal or its Run.
            }
            finally
            {
                _captured.Dispose();
                _stop.Dispose();
            }
        }
    }

    private sealed class TerminalCliFixture(TestNode node, Process process, NodeChannel channel, Id epoch, Sandbox sandbox,
        string working, string payload) : IAsyncDisposable
    {
        private readonly List<Id> _sandboxes = [sandbox.SandboxId];

        internal TestNode Node { get; } = node;
        internal Sandbox Sandbox { get; } = sandbox;
        internal string SandboxText { get; } = IdText.Format(sandbox.SandboxId);
        internal string Working { get; } = working;
        internal string Payload { get; } = payload;
        internal RunService.RunServiceClient Runs { get; } = new(channel.CallInvoker);

        internal static async Task<TerminalCliFixture> StartAsync(ulong? retention = null)
        {
            RequireExtractedPackage();
            var node = TestNode.Create();
            Process? process = null;
            NodeChannel? channel = null;
            Id? epoch = null;
            try
            {
                PrepareInstalledCliFixture(node);
                process = await node.StartNodeAsync();
                channel = OpenChannel(node);
                epoch = (await HandshakeAsync(new NodeService.NodeServiceClient(channel.CallInvoker))).OwnerEpoch;
                var sandbox = await CreateSandboxAsync(new SandboxService.SandboxServiceClient(channel.CallInvoker), epoch,
                    outputRetentionBytes: retention);
                var working = Directory.CreateDirectory(Path.Combine(sandbox.DataLocation, "work", "quoted directory")).FullName;
                return new(node, process, channel, epoch, sandbox, working, CopySecurityTestLoad(working));
            }
            catch
            {
                try
                {
                    if (channel is not null) await channel.DisposeAsync();
                    if (process is not null)
                    {
                        await StopInstalledCliNodeAsync(node, process);
                        process.Dispose();
                    }

                    if (epoch is not null) RemoveFixtureOwnerKey(node.DataRoot, epoch);
                }
                finally
                {
                    await node.DisposeAsync();
                }

                throw;
            }
        }

        internal string[] StartArguments(params string[] payloadArguments) => StartArguments(payloadArguments, terminal: "auto");

        internal string[] StartArguments(string[] payloadArguments, string terminal) =>
            ["run", "start", SandboxText, "--terminal", terminal, "--cwd", RelativeWorkdir, "--", .. payloadArguments];

        internal async Task<Sandbox> CreateAuxiliarySandboxAsync(CancellationToken token)
        {
            var service = new SandboxService.SandboxServiceClient(channel.CallInvoker);
            var reply = await service.CreateAsync(new SandboxServiceCreateRequest
            {
                Meta = Mutation(),
                OwnerEpoch = epoch,
                DisplayName = "Independent terminal contest Run",
                Config = Sandbox.Config.Clone(),
            }, deadline: Deadline, cancellationToken: token);
            var second = Value(reply.Value, reply.Error).Sandbox;
            _sandboxes.Add(second.SandboxId);
            return second;
        }

        internal async Task<(Run Run, string Marker)> StartQuietProbeAsync(Sandbox scope, CancellationToken token)
        {
            var directory = Directory.CreateDirectory(Path.Combine(scope.DataLocation, "work", "quoted directory")).FullName;
            var image = scope.SandboxId.Equals(Sandbox.SandboxId) ? Payload : CopySecurityTestLoad(directory);
            var marker = Path.Combine(directory, "shared-cli-marker.log");
            var response = await Runs.StartAsync(BuildStart(scope, epoch, [image, "terminal", "quiet", marker, "1", "1200"]),
                deadline: Deadline, cancellationToken: token);
            var run = Value(response.Value, response.Error).Run;
            await WaitForStateAsync(Node, Runs, run.RunId, RunState.Running, token);
            await WaitMarkerAsync(marker, "ready 24 80");
            return (run, marker);
        }

        internal Task<TerminalCliOuter> OpenTerminalAsync(ushort rows, ushort columns, CancellationToken token, params string[] arguments) =>
            TerminalCliOuter.StartAsync(InstalledCliHost, [NodeLocations.TestModeOption, .. arguments], Node.Root, Node.Environment,
                rows, columns, token);

        internal Process OpenPipes(params string[] arguments)
        {
            var start = new ProcessStartInfo(InstalledCliHost)
            {
                UseShellExecute = false,
                WorkingDirectory = Node.Root,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            };
            start.ArgumentList.Add(NodeLocations.TestModeOption);
            foreach (var argument in arguments) start.ArgumentList.Add(argument);
            foreach (var (name, value) in Node.Environment)
            {
                if (value is null) start.Environment.Remove(name);
                else start.Environment[name] = value;
            }

            start.Environment.Remove(OsSecretStoreGuard.OptInVariable);
            return Process.Start(start) ?? throw new InvalidOperationException("The installed CLI did not start.");
        }

        internal async Task<Run> OnlyNewRunAsync(Id? previous, CancellationToken token)
        {
            Run? result = null;
            await TestNode.WaitAsync(async () =>
            {
                token.ThrowIfCancellationRequested();
                var runs = (await ListAsync(Runs, Sandbox.SandboxId)).Where(run => !run.RunId.Equals(previous)).ToArray();
                if (runs.Length == 0) return false;
                result = Assert.Single(runs);
                return true;
            }, NativeBound, "the CLI's single new durable Run");
            return Assert.IsType<Run>(result);
        }

        internal async Task<Run> WaitExitedAsync(Id id, CancellationToken token)
        {
            var final = await WaitForStateAsync(Node, Runs, id, RunState.Exited, token);
            Assert.True(final.Exit.GroupEmptyVerified);
            return final;
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                if (!process.HasExited)
                {
                    foreach (var id in _sandboxes)
                    {
                        var listed = await Runs.ListAsync(new RunServiceListRequest { Meta = Query(), SandboxId = id },
                            deadline: Deadline, cancellationToken: CancellationToken.None);
                        foreach (var original in Value(listed.Value, listed.Error).Runs)
                        {
                            await TestNode.WaitAsync(async () =>
                            {
                                var current = await InspectAsync(Runs, original.RunId, CancellationToken.None);
                                if (current.State is RunState.Exited or RunState.Failed) return current.Exit.GroupEmptyVerified;
                                if (current.State is RunState.Starting or RunState.Running)
                                {
                                    var reply = await Runs.StopAsync(BuildStop(epoch, current), deadline: Deadline,
                                        cancellationToken: CancellationToken.None);
                                    if (reply.Error?.Code != "revision_mismatch") _ = Value(reply.Value, reply.Error);
                                }

                                return false;
                            }, NativeBound, $"verified cleanup of CLI Run {Hex(original.RunId)}");
                        }
                    }
                }
            }
            finally
            {
                try
                {
                    await channel.DisposeAsync();
                    using (process)
                    {
                        await StopInstalledCliNodeAsync(Node, process);
                        RemoveFixtureOwnerKey(Node.DataRoot, epoch);
                    }
                }
                finally
                {
                    await Node.DisposeAsync();
                }
            }
        }
    }
}
