// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    [Fact(Timeout = 100_000, DisableParallelization = true)]
    public async Task InstalledCliReportsLostNativePipeAcknowledgmentWithoutResendingInput()
    {
        var token = TestContext.Current.CancellationToken;
        await using var fixture = await TerminalCliFixture.StartAsync();
        var ready = Path.Combine(fixture.Working, "cli-ack-ready");
        var release = Path.Combine(fixture.Working, "cli-ack-release");
        var captured = Path.Combine(fixture.Working, "cli-ack-captured");
        var workload = GatedInputWorkload(fixture, ready, release, captured);
        using var child = fixture.OpenPipes(fixture.StartArguments(workload, terminal: "off"));
        try
        {
            var stdout = child.StandardOutput.ReadToEndAsync(token);
            await using var errors = new TerminalCliCanvas(child.StandardError.BaseStream, token);
            var run = await fixture.OnlyNewRunAsync(null, token);
            Assert.Equal(TerminalMode.Pipes, run.TerminalMode);
            await errors.WaitForLeaseAsync(IdText.Format(run.RunId), token);
            await TestNode.WaitAsync(() => File.Exists(ready), NativeBound, "the gated native payload to hold stdin open");

            // Distinct input bytes expose duplicate dispatch when the payload is eventually allowed to read.
            var input = RandomNumberGenerator.GetBytes(2 * 1024 * 1024);
            var sending = child.StandardInput.BaseStream.WriteAsync(input, token).AsTask();
            await child.WaitForExitAsync(token).WaitAsync(NativeBound, token);
            try
            {
                await sending.WaitAsync(NativeBound, token);
            }
            catch (IOException) when (child.HasExited)
            {
                // The input remaining in the test-side pipe has no reader after the CLI exits.
            }

            await stdout.WaitAsync(NativeBound, token);
            Assert.Equal(8, child.ExitCode);
            await errors.WaitForAsync("EXECUTION/terminal_ack_unavailable, effect Unknown", token);
            await errors.WaitForAsync("attach explicitly to continue", token);
            Assert.False(File.Exists(release));
            Assert.False(File.Exists(captured));
            Assert.Equal(RunState.Running, (await InspectAsync(fixture.Runs, run.RunId, token)).State);

            await File.WriteAllTextAsync(release, "read stdin", token);
            await TestNode.WaitAsync(() => File.Exists(captured) && new FileInfo(captured).Length > 0, NativeBound,
                "the native payload to read the original input prefix");
            await CloseWithFreshWriterAsync(fixture, run);
            RequireObservedCliExit(await fixture.WaitExitedAsync(run.RunId, token), 0);

            var received = await File.ReadAllBytesAsync(captured, token);
            Assert.InRange(received.Length, 1, input.Length - 1);
            Assert.True(received.AsSpan().SequenceEqual(input.AsSpan(0, received.Length)),
                "The real pipe consumer saw bytes outside the original, ordered input prefix.");
            Assert.Equal(run.RunId, Assert.Single(await ListAsync(fixture.Runs, run.SandboxId)).RunId);
            TestContext.Current.TestOutputHelper?.WriteLine(
                $"Lost CLI write acknowledgment with the read gate closed; explicit fresh EOF drained an original prefix of {received.Length} bytes.");
        }
        finally
        {
            await KillOwnedCliAsync(child);
        }
    }

    [Fact(Timeout = 150_000, DisableParallelization = true)]
    public async Task InstalledCliDoesNotReplayAcknowledgedInputAfterNodeLossOrWriterExpiry()
    {
        var token = TestContext.Current.CancellationToken;
        await using var installed = await InstalledTerminal.StartAsync();
        var marker = Path.Combine(installed.Working, "cli-ack-recovery.log");
        var firstInput = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)));
        var run = await installed.RunAsync(TerminalMode.Interactive, "terminal", "quiet", marker,
            FormattableString.Invariant($"{firstInput.Length + 3}"), "3000");
        await WaitMarkerAsync(marker, "ready 24 80");
        var node = await HandshakeAsync(installed.Node);
        var binding = ReadRecoveryBinding(installed.Fixture.DataRoot, run);
        var owner = CaptureRecoveryTerminalSupervisor(installed, binding);
        var id = IdText.Format(run.RunId);
        string originalLease;
        Run continued;
        await using (var first = await OpenAcknowledgmentTerminalAsync(installed, id, token))
        {
            await using var display = new TerminalCliCanvas(first.Output, token);
            originalLease = await display.WaitForLeaseAsync(id, token);
            await first.RequireActiveModeAsync(token);
            await first.SendAsync(firstInput, token);
            await WaitMarkerAsync(marker, FormattableString.Invariant($"consumed {firstInput.Length}"));
            await first.SendAsync("a"u8.ToArray(), token);
            // The CLI forwards the later byte only after the preceding native write has acknowledged.
            await WaitMarkerAsync(marker, FormattableString.Invariant($"consumed {firstInput.Length + 1}"));
            continued = await RebindRecoveryTerminalAsync(installed, run, binding, owner, node.NodeEpoch, token);
            var code = await first.WaitForExitAsync(token).WaitAsync(NativeBound, token);
            Assert.True(code is 7 or 8, $"The disconnected CLI exited with {code}.");
            await first.RequireRestoredModeAsync(token);
        }

        var expired = await AcquireWriterAsync(installed.Runs, continued);
        var aged = Input(continued, expired, 1, "b"u8.ToArray());
        await AcceptInputAsync(installed.Runs, aged, 1);
        await WaitMarkerAsync(marker, FormattableString.Invariant($"consumed {firstInput.Length + 2}"));
        await using (var contender = await OpenAcknowledgmentTerminalAsync(installed, id, token))
        {
            await using var display = new TerminalCliCanvas(contender.Output, token);
            await display.WaitForAsync("STATE/busy", token);
            Assert.Equal(3, await contender.WaitForExitAsync(token).WaitAsync(NativeBound, token));
            await contender.RequireRestoredModeAsync(token);
        }
        var expiration = Assert.IsType<DateTimeOffset>(ProtoTime.ToDateTimeOffset(expired.ExpiresAt));
        var remaining = expiration - DateTimeOffset.UtcNow;
        Assert.InRange(remaining.TotalSeconds, 1, 31);
        await Task.Delay(remaining + TimeSpan.FromMilliseconds(300), token);
        RequireUncertain((await WriteAsync(installed.Runs, aged)).Error);
        Assert.Equal(FormattableString.Invariant($"consumed {firstInput.Length + 2}"),
            ReadLines(marker).Last(line => line.StartsWith("consumed ", StringComparison.Ordinal)));

        await using (var next = await OpenAcknowledgmentTerminalAsync(installed, id, token))
        {
            await using var display = new TerminalCliCanvas(next.Output, token);
            var nextLease = await display.WaitForLeaseAsync(id, token);
            Assert.NotEqual(originalLease, nextLease);
            Assert.NotEqual(IdText.Format(expired.LeaseId), nextLease);
            await next.SendAsync("c"u8.ToArray(), token);
            await WaitMarkerAsync(marker, FormattableString.Invariant($"consumed {firstInput.Length + 3}"));
            Assert.Equal(8, await next.WaitForExitAsync(token).WaitAsync(NativeBound, token));
            await display.WaitForAsync("trustworthy_run_exit_unavailable", token);
            await next.RequireRestoredModeAsync(token);
        }

        var final = await AssertTerminalExitAsync(installed, continued);
        RequireObservedCliExit(final, 0);
        Assert.Equal(run.RunId, Assert.Single(await ListAsync(installed.Runs, run.SandboxId)).RunId);
        var originalStart = await OperationAsync(installed.Node, installed.OwnerEpoch, installed.StartCommand(run));
        Assert.Equal(run.RunId, originalStart.AggregateId);
        Assert.Equal(OperationState.Succeeded, originalStart.State);
        Assert.Equal(EffectCertainty.Happened, originalStart.Effect);
        var stop = BuildStop(installed.OwnerEpoch, final);
        var stopped = await StopAsync(installed.Runs, stop, token);
        AssertStopReceipt(stopped.Operation, stop, final.Revision, EffectCertainty.DidNotHappen);
        await AssertNoTerminalReceiptsAsync(installed, [aged.Meta.CommandId]);
        AssertNoDurableInput(installed.Fixture, firstInput, [aged.Meta.CommandId]);
    }

    private static Task<TerminalCliOuter> OpenAcknowledgmentTerminalAsync(InstalledTerminal installed, string run, CancellationToken token) =>
        TerminalCliOuter.StartAsync(InstalledCliHost, [NodeLocations.TestModeOption, "run", "attach", run],
            installed.Fixture.Root, installed.Fixture.Environment, 24, 80, token);

    private static async Task CloseWithFreshWriterAsync(TerminalCliFixture fixture, Run run)
    {
        var writer = await WaitForExclusiveWriterAsync(fixture.Runs, run);
        Assert.Equal(0UL, writer.LastInputSequence);
        await TestNode.WaitAsync(async () =>
        {
            var eof = Input(run, writer, 1, bytes: null);
            eof.CloseStdin = true;
            var reply = await WriteAsync(fixture.Runs, eof);
            if (reply.Value is null)
            {
                // The original native write can still be draining. Busy precedes admission.
                Assert.Equal("busy", reply.Error?.Code);
                return false;
            }

            Assert.True(reply.Value.HasAcceptedBytes);
            Assert.Equal(0U, reply.Value.AcceptedBytes);
            return true;
        }, TimeSpan.FromSeconds(8), "the fresh writer's separately acknowledged EOF");
    }

    private static string[] GatedInputWorkload(TerminalCliFixture fixture, string ready, string release, string captured)
    {
        if (OperatingSystem.IsLinux())
        {
            const string command = """
                "$1" hold --hold-ms 70000 --file "$2" --until-file "$3" >/dev/null || exit $?
                test -f "$3" || exit 9
                exec "$1" echo >"$4"
                """;
            return ["/usr/bin/dash", "-c", command, "arcforges-cli-ack-fixture", fixture.Payload, ready, release, captured];
        }

        const string batch = """
            @echo off
            arcforges-testload.exe hold --hold-ms 70000 --file cli-ack-ready --until-file cli-ack-release >nul
            if not "%errorlevel%"=="0" exit /b %errorlevel%
            if not exist cli-ack-release exit /b 9
            arcforges-testload.exe echo > cli-ack-captured
            exit /b %errorlevel%
            """;
        File.WriteAllText(Path.Combine(fixture.Working, "cli-ack.cmd"), batch.ReplaceLineEndings("\r\n"));
        return [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c", "cli-ack.cmd"];
    }
}
