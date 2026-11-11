// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Client;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real CLI process with a redirected stdin; no test claims an interactive HUMAN from this fixture.</summary>
public sealed class FileOperationCliTests
{
    [Fact(Timeout = 30_000)]
    public async Task YesAndPipedConfirmationCannotBypassTheInteractiveRequirement()
    {
        var token = TestContext.Current.CancellationToken;
        var start = new ProcessStartInfo(CloudNode.HelperExecutable)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in new[]
        {
            "--test-mode", "--yes", "file-operation", "acknowledge", IdText.Format(CommandIds.New()),
            "--digest", new string('a', 64),
        }) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the owned CLI.");
        await process.StandardInput.WriteLineAsync("acknowledge");
        process.StandardInput.Close();
        var output = process.StandardOutput.ReadToEndAsync(token);
        var error = process.StandardError.ReadToEndAsync(token);
        try
        {
            await process.WaitForExitAsync(token).WaitAsync(TimeSpan.FromSeconds(15), token);
        }
        catch (Exception exception) when (exception is TimeoutException or OperationCanceledException)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None);
            }
            throw;
        }

        Assert.Equal(2, process.ExitCode);
        Assert.Contains("interactive local HUMAN confirmation", await error, StringComparison.Ordinal);
        Assert.DoesNotContain("hold was released", await output, StringComparison.Ordinal);
    }
}
