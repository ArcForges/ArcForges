// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.CommandLine;

namespace ArcForges.Client.Tests;

public sealed class UpdateCommandTests
{
    [Fact]
    public async Task RestoreRejectsRelativeDestinationBeforeUpdateActuation()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var exit = await CliApplication.RunAsync(["update", "restore", "--destination", "relative"], UnexpectedNode, output, error, UnexpectedUpdate);
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("--destination requires a fresh absolute directory", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task PriorKeyRequiresAnIndependentlyIdentifiedArchiveBeforeStaging()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var exit = await CliApplication.RunAsync(["update", "apply", "--archive", "candidate", "--archive-sha256", new string('1', 64),
            "--commit", new string('2', 40), "--tree", new string('3', 40), "--trusted-key", "candidate-key", "--python", "python",
            "--openssl", "openssl", "--previous-trusted-key", "prior-key"], UnexpectedNode, output, error, UnexpectedUpdate);
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("--previous-trusted-key requires the four prior archive identity options", error.ToString(), StringComparison.Ordinal);
    }

    private static Task<int> UnexpectedNode(NodeRunRequest _, CancellationToken __) =>
        throw new InvalidOperationException("Invalid update arguments must be refused before launching Node.");

    private static Task<NodeUpdateResponse> UnexpectedUpdate(NodeUpdateRequest _, CancellationToken __) =>
        throw new InvalidOperationException("Invalid update arguments must be refused before applying an update.");
}
