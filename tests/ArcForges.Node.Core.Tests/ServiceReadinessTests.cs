// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// The output-regex readiness of a SERVICE (04 section 8): each stream is decoded as a stream, so a UTF-8 character split across two reads
/// still matches; a line longer than 64 KiB is matched by its first 64 KiB, and its rest is skipped up to its newline, never joined to
/// later output.
/// </summary>
public sealed class ServiceReadinessTests
{
    [Fact]
    public void AUtf8CharacterSplitAcrossTwoReadsMatches()
    {
        using var root = new TemporaryRoot();
        var files = new AttemptFiles(root.Path, "attempt");
        var readiness = Regex("^ready é$");
        var line = Encoding.UTF8.GetBytes("ready é\n");

        // "é" is two bytes (C3 A9): the first read ends between them.
        Append(files, line[..^2]);
        Assert.Equal(ReadinessOutcome.Waiting, Check(readiness, files));
        Append(files, line[^2..]);
        Assert.Equal(ReadinessOutcome.Ready, Check(readiness, files));
    }

    [Fact]
    public void ALineLongerThan64KiBIsMatchedByItsStart()
    {
        using var root = new TemporaryRoot();
        var files = new AttemptFiles(root.Path, "attempt");
        var readiness = Regex("^y{100}");
        Append(files, Encoding.UTF8.GetBytes(new string('y', ServiceReadiness.MaxLine + 4_096)));
        Assert.Equal(ReadinessOutcome.Ready, Check(readiness, files));
    }

    [Fact]
    public void TheRestOfALineLongerThan64KiBIsNotJoinedToLaterOutput()
    {
        using var root = new TemporaryRoot();
        var files = new AttemptFiles(root.Path, "attempt");

        // Joined to the "ready" that ends the long line, its first 64 KiB of x would match; the rest of the line is skipped instead.
        var readiness = Regex("^x+ready");
        Append(files, Encoding.UTF8.GetBytes(new string('x', ServiceReadiness.MaxLine + 10)));
        Assert.Equal(ReadinessOutcome.Waiting, Check(readiness, files));
        Append(files, Encoding.UTF8.GetBytes("xxready and more\n"));
        Assert.Equal(ReadinessOutcome.Waiting, Check(readiness, files));

        // The next line is matched on its own.
        Append(files, Encoding.UTF8.GetBytes("xready\n"));
        Assert.Equal(ReadinessOutcome.Ready, Check(readiness, files));
    }

    private static ServiceReadiness Regex(string pattern) => ServiceReadiness.For(new TaskSpec
    {
        Kind = TaskKind.Service,
        Readiness = new ReadinessCondition { OutputRegex = pattern },
    })!;

    private static ReadinessOutcome Check(ServiceReadiness readiness, AttemptFiles files) =>
        readiness.Check(files, null, () => Array.Empty<int>(), TimeSpan.Zero, TimeProvider.System);

    private static void Append(AttemptFiles files, byte[] bytes)
    {
        Directory.CreateDirectory(files.Directory);
        using var stream = new FileStream(files.OutputPath(OutputStreamKind.Stdout), FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        stream.Write(bytes);
    }

    private sealed class TemporaryRoot : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("arcforges-readiness-").FullName;

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
