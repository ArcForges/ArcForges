// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Native opened-root inspection against test-owned repositories. Git is executed only by the test as an independent
/// oracle with isolated global/system configuration; production WorkspaceGitStatus never executes Git.
/// </summary>
[Trait("tool", "git")]
public sealed class WorkspaceGitStatusTests
{
    private static readonly WorkspaceGitStatus.GitConfigSources IsolatedSources = new([], null, null);

    [Fact(Timeout = 60_000)]
    public async Task LooseRepositoryCleanStagedUnstagedUntrackedAndLockMatchRealGit()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new Repository();
        await fixture.InitAsync(TestContext.Current.CancellationToken);
        File.WriteAllText(Path.Combine(fixture.Root, "tracked.txt"), "before\n");
        File.WriteAllText(Path.Combine(fixture.Root, "staged.txt"), "base\n");
        await fixture.GitAsync(["add", "tracked.txt", "staged.txt"], TestContext.Current.CancellationToken);
        await fixture.GitAsync(["commit", "-qm", "initial"], TestContext.Current.CancellationToken);
        using var root = WorkspacePath.OpenRoot(fixture.Root);

        await CompareAsync(fixture, root, TestContext.Current.CancellationToken);
        File.WriteAllText(Path.Combine(fixture.Root, "tracked.txt"), "after!\n");
        File.WriteAllText(Path.Combine(fixture.Root, "staged.txt"), "staged\n");
        await fixture.GitAsync(["add", "staged.txt"], TestContext.Current.CancellationToken);
        File.WriteAllText(Path.Combine(fixture.Root, "untracked.txt"), "untracked\n");
        await CompareAsync(fixture, root, TestContext.Current.CancellationToken);

        File.WriteAllText(Path.Combine(fixture.Root, ".git", "index.lock"), string.Empty);
        var locked = await WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, TestContext.Current.CancellationToken);
        Assert.NotNull(locked);
        Assert.Equal(GitStatusQuality.Complete, locked.Quality);
        Assert.True(locked.Locked);
        File.Delete(Path.Combine(fixture.Root, ".git", "index.lock"));
    }

    [Fact(Timeout = 60_000)]
    public async Task UnsupportedFilterAndIgnoreDoNotRunAHelperOrPretendComplete()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new Repository();
        await fixture.InitAsync(TestContext.Current.CancellationToken);
        File.WriteAllText(Path.Combine(fixture.Root, "file"), "content\n");
        await fixture.GitAsync(["add", "file"], TestContext.Current.CancellationToken);
        await fixture.GitAsync(["commit", "-qm", "initial"], TestContext.Current.CancellationToken);
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        File.WriteAllText(Path.Combine(fixture.Root, ".gitignore"), "*.ignored\n");
        var ignore = await WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, TestContext.Current.CancellationToken);
        Assert.NotNull(ignore);
        Assert.Equal(GitStatusQuality.Unknown, ignore.Quality);
        Assert.False(ignore.HasDirty);
        Assert.False(ignore.HasModifiedFiles);
        Assert.False(ignore.HasUntrackedFiles);
        Assert.False(ignore.HasLocked);
        File.Delete(Path.Combine(fixture.Root, ".gitignore"));

        var marker = Path.Combine(fixture.Directory, "helper-ran");
        await fixture.GitAsync(["config", "--local", "core.fsmonitor", marker], TestContext.Current.CancellationToken);
        var helper = await WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, TestContext.Current.CancellationToken);
        Assert.NotNull(helper);
        Assert.Equal(GitStatusQuality.Unknown, helper.Quality);
        Assert.False(helper.HasDirty);
        Assert.False(File.Exists(marker));
    }

    [Fact(Timeout = 60_000)]
    public async Task ActualExternalConfigurationAndDefaultIgnoreAreNotSilentlyIgnored()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new Repository();
        await fixture.InitAsync(TestContext.Current.CancellationToken);
        File.WriteAllText(Path.Combine(fixture.Root, "file"), "content\n");
        await fixture.GitAsync(["add", "file"], TestContext.Current.CancellationToken);
        await fixture.GitAsync(["commit", "-qm", "initial"], TestContext.Current.CancellationToken);
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        var config = Path.Combine(fixture.Directory, "test-gitconfig");
        var ignore = Path.Combine(fixture.Directory, "test-ignore");
        var attributes = Path.Combine(fixture.Directory, "test-attributes");
        var sources = new WorkspaceGitStatus.GitConfigSources([config], ignore, attributes);
        File.WriteAllText(config, "[user]\n  name = synthetic-only\n[core]\n  autocrlf = false\n");
        Assert.Equal(GitStatusQuality.Complete,
            (await WorkspaceGitStatus.ObserveAsync(root, sources, TestContext.Current.CancellationToken))!.Quality);
        File.WriteAllText(ignore, "*.ignored\n");
        var ignored = await WorkspaceGitStatus.ObserveAsync(root, sources, TestContext.Current.CancellationToken);
        Assert.Equal(GitStatusQuality.Unknown, ignored!.Quality);
        Assert.False(ignored.HasDirty);
        File.Delete(ignore);
        File.WriteAllText(attributes, "*.txt filter=synthetic\n");
        var attributed = await WorkspaceGitStatus.ObserveAsync(root, sources, TestContext.Current.CancellationToken);
        Assert.Equal(GitStatusQuality.Unknown, attributed!.Quality);
        Assert.False(attributed.HasUntrackedFiles);
        File.Delete(attributes);
        File.WriteAllText(config, "[core]\n  autocrlf = true\n");
        var conversion = await WorkspaceGitStatus.ObserveAsync(root, sources, TestContext.Current.CancellationToken);
        Assert.Equal(GitStatusQuality.Unknown, conversion!.Quality);
        Assert.False(conversion.HasModifiedFiles);
        File.WriteAllText(config, "[include]\n  path = /synthetic/not-followed\n");
        Assert.Equal(GitStatusQuality.Unknown,
            (await WorkspaceGitStatus.ObserveAsync(root, sources, TestContext.Current.CancellationToken))!.Quality);
    }

    [Fact(Timeout = 60_000)]
    public async Task PackedReferenceWithLooseObjectsAndCorruptIndexAreDistinguished()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new Repository();
        await fixture.InitAsync(TestContext.Current.CancellationToken);
        File.WriteAllText(Path.Combine(fixture.Root, "file"), "content\n");
        await fixture.GitAsync(["add", "file"], TestContext.Current.CancellationToken);
        await fixture.GitAsync(["commit", "-qm", "initial"], TestContext.Current.CancellationToken);
        await fixture.GitAsync(["pack-refs", "--all", "--prune"], TestContext.Current.CancellationToken);
        Assert.True(File.Exists(Path.Combine(fixture.Root, ".git", "packed-refs")));
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        await CompareAsync(fixture, root, TestContext.Current.CancellationToken);

        var index = Path.Combine(fixture.Root, ".git", "index");
        var original = File.ReadAllBytes(index);
        var damaged = original.ToArray();
        damaged[10] ^= 1;
        File.WriteAllBytes(index, damaged);
        var summary = await WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, TestContext.Current.CancellationToken);
        Assert.Equal(GitStatusQuality.Unknown, summary!.Quality);
        Assert.False(summary.HasDirty);
        File.WriteAllBytes(index, original);
        await CompareAsync(fixture, root, TestContext.Current.CancellationToken);
    }

    [Fact(Timeout = 60_000)]
    public async Task LargeRealStatusReturnsTruncatedWithoutPartialCounts()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new Repository();
        await fixture.InitAsync(TestContext.Current.CancellationToken);
        File.WriteAllText(Path.Combine(fixture.Root, "file"), "content\n");
        await fixture.GitAsync(["add", "file"], TestContext.Current.CancellationToken);
        await fixture.GitAsync(["commit", "-qm", "initial"], TestContext.Current.CancellationToken);
        for (var i = 0; i < 110; i++)
        {
            File.WriteAllText(Path.Combine(fixture.Root, i.ToString("D3", System.Globalization.CultureInfo.InvariantCulture) + new string('a', 170)), "");
        }

        var gitStatus = await fixture.GitAsync(["status", "--porcelain=v1", "--untracked-files=all", "--no-renames"], TestContext.Current.CancellationToken);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(gitStatus) > 16_384);
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        string? failure = null;
        var summary = await WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, TestContext.Current.CancellationToken, value => failure = value);
        Assert.True(summary!.Quality == GitStatusQuality.Truncated, "quality=" + summary.Quality + "; phase=" + failure);
        Assert.False(summary.HasDirty);
        Assert.False(summary.HasModifiedFiles);
        Assert.False(summary.HasUntrackedFiles);
        Assert.False(summary.HasLocked);
    }

    [Fact(Timeout = 60_000)]
    public async Task ActualHostileFsmonitorAndCleanFilterNeverExecuteDuringInspection()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new Repository();
        await fixture.InitAsync(ct);
        File.WriteAllText(Path.Combine(fixture.Root, "file"), "content\n");
        await fixture.GitAsync(["add", "file"], ct);
        await fixture.GitAsync(["commit", "-qm", "initial"], ct);
        var helper = Path.Combine(fixture.Directory, "hostile-helper.sh");
        var marker = Path.Combine(fixture.Directory, "helper-marker");
        File.WriteAllText(helper, "#!/bin/sh\nprintf activated > \"$ARCFORGES_TEST_HELPER_MARKER\"\ncat\n");
        const string command = "sh \"$ARCFORGES_TEST_HELPER\"";
        await fixture.GitAsync(["config", "--local", "core.fsmonitor", command], ct);
        await fixture.GitAsync(["-c", "core.fsmonitor=" + command, "status", "--porcelain=v1"], ct);
        Assert.True(File.Exists(marker)); // Proves the test-owned helper would actually execute under Git.
        File.Delete(marker);
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        var monitor = await WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, ct);
        Assert.Equal(GitStatusQuality.Unknown, monitor!.Quality);
        Assert.False(File.Exists(marker));

        await fixture.GitAsync(["config", "--local", "--unset", "core.fsmonitor"], ct);
        await fixture.GitAsync(["config", "--local", "filter.synthetic.clean", command], ct);
        await fixture.GitAsync(["config", "--local", "filter.synthetic.required", "true"], ct);
        File.WriteAllText(Path.Combine(fixture.Root, ".gitattributes"), "file filter=synthetic\n");
        // The preceding fsmonitor status can mark the unchanged file clean in the index. Change it so the
        // native Git oracle must actually run the configured clean filter when staging this file.
        File.AppendAllText(Path.Combine(fixture.Root, "file"), "changed\n");
        await fixture.GitAsync(["add", "file"], ct);
        Assert.True(File.Exists(marker)); // The test Git oracle really invokes this configured clean filter.
        File.Delete(marker);
        var filter = await WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, ct);
        Assert.Equal(GitStatusQuality.Unknown, filter!.Quality);
        Assert.False(File.Exists(marker));
    }

    [Fact(Timeout = 60_000)]
    public async Task PackedOnlyObjectsAreUnknownUntilTheirFormatIsImplemented()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new Repository();
        await fixture.InitAsync(TestContext.Current.CancellationToken);
        File.WriteAllText(Path.Combine(fixture.Root, "file"), "content\n");
        await fixture.GitAsync(["add", "file"], TestContext.Current.CancellationToken);
        await fixture.GitAsync(["commit", "-qm", "initial"], TestContext.Current.CancellationToken);
        await fixture.GitAsync(["gc", "--prune=now", "--quiet"], TestContext.Current.CancellationToken);
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(fixture.Root, ".git", "objects", "pack"), "*.pack"));
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        var summary = await WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, TestContext.Current.CancellationToken);
        Assert.NotNull(summary);
        Assert.Equal(GitStatusQuality.Unknown, summary.Quality);
        Assert.False(summary.HasDirty);
        Assert.False(summary.HasModifiedFiles);
        Assert.False(summary.HasUntrackedFiles);
        Assert.False(summary.HasLocked);
    }

    // isolation=exclusive: the two-second product deadline is a real timing bound under concurrent work.
    [Fact(Timeout = 60_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task ConcurrentNativeInspectionsUseTheSharedDeadlineInsteadOfImmediateWorkerRefusal()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new Repository();
        await fixture.InitAsync(ct);
        File.WriteAllText(Path.Combine(fixture.Root, "file"), "content\n");
        await fixture.GitAsync(["add", "file"], ct);
        await fixture.GitAsync(["commit", "-qm", "initial"], ct);
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        var tasks = Enumerable.Range(0, 12).Select(_ => WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, ct)).ToArray();
        var results = await Task.WhenAll(tasks);
        Assert.All(results, result => Assert.Equal(GitStatusQuality.Complete, result!.Quality));
        Assert.All(results, result => Assert.False(result!.Dirty));
    }

    [Fact(Timeout = 60_000)]
    public async Task MalformedNonCoreConfigurationIsUnknownAndRealGitRejectsIt()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new Repository();
        await fixture.InitAsync(ct);
        File.WriteAllText(Path.Combine(fixture.Root, "file"), "content\n");
        await fixture.GitAsync(["add", "file"], ct);
        await fixture.GitAsync(["commit", "-qm", "initial"], ct);
        var config = Path.Combine(fixture.Root, ".git", "config");
        var original = File.ReadAllText(config);
        var malformed = new[]
        {
            "\n[user]\n  name = " + (char)34 + "unterminated\n",
            "\n[user]\n  name = invalid" + (char)92 + "q\n",
            "\n[user]\n  name = valid\n[unclosed\n",
            "\n[credential " + (char)34 + "unterminated]\n  helper = ignored\n",
        };
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        foreach (var suffix in malformed)
        {
            File.WriteAllText(config, original + suffix);
            await fixture.GitFailureAsync(["status", "--porcelain=v1"], ct);
            var result = await WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, ct);
            Assert.Equal(GitStatusQuality.Unknown, result!.Quality);
            Assert.False(result.HasDirty);
        }

        File.WriteAllText(config, original);
        await CompareAsync(fixture, root, ct);
    }

    [Fact(Timeout = 60_000)]
    public async Task RealMetadataChangeImmediatelyAfterReadReturnsUnknown()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var ct = TestContext.Current.CancellationToken;
        using var fixture = new Repository();
        await fixture.InitAsync(ct);
        File.WriteAllText(Path.Combine(fixture.Root, "file"), "content\n");
        await fixture.GitAsync(["add", "file"], ct);
        await fixture.GitAsync(["commit", "-qm", "initial"], ct);
        // Windows opens HEAD without write sharing, so mutate already-observed config after that handle closes;
        // on Linux also exercise an actual concurrent change to the HEAD handle currently being read.
        var observed = Path.Combine(fixture.Root, ".git", OperatingSystem.IsWindows() ? "config" : "HEAD");
        var original = File.ReadAllBytes(observed);
        var changed = false;
        var sources = IsolatedSources with
        {
            AfterReadForTests = path =>
        {
            if (path == ".git/HEAD" && !changed)
            {
                if (OperatingSystem.IsWindows())
                {
                    File.AppendAllText(observed, "\n# changed after observation\n");
                }
                else
                {
                    File.WriteAllText(observed, "ref: refs/heads/substituted\n");
                }

                changed = true;
            }
        }
        };
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        var result = await WorkspaceGitStatus.ObserveAsync(root, sources, ct);
        Assert.True(changed);
        Assert.Equal(GitStatusQuality.Unknown, result!.Quality);
        Assert.False(result.HasDirty);
        File.WriteAllBytes(observed, original);
        await CompareAsync(fixture, root, ct);
    }

    [Fact(Timeout = 60_000)]
    public async Task NonGitRequiresCheckedAncestorsAndCancellationIsHonored()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        using var fixture = new Repository();
        using var root = WorkspacePath.OpenRoot(fixture.Root);
        Assert.Null(await WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, TestContext.Current.CancellationToken));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, cancelled.Token));
    }

    [Fact]
    public void FixtureCleanupHandlesReadOnlyFilesOnlyWithinItsOwnRoot()
    {
        using var other = new Repository();
        var outside = Path.Combine(other.Root, "outside");
        File.WriteAllText(outside, "outside");
        File.SetAttributes(outside, File.GetAttributes(outside) | FileAttributes.ReadOnly);
        using var fixture = new Repository();
        var path = Path.Combine(fixture.Root, "read-only");
        File.WriteAllText(path, "test-owned");
        File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
        var root = fixture.Directory;

        fixture.Dispose();

        Assert.False(System.IO.Directory.Exists(root));
        Assert.True(File.Exists(outside));
        Assert.True((File.GetAttributes(outside) & FileAttributes.ReadOnly) != 0);
        Assert.Equal("outside", File.ReadAllText(outside));
    }

    private static async Task CompareAsync(Repository fixture, WorkspacePath root, CancellationToken token)
    {
        string? failure = null;
        var actual = await WorkspaceGitStatus.ObserveAsync(root, IsolatedSources, token, value => failure = value);
        Assert.NotNull(actual);
        Assert.True(actual.Quality == GitStatusQuality.Complete, "quality=" + actual.Quality + "; phase=" + failure);
        var status = await fixture.GitAsync(["status", "--porcelain=v1", "--untracked-files=all", "--no-renames"], token);
        var lines = status.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var untracked = lines.Count(line => line.StartsWith("?? ", StringComparison.Ordinal));
        var modified = lines.Length - untracked;
        Assert.Equal((uint)modified, actual.ModifiedFiles);
        Assert.Equal((uint)untracked, actual.UntrackedFiles);
        Assert.Equal(lines.Length != 0, actual.Dirty);
        Assert.False(actual.Locked);
        Assert.Equal((await fixture.GitAsync(["rev-parse", "HEAD"], token)).Trim(), actual.Head);
        Assert.Equal((await fixture.GitAsync(["symbolic-ref", "--short", "HEAD"], token)).Trim(), actual.Branch);
    }

    private sealed class Repository : IDisposable
    {
        private readonly DirectoryInfo _directory = System.IO.Directory.CreateTempSubdirectory("arcforges-git-status-");
        private readonly string _git = FindGit();
        public string Directory => _directory.FullName;
        public string Root { get; }

        public Repository()
        {
            Root = System.IO.Directory.CreateDirectory(Path.Combine(Directory, "work")).FullName;
        }

        public async Task InitAsync(CancellationToken cancellationToken)
        {
            var template = System.IO.Directory.CreateDirectory(Path.Combine(Directory, "empty-template")).FullName;
            await GitAsync(["init", "--quiet", "--initial-branch=main", "--template=" + template], cancellationToken);
        }

        public Task<string> GitAsync(IReadOnlyList<string> args, CancellationToken cancellationToken) =>
            RunGitAsync(args, expectFailure: false, cancellationToken);

        public Task<string> GitFailureAsync(IReadOnlyList<string> args, CancellationToken cancellationToken) =>
            RunGitAsync(args, expectFailure: true, cancellationToken);

        private async Task<string> RunGitAsync(IReadOnlyList<string> args, bool expectFailure, CancellationToken cancellationToken)
        {
            var start = new ProcessStartInfo(_git) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            start.ArgumentList.Add("-C");
            start.ArgumentList.Add(Root);
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add("user.name=Synthetic");
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add("user.email=synthetic@example.invalid");
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add("core.hooksPath=" + Path.Combine(Directory, "empty-template"));
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add("core.fsmonitor=false");
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add("core.excludesfile=" + (OperatingSystem.IsWindows() ? "NUL" : "/dev/null"));
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add("core.attributesfile=" + (OperatingSystem.IsWindows() ? "NUL" : "/dev/null"));
            foreach (var item in args) start.ArgumentList.Add(item);
            start.Environment["GIT_CONFIG_NOSYSTEM"] = "1";
            start.Environment["GIT_CONFIG_GLOBAL"] = OperatingSystem.IsWindows() ? "NUL" : "/dev/null";
            start.Environment["GIT_TERMINAL_PROMPT"] = "0";
            start.Environment["GIT_OPTIONAL_LOCKS"] = "0";
            start.Environment["ARCFORGES_TEST_HELPER"] = Path.Combine(Directory, "hostile-helper.sh");
            start.Environment["ARCFORGES_TEST_HELPER_MARKER"] = Path.Combine(Directory, "helper-marker");
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start test Git.");
            var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);
            var text = await stdout;
            var errors = await stderr;
            Assert.True(expectFailure ? process.ExitCode != 0 : process.ExitCode == 0,
                expectFailure ? "Test Git unexpectedly accepted malformed configuration." : "Test Git failed: " + errors);
            return text;
        }

        private static string FindGit()
        {
            if (OperatingSystem.IsLinux())
            {
                Assert.SkipUnless(File.Exists("/usr/bin/git"), "Native Git is not installed at the test's fixed path.");
                return "/usr/bin/git";
            }

            Assert.SkipUnless(OperatingSystem.IsWindows(), "Native Git oracle is configured for Linux and Windows.");
            var candidates = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "bin", "git.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "cmd", "git.exe"),
            };
            var executable = candidates.FirstOrDefault(File.Exists);
            Assert.SkipUnless(executable is not null, "Native Git was not found at a fixed Program Files path.");
            return executable!;
        }

        public void Dispose()
        {
            var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(_directory.FullName));
            var temp = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (!string.Equals(Path.GetDirectoryName(root), temp, comparison) ||
                !Path.GetFileName(root).StartsWith("arcforges-git-status-", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Refusing to clean a directory outside this test fixture.");
            }

            if (!System.IO.Directory.Exists(root))
            {
                return;
            }

            if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("Refusing to clean a replaced test fixture.");
            }

            if (OperatingSystem.IsWindows())
            {
                // Git creates read-only objects. Only clear that bit on actual files in this owned root;
                // do not traverse reparse points or change a similarly named file outside the fixture.
                var options = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint };
                foreach (var file in System.IO.Directory.EnumerateFiles(root, "*", options))
                {
                    var full = Path.GetFullPath(file);
                    if (!full.StartsWith(root + Path.DirectorySeparatorChar, comparison))
                    {
                        throw new InvalidOperationException("Refusing to change a file outside this test fixture.");
                    }

                    var attributes = File.GetAttributes(full);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        throw new InvalidOperationException("Refusing to change a reparse point.");
                    }

                    if ((attributes & FileAttributes.ReadOnly) != 0)
                    {
                        File.SetAttributes(full, attributes & ~FileAttributes.ReadOnly);
                    }
                }
            }

            System.IO.Directory.Delete(root, recursive: true);
        }
    }
}
