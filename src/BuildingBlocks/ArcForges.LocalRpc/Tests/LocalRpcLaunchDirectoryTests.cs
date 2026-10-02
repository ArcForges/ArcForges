// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Xunit;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// Launch directories are plain file-system state, so these checks run in any environment: owner-only creation and
/// verification, atomic publish and removal, records that hold no secret, and the sweep of directories whose parent is gone.
/// Windows access control lists are checked on Windows and Unix modes on Unix; each platform's check is skipped on the other.
/// </summary>
public sealed class LocalRpcLaunchDirectoryTests
{
    private const string WindowsOnly = "Windows access control check.";
    private const string UnixOnly = "Unix file mode check.";
    private static readonly LocalRpcLaunchIdentity Standard = Launches.Identity();

    private static readonly string[] LookalikeNames = ["zzzzzzzzzzzz", "0123456789AB"];

    public static bool IsWindows => OperatingSystem.IsWindows();

    public static bool IsUnix => !OperatingSystem.IsWindows();

    // ---- runtime root ----

    [Fact]
    public void TheRuntimeRootMustBeACanonicalLocalAbsolutePathWithAnExistingParent()
    {
        using var world = new LaunchWorld();
        _ = Directory.CreateDirectory(Path.GetDirectoryName(world.Root)!);

        Assert.Throws<ArgumentNullException>(() => LocalRpcLaunchAuthority.Create(null!));
        Assert.Throws<ArgumentException>(() => LocalRpcLaunchAuthority.Create("relative-root"));
        Assert.Throws<ArgumentException>(() => LocalRpcLaunchAuthority.Create(Path.Combine(Path.GetDirectoryName(world.Root)!, "a", "..", "rt")));
        Assert.Throws<ArgumentException>(() => LocalRpcLaunchAuthority.Create(@"\\server\share\rt"));
        Assert.Throws<DirectoryNotFoundException>(() => LocalRpcLaunchAuthority.Create(Path.Combine(world.Root, "missing-parent", "rt")));
        Assert.False(Directory.Exists(world.Root));
    }

    [Fact]
    public async Task TheRootIsCreatedOnceAndAnExistingOwnerOnlyRootIsReused()
    {
        using var world = new LaunchWorld();
        _ = Directory.CreateDirectory(Path.GetDirectoryName(world.Root)!);

        await using (var first = world.Authority())
        {
            Assert.True(Directory.Exists(world.Root));
        }

        await using var second = world.Authority();
        Assert.Equal(1UL, second.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams).Descriptor.Epoch);
    }

    [Fact]
    public void ARootThatIsAFileIsRefused()
    {
        using var world = new LaunchWorld();
        File.WriteAllText(world.Root, "not a directory");

        Assert.Throws<IOException>(() => LocalRpcLaunchAuthority.Create(world.Root));
    }

    [Fact(Skip = UnixOnly, SkipUnless = nameof(IsUnix))]
    [UnsupportedOSPlatform("windows")]
    public async Task OnUnixTheRootAndEveryLaunchDirectoryAreOwnerOnlyAndTheRecordIsMode0600()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard);

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(world.Root));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(launch.DirectoryPath!));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(LaunchDirectory.RecordPath(launch.DirectoryPath!)));
    }

    [Theory(Skip = UnixOnly, SkipUnless = nameof(IsUnix))]
    [InlineData(UnixFileMode.GroupRead)]
    [InlineData(UnixFileMode.GroupWrite)]
    [InlineData(UnixFileMode.GroupExecute)]
    [InlineData(UnixFileMode.OtherRead)]
    [InlineData(UnixFileMode.OtherWrite)]
    [InlineData(UnixFileMode.OtherExecute)]
    [UnsupportedOSPlatform("windows")]
    public async Task OnUnixAnyGroupOrOtherPermissionOnTheRootIsRefused(UnixFileMode extra)
    {
        using var world = new LaunchWorld();
        _ = Directory.CreateDirectory(Path.GetDirectoryName(world.Root)!);
        LaunchDirectory.CreateOwnerOnly(world.Root);
        File.SetUnixFileMode(world.Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | extra);

        Assert.Throws<UnauthorizedAccessException>(() => LocalRpcLaunchAuthority.Create(world.Root));
        File.SetUnixFileMode(world.Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        await using var reused = LocalRpcLaunchAuthority.Create(world.Root);
    }

    [Fact(Skip = WindowsOnly, SkipUnless = nameof(IsWindows))]
    [SupportedOSPlatform("windows")]
    public async Task OnWindowsTheRootIsCreatedWithOnlyTheCurrentUsersAccessAndAnExtraPrincipalIsRefused()
    {
        using var world = new LaunchWorld();
        _ = Directory.CreateDirectory(Path.GetDirectoryName(world.Root)!);
        var user = WindowsIdentity.GetCurrent().User!;

        await using (var authority = world.Authority())
        {
            var launch = authority.Launch("slot-a", Standard);
            foreach (var path in new[] { world.Root, launch.DirectoryPath!, LaunchDirectory.RecordPath(launch.DirectoryPath!) })
            {
                var security = Directory.Exists(path) ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
                var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
                Assert.True(security.AreAccessRulesProtected || File.Exists(path), path);
                Assert.NotEmpty(rules);
                Assert.All(rules, rule =>
                {
                    Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
                    Assert.Equal(user, rule.IdentityReference);
                });
            }
        }

        var open = new DirectoryInfo(world.Root);
        var acl = open.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        open.SetAccessControl(acl);

        Assert.Throws<UnauthorizedAccessException>(() => LocalRpcLaunchAuthority.Create(world.Root));
    }

    [Fact]
    public void ARootThatIsALinkIsRefused()
    {
        using var world = new LaunchWorld();
        _ = Directory.CreateDirectory(Path.GetDirectoryName(world.Root)!);
        // The target is itself owner-only, so only the link guard can refuse the root.
        var target = Path.Combine(Path.GetDirectoryName(world.Root)!, "target");
        LaunchDirectory.CreateOwnerOnly(target);
        LaunchDirectory.RequireOwnerOnly(target);
        if (!TestLinks.TryCreateDirectoryLink(world.Root, target))
        {
            Assert.Skip("This account can create neither a symbolic link nor a junction.");
            return;
        }

        Assert.Throws<UnauthorizedAccessException>(() => LocalRpcLaunchAuthority.Create(world.Root));
    }

    // ---- launch directory contents ----

    [Fact]
    public async Task AnEndpointLaunchOwnsOneDirectoryWithItsRecordAndNoSecretOnDisk()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard);
        var resource = launch.HandoffBootstrapResource();
        var secret = resource[^LocalRpcLaunchDescriptor.SecretLength..];
        var directory = launch.DirectoryPath!;

        Assert.Equal(world.Root, Path.GetDirectoryName(directory));
        Assert.Matches("^[0-9a-f]{12}$", Path.GetFileName(directory));
        Assert.Equal(Path.Combine(directory, "s"), launch.Endpoint!.Address);
        Assert.Equal(LocalRpcTransport.UnixDomainSocket, launch.Endpoint.Transport);
        Assert.Equal(world.Parent, LaunchDirectory.ReadRecord(LaunchDirectory.RecordPath(directory)));
        Assert.Equal(["launch.rec"], Directory.EnumerateFileSystemEntries(directory).Select(Path.GetFileName));
        var onDisk = await File.ReadAllBytesAsync(LaunchDirectory.RecordPath(directory), TestContext.Current.CancellationToken);
        Assert.False(onDisk.AsSpan().IndexOf(secret) >= 0);
        Assert.False(onDisk.AsSpan().IndexOf(launch.Descriptor.Nonce.Span) >= 0);
        Assert.Equal([Path.GetFileName(directory)], Directory.EnumerateFileSystemEntries(world.Root).Select(Path.GetFileName));
    }

    [Fact]
    public async Task ASuppliedStreamLaunchCreatesNoFileAtAll()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();

        var launch = authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams);

        Assert.Null(launch.Endpoint);
        Assert.Null(launch.DirectoryPath);
        Assert.Empty(Directory.EnumerateFileSystemEntries(world.Root));
    }

    [Fact(Skip = WindowsOnly, SkipUnless = nameof(IsWindows))]
    public async Task OnWindowsAPrivateEndpointIsAnUnguessablePipeNameAndCreatesNoFile()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority(unixSocket: false);

        var first = authority.Launch("slot-a", Standard);
        var second = authority.Launch("slot-b", Standard);

        Assert.Equal(LocalRpcTransport.NamedPipe, first.Endpoint!.Transport);
        Assert.Matches("^afl-[0-9a-f]{32}$", first.Endpoint.Address);
        Assert.NotEqual(first.Endpoint.Address, second.Endpoint!.Address);
        Assert.Null(first.DirectoryPath);
        Assert.Empty(Directory.EnumerateFileSystemEntries(world.Root));
    }

    [Fact]
    public async Task DisposingALaunchRemovesItsWholeDirectoryByOneRenameAndLeavesNothingBehind()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard);
        var directory = launch.DirectoryPath!;
        await File.WriteAllTextAsync(Path.Combine(directory, "s"), "socket stand-in", TestContext.Current.CancellationToken);

        await launch.DisposeAsync();
        await launch.DisposeAsync();

        Assert.False(Directory.Exists(directory));
        Assert.Empty(Directory.EnumerateFileSystemEntries(world.Root));
        Assert.True(launch.Revoked.IsCancellationRequested);
        Assert.Equal(LocalRpcLaunchRefusal.Revoked, launch.Status());
        LaunchDirectory.Remove(directory);
        LaunchDirectory.Remove(Path.Combine(world.Root, "000000000000"));
    }

    [Fact]
    public async Task RevokingALaunchKeepsItsFilesUntilItIsDisposed()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var launch = authority.Launch("slot-a", Standard);

        launch.Revoke();

        Assert.True(Directory.Exists(launch.DirectoryPath));
        await launch.DisposeAsync();
        Assert.False(Directory.Exists(launch.DirectoryPath));
    }

    [Fact]
    public async Task AuthorityDisposalRemovesEveryIssuedLaunchDirectoryIncludingSupersededOnes()
    {
        using var world = new LaunchWorld();
        var authority = world.Authority();
        string[] slots = ["slot-a", "slot-b", "slot-c"];
        var directories = slots.Select(slot => authority.Launch(slot, Standard).DirectoryPath!).ToArray();
        var superseding = authority.Launch("slot-a", Standard).DirectoryPath!;
        Assert.True(Directory.Exists(superseding));
        Assert.All(directories, directory => Assert.True(Directory.Exists(directory)));

        await authority.DisposeAsync();

        Assert.False(Directory.Exists(superseding));
        Assert.All(directories, directory => Assert.False(Directory.Exists(directory)));
        Assert.Empty(Directory.EnumerateFileSystemEntries(world.Root));
    }

    [Fact]
    public async Task ALaunchDirectoryIsNeverVisibleWithoutItsRecord()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var stop = false;
        var violations = new List<string>();
        var watcher = Task.Run(() =>
        {
            while (!Volatile.Read(ref stop))
            {
                foreach (var entry in Directory.EnumerateDirectories(world.Root))
                {
                    var name = Path.GetFileName(entry);
                    if (name.Length == 12 && !name.StartsWith('.') && LaunchDirectory.ReadRecord(LaunchDirectory.RecordPath(entry)) is null && Directory.Exists(entry))
                    {
                        lock (violations)
                        {
                            violations.Add(name);
                        }
                    }
                }
            }
        }, TestContext.Current.CancellationToken);

        for (var index = 0; index < 60; index++)
        {
            await authority.Launch("slot-" + (index % 3), Standard).DisposeAsync();
        }

        Volatile.Write(ref stop, true);
        await watcher;
        Assert.Empty(violations);
    }

    // ---- records ----

    [Theory]
    [InlineData("truncated")]
    [InlineData("magic")]
    [InlineData("version")]
    [InlineData("length")]
    [InlineData("pid")]
    [InlineData("missing")]
    public void AnyDamagedRecordNamesNoParent(string damage)
    {
        using var world = new LaunchWorld();
        var directory = Path.Combine(Path.GetDirectoryName(world.Root)!, "rec");
        _ = Directory.CreateDirectory(directory);
        var good = LaunchDirectory.Publish(Directory.CreateDirectory(Path.Combine(directory, "r")).FullName, Guid.NewGuid(), world.Parent, 1, "x");
        var path = LaunchDirectory.RecordPath(good);
        var bytes = File.ReadAllBytes(path);
        Assert.Equal(world.Parent, LaunchDirectory.ReadRecord(path));

        switch (damage)
        {
            case "truncated":
                bytes = bytes[..43];
                break;
            case "magic":
                bytes[0] ^= 0xFF;
                break;
            case "version":
                bytes[5] = 9;
                break;
            case "length":
                bytes[43] = 7;
                break;
            case "pid":
                Array.Clear(bytes, 22, 4);
                break;
            default:
                File.Delete(path);
                break;
        }

        if (damage != "missing")
        {
            File.WriteAllBytes(path, bytes);
        }

        Assert.Null(LaunchDirectory.ReadRecord(path));
        Assert.Equal(
            damage == "missing" ? LaunchDirectory.RecordState.Missing : LaunchDirectory.RecordState.Invalid,
            LaunchDirectory.ReadRecordState(path, out _));
    }

    // ---- sweep ----

    [Fact]
    public async Task TheSweepRemovesOnlyDirectoriesOfDeadParents()
    {
        using var world = new LaunchWorld();
        var dead = world.SpawnFake(7001);
        var unknown = world.SpawnFake(7002);
        var live = world.SpawnFake(7003);
        await using var survivor = world.Authority();
        var keep = survivor.Launch("slot-keep", Standard).DirectoryPath!;
        var directories = new Dictionary<string, string>();
        var others = new List<LocalRpcLaunchAuthority>();
        foreach (var (name, parent) in new[] { ("dead", dead), ("unknown", unknown), ("live", live) })
        {
            var other = world.Authority(parent);
            others.Add(other);
            directories[name] = other.Launch("slot-" + name, Standard).DirectoryPath!;
        }

        world.Processes.Set(dead, ProcessLiveness.Dead);
        world.Processes.Set(unknown, ProcessLiveness.Unknown);
        var removed = survivor.SweepStale();

        Assert.Equal(1, removed);
        Assert.False(Directory.Exists(directories["dead"]));
        Assert.True(Directory.Exists(directories["unknown"]));
        Assert.True(Directory.Exists(directories["live"]));
        Assert.True(Directory.Exists(keep));
        Assert.Equal(0, survivor.SweepStale());
        foreach (var other in others)
        {
            await other.DisposeAsync();
        }
    }

    [Fact]
    public async Task CreatingAnAuthorityAfterAParentDiedRemovesTheOrphanAndNeverAuthorizesItsDescriptor()
    {
        using var world = new LaunchWorld();
        var previous = world.SpawnFake(7101);
        await using var old = world.Authority(previous);
        var orphan = old.Launch("slot-a", Standard);
        var oldClaim = orphan.Descriptor.ToClaim();
        var oldBytes = orphan.Descriptor.Encode();
        world.Processes.Set(previous, ProcessLiveness.Dead);
        Assert.True(Directory.Exists(orphan.DirectoryPath));

        await using var fresh = world.Authority();

        Assert.False(Directory.Exists(orphan.DirectoryPath));
        Assert.Equal(LocalRpcLaunchRefusal.ParentMismatch, orphan.Status());
        Assert.Equal(LocalRpcLaunchRefusal.UnknownSlot, fresh.Verify(oldClaim));
        // Even once the same slot is launched again with the same epoch number, the old descriptor's identity does not match.
        var current = fresh.Launch("slot-a", Standard);
        Assert.Equal(oldClaim.Epoch, current.Descriptor.Epoch);
        Assert.Equal(LocalRpcLaunchRefusal.UnknownLaunch, fresh.Verify(LocalRpcLaunchDescriptor.Decode(oldBytes).ToClaim()));
        Assert.Equal(LocalRpcLaunchRefusal.None, fresh.Verify(current.Descriptor.ToClaim()));
    }

    [Fact]
    public async Task ARecycledProcessIdIsDeadAndTheRealParentIsKept()
    {
        using var world = new LaunchWorld();
        _ = Directory.CreateDirectory(Path.GetDirectoryName(world.Root)!);
        LaunchDirectory.CreateOwnerOnly(world.Root);
        var current = LocalRpcProcessIdentity.Current;
        var recycled = LaunchDirectory.Publish(world.Root, Guid.NewGuid(), current with { StartTimeUtcTicks = current.StartTimeUtcTicks + TimeSpan.FromHours(1).Ticks }, 1, null);
        var real = LaunchDirectory.Publish(world.Root, Guid.NewGuid(), current, 1, null);

        await using var authority = LocalRpcLaunchAuthority.Create(world.Root);

        Assert.False(Directory.Exists(recycled));
        Assert.True(Directory.Exists(real));
    }

    [Fact]
    public async Task ADirectoryWithNoRecordIsRemovedOnlyOnceItIsOld()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var recordless = Path.Combine(world.Root, "0123456789ab");
        LaunchDirectory.CreateOwnerOnly(recordless);

        Assert.Equal(0, authority.SweepStale());
        world.Clock.Advance(TimeSpan.FromSeconds(59));
        Assert.Equal(0, authority.SweepStale());
        world.Clock.Advance(TimeSpan.FromSeconds(2));
        Assert.Equal(1, authority.SweepStale());

        Assert.False(Directory.Exists(recordless));
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("short")]
    [InlineData("newer-version")]
    [InlineData("newer-version-dead-parent")]
    public async Task ARecordThatExistsButIsNotUnderstoodNeverMakesADirectoryStale(string kind)
    {
        using var world = new LaunchWorld();
        var dead = world.SpawnFake(7301, ProcessLiveness.Dead);
        await using var authority = world.Authority();
        var parent = kind == "newer-version-dead-parent" ? dead : world.Parent;
        var directory = LaunchDirectory.Publish(world.Root, Guid.NewGuid(), parent, 1, null);
        var record = LaunchDirectory.RecordPath(directory);
        var bytes = await File.ReadAllBytesAsync(record, TestContext.Current.CancellationToken);
        switch (kind)
        {
            case "garbage":
                bytes = [9, 9, 9, 9, 9, 9, 9, 9];
                break;
            case "short":
                bytes = bytes[..20];
                break;
            default:
                bytes[5] = 2;
                break;
        }

        await File.WriteAllBytesAsync(record, bytes, TestContext.Current.CancellationToken);
        world.Clock.Advance(TimeSpan.FromHours(1));

        Assert.Equal(0, authority.SweepStale());
        Assert.Equal(0, authority.SweepStale());

        Assert.True(Directory.Exists(directory));
        Assert.Equal(LaunchDirectory.RecordState.Invalid, LaunchDirectory.ReadRecordState(record, out _));
    }

    [Fact(Skip = WindowsOnly, SkipUnless = nameof(IsWindows))]
    public async Task OnWindowsARecordAnotherProgramHoldsOpenNeverMakesADirectoryStale()
    {
        using var world = new LaunchWorld();
        var dead = world.SpawnFake(7401, ProcessLiveness.Dead);
        await using var authority = world.Authority();
        var directory = LaunchDirectory.Publish(world.Root, Guid.NewGuid(), dead, 1, null);
        var record = LaunchDirectory.RecordPath(directory);
        world.Clock.Advance(TimeSpan.FromHours(1));

        await using (new FileStream(record, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Assert.Equal(LaunchDirectory.RecordState.Unreadable, LaunchDirectory.ReadRecordState(record, out _));
            Assert.Equal(0, authority.SweepStale());
            Assert.True(Directory.Exists(directory));
        }

        Assert.Equal(1, authority.SweepStale());
        Assert.False(Directory.Exists(directory));
    }

    [Fact]
    public async Task InterruptedRemovalsAreCleanedUpAtOnceAndInterruptedCreatesWhenAbandoned()
    {
        using var world = new LaunchWorld();
        var dead = world.SpawnFake(7201);
        await using var authority = world.Authority();
        var leftoverRemoval = Path.Combine(world.Root, ".d-0123456789abcdef");
        var deadCreate = Path.Combine(world.Root, ".n-0123456789abcdef");
        var freshCreate = Path.Combine(world.Root, ".n-fedcba9876543210");
        LaunchDirectory.CreateOwnerOnly(leftoverRemoval);
        await File.WriteAllTextAsync(Path.Combine(leftoverRemoval, "x"), "x", TestContext.Current.CancellationToken);
        _ = LaunchDirectory.Publish(world.Root, Guid.NewGuid(), dead, 1, null);
        Directory.Move(Directory.EnumerateDirectories(world.Root).Single(entry => Path.GetFileName(entry).Length == 12), deadCreate);
        world.Processes.Set(dead, ProcessLiveness.Dead);
        LaunchDirectory.CreateOwnerOnly(freshCreate);

        Assert.Equal(1, authority.SweepStale());

        Assert.False(Directory.Exists(leftoverRemoval));
        Assert.True(Directory.Exists(deadCreate));
        Assert.True(Directory.Exists(freshCreate));
        world.Clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(2, authority.SweepStale());
        Assert.False(Directory.Exists(deadCreate));
        Assert.False(Directory.Exists(freshCreate));
    }

    [Fact]
    public async Task TheSweepIgnoresForeignEntriesAndLinks()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var foreignDirectory = Path.Combine(world.Root, "someone-elses-directory");
        var lookalikes = LookalikeNames.Select(name => Path.Combine(world.Root, name)).ToArray();
        foreach (var lookalike in lookalikes)
        {
            LaunchDirectory.CreateOwnerOnly(lookalike);
        }

        var foreignFile = Path.Combine(world.Root, "0123456789ab.txt");
        LaunchDirectory.CreateOwnerOnly(foreignDirectory);
        await File.WriteAllTextAsync(foreignFile, "keep", TestContext.Current.CancellationToken);
        var target = Path.Combine(Path.GetDirectoryName(world.Root)!, "link-target");
        _ = Directory.CreateDirectory(target);
        await File.WriteAllTextAsync(Path.Combine(target, "precious"), "keep", TestContext.Current.CancellationToken);
        var link = Path.Combine(world.Root, "0123456789ab");
        var linked = TestLinks.TryCreateDirectoryLink(link, target);

        world.Clock.Advance(TimeSpan.FromHours(1));
        Assert.Equal(0, authority.SweepStale());

        Assert.True(Directory.Exists(foreignDirectory));
        Assert.All(lookalikes, lookalike => Assert.True(Directory.Exists(lookalike)));
        Assert.True(File.Exists(foreignFile));
        Assert.True(File.Exists(Path.Combine(target, "precious")));
        Assert.True(!linked || Directory.Exists(link));
        Assert.Equal(linked, new DirectoryInfo(link).LinkTarget is not null || (new DirectoryInfo(link).Attributes & FileAttributes.ReparsePoint) != 0);
    }


    // ---- paths that only a race or a held handle reaches (review finding 7)

    [Fact]
    public void ConcurrentCreationOfTheSameRootBySeveralThreadsAlwaysSucceeds()
    {
        using var world = new LaunchWorld();
        var parent = Path.GetDirectoryName(world.Root)!;
        _ = Directory.CreateDirectory(parent);

        for (var round = 0; round < 40; round++)
        {
            var root = Path.Combine(parent, "race-" + round);
            var results = Enumerable.Range(0, 8).AsParallel().WithDegreeOfParallelism(8).Select(_ => LaunchDirectory.EnsureRoot(root)).ToArray();

            Assert.All(results, result => Assert.Equal(root, result));
            LaunchDirectory.RequireOwnerOnly(root);
        }
    }

    [Fact]
    public async Task APublishedNameThatAlreadyExistsIsSkippedAndGivingUpIsAnError()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var taken = Path.Combine(world.Root, "aaaaaaaaaaaa");
        LaunchDirectory.CreateOwnerOnly(taken);
        await File.WriteAllTextAsync(Path.Combine(taken, "mine"), "must survive", TestContext.Current.CancellationToken);
        var names = new Queue<string>(["aaaaaaaaaaaa", "aaaaaaaaaaaa", "bbbbbbbbbbbb"]);

        var published = LaunchDirectory.Publish(world.Root, Guid.NewGuid(), world.Parent, 1, null, names.Dequeue);

        Assert.Equal(Path.Combine(world.Root, "bbbbbbbbbbbb"), published);
        Assert.Empty(names);
        Assert.Equal("must survive", await File.ReadAllTextAsync(Path.Combine(taken, "mine"), TestContext.Current.CancellationToken));
        Assert.Throws<IOException>(() => LaunchDirectory.Publish(world.Root, Guid.NewGuid(), world.Parent, 1, null, () => "aaaaaaaaaaaa"));
        Assert.Equal(
            ["aaaaaaaaaaaa", "bbbbbbbbbbbb"],
            Directory.EnumerateDirectories(world.Root).Select(Path.GetFileName).Order(StringComparer.Ordinal));
    }

    [Fact(Skip = WindowsOnly, SkipUnless = nameof(IsWindows))]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000", Justification = "The second handle is disposed by the task that releases it.")]
    public async Task OnWindowsARenameThatAHandleBlocksIsRetriedThenGivenUpAndRemoveLeavesTheFilesForALaterSweep()
    {
        using var world = new LaunchWorld();
        await using var authority = world.Authority();
        var source = Path.Combine(world.Root, "0000000000a1");
        var destination = Path.Combine(world.Root, "0000000000a2");
        LaunchDirectory.CreateOwnerOnly(source);
        var held = Path.Combine(source, "held");

        await using (new FileStream(held, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            Assert.Throws<IOException>(() => LaunchDirectory.MoveWithRetry(source, destination));
            Assert.True(Directory.Exists(source));
            LaunchDirectory.Remove(source);
            Assert.True(Directory.Exists(source), "a directory that cannot be removed yet is left in place, not half-deleted");
        }

        // The handle is released while a rename is being retried: the retry succeeds.
        var again = new FileStream(held, FileMode.Open, FileAccess.Write, FileShare.None);
        var releasing = Task.Run(async () =>
        {
            await Task.Delay(60, TestContext.Current.CancellationToken);
            await again.DisposeAsync();
        }, TestContext.Current.CancellationToken);
        LaunchDirectory.MoveWithRetry(source, destination);
        await releasing;

        Assert.False(Directory.Exists(source));
        Assert.True(Directory.Exists(destination));
        LaunchDirectory.Remove(destination);
        Assert.False(Directory.Exists(destination));
    }


    [Fact]
    public void AnOwnerOnlyDirectoryIsNeverCreatedOverAnExistingOne()
    {
        using var world = new LaunchWorld();
        _ = Directory.CreateDirectory(Path.GetDirectoryName(world.Root)!);
        LaunchDirectory.CreateOwnerOnly(world.Root);

        Assert.Throws<IOException>(() => LaunchDirectory.CreateOwnerOnly(world.Root));
        Assert.Throws<IOException>(() => LaunchDirectory.CreateOwnerOnly(Path.GetDirectoryName(world.Root)!));
    }

    [Fact(Skip = WindowsOnly, SkipUnless = nameof(IsWindows))]
    [SupportedOSPlatform("windows")]
    public async Task OnWindowsARootThatNamesOnlyTheUserSystemAndAdministratorsIsAccepted()
    {
        using var world = new LaunchWorld();
        _ = Directory.CreateDirectory(Path.GetDirectoryName(world.Root)!);
        var user = WindowsIdentity.GetCurrent().User!;
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var identity in new SecurityIdentifier[]
        {
            user,
            new(WellKnownSidType.LocalSystemSid, null),
            new(WellKnownSidType.BuiltinAdministratorsSid, null),
        })
        {
            security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }

        new DirectoryInfo(world.Root).Create(security);

        await using var authority = LocalRpcLaunchAuthority.Create(world.Root);
        Assert.Equal(1UL, authority.Launch("slot-a", Standard, LocalRpcLaunchTransport.SuppliedStreams).Descriptor.Epoch);
    }
}
