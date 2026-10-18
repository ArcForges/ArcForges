// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Security.Secrets;

namespace ArcForges.Tests.SecretStoreTier;

/// <summary>
/// The fixture of ArcForges's OS secret-store integration tier (ArcForges-Design 16-testing-strategy section 1; the node binding's tier,
/// following DesktopPlatform's tests/OsSecretStoreTests fixture). It is the only way the tier's tests reach a store, and it enforces the
/// tier's rules for the whole run. It names no adapter: the tests give it the store, and it counts, bounds and records every call.
/// (The routine store tests compile this file too, for the guard's negative test: without the opt-in it refuses before any call.)
/// <list type="bullet">
/// <item>the single opt-in <c>ARCFORGES_OS_SECRET_STORE_TESTS=1</c> (otherwise the tests are reported as not run, with that reason);</item>
/// <item>canonical, unique entry names: <c>ArcForges.Secrets.v1.</c> plus the uppercase SHA-256 hex of
/// <c>arcforges.os-secret-store-test.v1|&lt;run id&gt;|&lt;n&gt;</c> with a fresh random run id, or for the node binding the node data
/// key name of a fresh random node ID (<c>arcforges.node-data-key.v1|…</c>), each new to this run;</item>
/// <item>the run's name list, written and flushed before each entry is created and kept as the run's evidence;</item>
/// <item>hard limits: at most 4 entries existing at once, 32 secret-store calls, 10 s per call and 5 minutes for the tier;
/// reaching one fails the run, and every later run call is refused with the same reason;</item>
/// <item>exact-name cleanup from the list only, each deletion followed by one read-back that must find the entry absent. After the
/// run has failed, every listed name that may exist gets exactly one bounded exact-name delete and one absence read from a separate
/// cleanup allowance (<see cref="CleanupAllowance"/> calls, 10 s each, sequential, outside the run budget), after waiting once for any timed-out call that may still be running for it. Every name ends with its
/// true outcome in the list (<c>DELETED-ABSENT</c>, <c>DELETE-FAILED</c>, <c>STILL-PRESENT</c>, <c>ABSENCE-UNVERIFIED</c>,
/// <c>NOT-ATTEMPTED</c> or <c>discarded</c>). Nothing is retried beyond that, enumerated or deleted by pattern; a remaining name
/// is evidence (L-26) and needs exact-name manual cleanup.</item>
/// </list>
/// </summary>
[SuppressMessage("Maintainability", "CA1515:Consider making public types internal", Justification = "The fixture of public xunit test classes.")]
public sealed class OsSecretStoreTier : IDisposable
{
    public const int MaximumLiveEntries = 4;
    public const int MaximumCalls = 32;
    public const int CleanupAllowance = 8;
    public const string NamePrefix = "ArcForges.Secrets.v1.";
    public const string NameDomain = "arcforges.os-secret-store-test.v1";
    public const string DeletedAbsent = "DELETED-ABSENT";
    public const string WindowsTierReason =
        "OS secret-store tier: runs only on Windows with ARCFORGES_OS_SECRET_STORE_TESTS=1 (the hosted tier job or eng/os_secret_store_tier.py).";

    public static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan TierTimeout = TimeSpan.FromMinutes(5);

    private readonly Stopwatch _elapsed = Stopwatch.StartNew();
    private readonly Lock _gate = new();
    private readonly Dictionary<string, Entry> _live = new(StringComparer.Ordinal);
    private readonly List<string> _listOrder = [];
    private readonly Dictionary<string, string> _outcomes = new(StringComparer.Ordinal);
    private int _next;
    private int _calls;
    private int _cleanupCalls;
    private readonly List<PendingCall> _pending = [];
    private string? _failure;

    public OsSecretStoreTier()
    {
        RunId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        NameList = Path.Combine(EvidenceDirectory(), "os-secret-store-tier-" + RunId + ".log");
    }

    /// <summary>Whether this process carries the tier's opt-in.</summary>
    public static bool OptedIn => Environment.GetEnvironmentVariable(OsSecretStoreGuard.OptInVariable) == "1";

    /// <summary>The Windows Credential Manager tests run.</summary>
    public static bool WindowsTier => OperatingSystem.IsWindows() && OptedIn;

    /// <summary>The fresh random run id that every entry name of this run is derived from.</summary>
    public string RunId { get; }

    /// <summary>The run's name list (evidence): every entry name, written before the entry is created, and what became of it.</summary>
    public string NameList { get; }

    /// <summary>The run's secret-store calls so far (the cleanup allowance is counted separately).</summary>
    public int Calls
    {
        get
        {
            lock (_gate) return _calls;
        }
    }

    /// <summary>The canonical name of the run's n-th entry.</summary>
    public static string EntryName(string runId, int n) => NamePrefix + Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes(NameDomain + "|" + runId + "|" + n.ToString(CultureInfo.InvariantCulture))));

    /// <summary>
    /// The next entry name, recorded in the name list (and flushed) before the caller creates it. <paramref name="store"/> is the
    /// store the entry will live in; the fixture deletes it there, by exact name, if the test does not. From now on the entry
    /// counts as one that may exist (a write that failed or timed out included) until its outcome is recorded.
    /// </summary>
    public string NewEntry(ISecretBackingStore? store) => List(null, store);

    /// <summary>
    /// As <see cref="NewEntry(ISecretBackingStore?)"/> for a name the test derives itself: the node data key name of a fresh random node
    /// ID (16 section 1: node-binding tests). It must be canonical and new to this run's list.
    /// </summary>
    public string NewEntry(string name, ISecretBackingStore store)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(store);
        if (name.Length != NamePrefix.Length + 64 || !name.StartsWith(NamePrefix, StringComparison.Ordinal)
            || !name[NamePrefix.Length..].All(character => char.IsAsciiDigit(character) || character is >= 'A' and <= 'F'))
        {
            throw new ArgumentException("A tier entry name is canonical: " + NamePrefix + " and 64 uppercase hexadecimal digits.", nameof(name));
        }

        return List(name, store);
    }

    private string List(string? given, ISecretBackingStore? store)
    {
        string name;
        lock (_gate)
        {
            Check();
            if (_live.Count >= MaximumLiveEntries)
            {
                throw Refuse($"the limit of {MaximumLiveEntries} test entries existing at once was reached");
            }

            ++_next;
            name = given ?? EntryName(RunId, _next);
            if (_listOrder.Contains(name, StringComparer.Ordinal))
            {
                throw Refuse("the entry name " + name + " is already on this run's list");
            }

            _live.Add(name, new Entry(store));
            _listOrder.Add(name);
            Record("listed", name);
        }

        return name;
    }

    /// <summary>
    /// One secret-store call of the run, counted and bounded by <see cref="CallTimeout"/>. A call refused by a limit (or after the
    /// run failed) is not made at all; a call that exceeds its bound fails the run with <see cref="TimeoutException"/>.
    /// </summary>
    public T Call<T>(string operation, Func<T> call) => RunCall(null, operation, call);

    // A run call; `name` is the listed entry it is for when the fixture knows it (null for a test's own calls, which may be for any).
    private T RunCall<T>(string? name, string operation, Func<T> call)
    {
        ArgumentNullException.ThrowIfNull(call);
        lock (_gate)
        {
            Check();
            if (_elapsed.Elapsed + CallTimeout > TierTimeout)
            {
                throw Refuse($"the tier's {TierTimeout.TotalMinutes:0} minutes would be exceeded by '{operation}'");
            }

            if (_calls >= MaximumCalls) throw Refuse($"the limit of {MaximumCalls} secret-store calls was reached before '{operation}'");
            _calls++;
        }

        return Bounded(name, operation, call, failRun: true);
    }

    /// <summary>As <see cref="Call{T}(string, Func{T})"/> for a call without a result.</summary>
    public void Call(string operation, Action call)
    {
        ArgumentNullException.ThrowIfNull(call);
        _ = Call(operation, () =>
        {
            call();
            return true;
        });
    }

    /// <summary>
    /// Deletes a listed entry by its exact name and reads it back once; it must be absent. A remaining entry fails the test with its
    /// name and stays recorded as evidence. If the run's limits refuse the delete or the read-back (the run has failed), the entry
    /// gets the one cleanup attempt of the cleanup allowance instead. Nothing is retried beyond that.
    /// </summary>
    public void Remove(string name)
    {
        ISecretBackingStore store;
        bool deleted;
        lock (_gate)
        {
            if (!_live.TryGetValue(name, out var entry) || entry.Store is null)
            {
                throw new InvalidOperationException("Only a live entry of this run's name list, with its store, can be removed: " + name);
            }

            store = entry.Store;
            deleted = entry.Deleted;
        }

        if (!deleted)
        {
            try
            {
                _ = RunCall(name, "delete " + name, () => store.Delete(name));
            }
            catch (TierRefusedException)
            {
                CleanUp(name);
                throw;
            }
            catch (Exception failure) when (failure is not OutOfMemoryException)
            {
                Finish(name, "DELETE-FAILED (" + Describe(failure) + "; never retried)");
                throw;
            }

            lock (_gate) _live[name] = _live[name] with { Deleted = true };
        }

        VerifyAbsent(name, store);
    }

    /// <summary>
    /// Reads a listed entry back once (test verification): it must be absent. A remaining value fails the test and is evidence. If the
    /// run's limits refuse the read, the entry gets the one cleanup attempt of the cleanup allowance instead.
    /// </summary>
    public void VerifyAbsent(string name, ISecretBackingStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        lock (_gate)
        {
            if (!_live.ContainsKey(name)) throw new InvalidOperationException("Not a live entry of this run's name list: " + name);
        }

        byte[]? remaining;
        try
        {
            remaining = RunCall(name, "read back " + name, () => store.Read(name));
        }
        catch (TierRefusedException)
        {
            CleanUp(name);
            throw;
        }
        catch (Exception failure) when (failure is not OutOfMemoryException)
        {
            Finish(name, "ABSENCE-UNVERIFIED (" + Describe(failure) + "; never retried)");
            throw;
        }

        if (remaining is not null)
        {
            CryptographicOperations.ZeroMemory(remaining);
            Finish(name, "STILL-PRESENT (evidence; never retried)");
            Assert.Fail("The OS secret store still returned a value for the deleted test entry " + name
                + " (evidence, never retried; it needs exact-name manual cleanup; see " + NameList + ").");
        }

        Finish(name, DeletedAbsent);
    }

    /// <summary>
    /// Records that a listed entry needs no deletion because it was never created in a persistent store (its write failed closed,
    /// or its store was a private keyring that the test destroyed with its files).
    /// </summary>
    public void Discard(string name, string reason)
    {
        lock (_gate)
        {
            if (!_live.ContainsKey(name)) throw new InvalidOperationException("Not a live entry of this run's name list: " + name);
        }

        Finish(name, "discarded (" + reason + ")");
    }

    /// <summary>
    /// Gives every listed entry that may still exist its one cleanup attempt (exact names only, from the cleanup allowance), then fails
    /// with every name whose absence is not verified: those names are evidence and need exact-name manual cleanup.
    /// </summary>
    [SuppressMessage("Design", "CA1065:Do not raise exceptions in unexpected locations", Justification =
        "xunit reports a failing fixture cleanup as a failed run, which is what an unverified cleanup must be.")]
    public void Dispose()
    {
        foreach (string name in Snapshot()) CleanUp(name);
        List<string> remaining;
        lock (_gate)
        {
            if (_next > 0 || _calls > 0)
            {
                Record(string.Create(CultureInfo.InvariantCulture,
                    $"run ended after {_calls} run calls and {_cleanupCalls} cleanup calls{(_failure is null ? "" : "; run failed: " + _failure)}"), "-");
            }

            remaining = [.. _listOrder.Where(name => !_outcomes.TryGetValue(name, out string? outcome)
                || !(outcome == DeletedAbsent || outcome.StartsWith("discarded", StringComparison.Ordinal)))
                .Select(name => name + " " + (_outcomes.GetValueOrDefault(name) ?? "NOT-ATTEMPTED (no outcome)"))];
        }

        if (remaining.Count > 0)
        {
            throw new InvalidOperationException("The OS secret-store tier could not verify the absence of these test entries; each is "
                + "evidence and needs exact-name manual cleanup (" + NameList + "): " + string.Join("; ", remaining));
        }
    }

    // The one cleanup attempt of a listed entry that may exist: one bounded exact-name delete (unless the run's delete already
    // returned) and one absence read, from the separate cleanup allowance, never past it and never retried.
    private void CleanUp(string name)
    {
        Entry entry;
        lock (_gate)
        {
            if (!_live.TryGetValue(name, out entry)) return;
        }

        if (entry.Store is null)
        {
            Finish(name, "NOT-ATTEMPTED (no store was attached)");
            return;
        }

        if (!OptedIn)
        {
            Finish(name, "NOT-ATTEMPTED (no opt-in in this process)");
            return;
        }

        // A call that timed out keeps running and could land after this cleanup's delete or read (overlapping calls, a wrong
        // outcome). Every timed-out call that may concern this name is waited for once, within its bound; one still pending
        // leaves the name unverified, without any further call.
        foreach (var pending in PendingFor(name))
        {
            if (!pending.Waited)
            {
                pending.Waited = true;
                _ = ((IAsyncResult)pending.Task).AsyncWaitHandle.WaitOne(CallTimeout);
            }

            if (!pending.Task.IsCompleted)
            {
                Finish(name, "ABSENCE-UNVERIFIED (a timed-out call is still pending: " + pending.Operation + "; no further call)");
                return;
            }

            _ = pending.Task.Exception; // observed: its outcome is superseded by the cleanup below
        }

        int needed = entry.Deleted ? 1 : 2;
        lock (_gate)
        {
            if (CleanupAllowance - _cleanupCalls < needed)
            {
                Finish(name, $"NOT-ATTEMPTED (the cleanup allowance of {CleanupAllowance} calls is used up)");
                return;
            }

            _cleanupCalls += needed;
        }

        var store = entry.Store;
        string? deleteFailure = null;
        if (!entry.Deleted)
        {
            try
            {
                _ = Bounded(name, "cleanup delete " + name, () => store.Delete(name), failRun: false);
            }
            catch (TimeoutException failure)
            {
                // The store did not answer within the bound; a read now could only race the pending delete.
                lock (_gate) _cleanupCalls--;
                Finish(name, "DELETE-FAILED (" + Describe(failure) + "; never retried)");
                return;
            }
            catch (Exception failure) when (failure is not OutOfMemoryException)
            {
                deleteFailure = Describe(failure);
            }
        }

        byte[]? remaining;
        try
        {
            remaining = Bounded(name, "cleanup read back " + name, () => store.Read(name), failRun: false);
        }
        catch (Exception failure) when (failure is not OutOfMemoryException)
        {
            Finish(name, deleteFailure is not null
                ? "DELETE-FAILED (" + deleteFailure + "; the absence read also failed: " + Describe(failure) + "; never retried)"
                : "ABSENCE-UNVERIFIED (" + Describe(failure) + "; never retried)");
            return;
        }

        if (remaining is not null)
        {
            CryptographicOperations.ZeroMemory(remaining);
            Finish(name, "STILL-PRESENT (" + (deleteFailure is null ? "after its delete" : "delete failed: " + deleteFailure)
                + "; evidence, never retried)");
            return;
        }

        Finish(name, deleteFailure is null ? DeletedAbsent : DeletedAbsent + " (the delete reported " + deleteFailure + ")");
    }

    private List<PendingCall> PendingFor(string name)
    {
        lock (_gate) return [.. _pending.Where(pending => (pending.Name is null || pending.Name == name) && !pending.Task.IsCompleted)];
    }

    private T Bounded<T>(string? name, string operation, Func<T> call, bool failRun)
    {
        var task = Task.Run(call);
        if (!((IAsyncResult)task).AsyncWaitHandle.WaitOne(CallTimeout))
        {
            string reason = $"'{operation}' did not finish within {CallTimeout.TotalSeconds:0} s";
            lock (_gate)
            {
                // The task keeps running; it is kept so that cleanup never overlaps it.
                _pending.Add(new PendingCall(name, operation, task));
                if (failRun) MarkFailed(reason);
                else Record("CLEANUP-TIMEOUT " + reason, "-");
            }

            throw new TimeoutException(reason);
        }

        return task.GetAwaiter().GetResult();
    }

    private void Finish(string name, string outcome)
    {
        lock (_gate)
        {
            if (!_live.Remove(name)) return;
            _outcomes[name] = outcome;
            Record(outcome, name);
        }
    }

    private List<string> Snapshot()
    {
        lock (_gate) return [.. _listOrder.Where(_live.ContainsKey)];
    }

    private void Check()
    {
        if (!OptedIn) throw new TierRefusedException("The OS secret-store tier runs only with ARCFORGES_OS_SECRET_STORE_TESTS=1.");
        if (_failure is not null) throw new TierRefusedException("The OS secret-store tier run already failed: " + _failure);
    }

    private TierRefusedException Refuse(string reason)
    {
        MarkFailed(reason);
        return new TierRefusedException("The OS secret-store tier run failed: " + reason);
    }

    private void MarkFailed(string reason)
    {
        if (_failure is not null) return;
        _failure = reason;
        Record("RUN-FAILED " + reason, "-");
    }

    private static string Describe(Exception failure) => failure.GetType().Name + ": " + failure.Message;

    // Each line is appended and flushed to the disk before the call that follows it, so the list survives a crash of the run.
    private void Record(string what, string name)
    {
        string line = string.Create(CultureInfo.InvariantCulture,
            $"{DateTimeOffset.UtcNow:O} run={RunId} n={_next} {what} {name}\n");
        Directory.CreateDirectory(Path.GetDirectoryName(NameList)!);
        using var stream = new FileStream(NameList, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
        stream.Write(Encoding.UTF8.GetBytes(line));
        stream.Flush(flushToDisk: true);
    }

    private static string EvidenceDirectory()
    {
        string? configured = Environment.GetEnvironmentVariable("ARCFORGES_OS_SECRET_STORE_TESTS_EVIDENCE");
        return !string.IsNullOrWhiteSpace(configured) ? Path.GetFullPath(configured) : Path.Combine(RepositoryRoot(), "artifacts",
            "evidence", "os-secret-store-tier");
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "ArcForges.slnx"))) return directory.FullName;
        }

        return Path.GetTempPath();
    }

    /// <summary>A listed entry: the store it lives in, and whether the run's delete of it has returned.</summary>
    private readonly record struct Entry(ISecretBackingStore? Store, bool Deleted = false);

    /// <summary>A call that exceeded its bound and may still be running; cleanup waits for it once before touching its name.</summary>
    private sealed class PendingCall(string? name, string operation, Task task)
    {
        public string? Name { get; } = name;
        public string Operation { get; } = operation;
        public Task Task { get; } = task;
        public bool Waited { get; set; }
    }

    /// <summary>A run call that a limit (or the run's earlier failure) refused: the call was not made.</summary>
    private sealed class TierRefusedException : InvalidOperationException
    {
        public TierRefusedException()
        {
        }

        public TierRefusedException(string message)
            : base(message)
        {
        }

        public TierRefusedException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
