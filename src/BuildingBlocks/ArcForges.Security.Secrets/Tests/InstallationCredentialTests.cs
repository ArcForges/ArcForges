// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Errors;
using Xunit;

namespace ArcForges.Security.Secrets.Tests;

public sealed class InstallationCredentialTests
{
    public static bool LocalWindowsStoreEnabled => OperatingSystem.IsWindows()
        && Environment.GetEnvironmentVariable("ARCFORGES_LOCAL_OS_SECRET_STORE") == "1"
        && Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true";

    [Fact]
    public async Task StableProtectedTupleSurvivesRestartAndMetadataCannotBeMutated()
    {
        var scope = Scope(); var store = new Backing();
        InstallationCredentialIdentity original;
        await using (var broker = Broker(scope, store))
        {
            original = Value(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken));
            var mutable = original.GetPublicKey(); mutable[30] ^= 1;
            Assert.NotEqual(mutable, original.GetPublicKey());
            Assert.Equal(original.GetPublicKey(), Value(await broker.OpenExistingAsync(original, TestContext.Current.CancellationToken)).GetPublicKey());
        }
        await using var reopened = Broker(scope, store);
        var repeated = Value(await reopened.InitializeNewInstallationAsync(TestContext.Current.CancellationToken));
        Assert.Equal(original.GetPublicKey(), repeated.GetPublicKey()); Assert.Equal(1, repeated.KeyVersion); Assert.Equal(1, store.Writes);
        Assert.Equal("InstallationCredentialIdentity:[public metadata]", original.ToString());
        Assert.All(store.ReadBuffers, static bytes => Assert.All(bytes, static value => Assert.Equal(0, value)));
    }

    [Fact]
    public async Task MissingExpectedWrongExpectedAndCorruptionNeverReplaceAKey()
    {
        var store = new Backing(); await using var broker = Broker(Scope(), store);
        using var foreign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var expected = new InstallationCredentialIdentity(1, foreign.ExportSubjectPublicKeyInfo());
        Assert.Equal("state.not_found", Code(await broker.OpenExistingAsync(expected, TestContext.Current.CancellationToken)));
        Assert.Equal(0, store.Writes);
        var actual = Value(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken));
        Assert.Equal("conflict.revision_mismatch", Code(await broker.OpenExistingAsync(expected, TestContext.Current.CancellationToken)));
        store.Corrupt();
        Assert.Equal("resource.integrity_failed", Code(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken)));
        Assert.Equal("resource.integrity_failed", Code(await broker.OpenExistingAsync(actual, TestContext.Current.CancellationToken)));
        Assert.Equal(1, store.Writes);
    }

    [Fact]
    public async Task ScopeOrPrincipalSubstitutionCannotUseAnotherStoredKey()
    {
        var scope = Scope(); var store = new Backing(); var principal = new Principal();
        var broker = new InstallationCredentialBroker(scope, store, principal, TimeSpan.FromSeconds(10));
        await using var lease = broker.ConfigureAwait(true);
        Value(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken));
        principal.Current = false;
        Assert.Equal("perm.resource_denied", Code(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken)));
        var other = new InstallationCredentialScope(scope.Realm, SecretApplicationDimension.Companion, scope.Platform, scope.Installation);
        await using var second = Broker(other, store);
        Value(await second.InitializeNewInstallationAsync(TestContext.Current.CancellationToken));
        Assert.Equal(2, store.Targets.Length); Assert.Equal(2, store.Writes);
        Assert.All(store.Targets, static target => Assert.StartsWith("ArcForges.Secrets.v1.", target, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ThrownSuccessfulWriteIsReconciledAndUncertainReadbackIsNotRepeated()
    {
        var store = new Backing { ThrowAfterWrite = true }; await using var broker = Broker(Scope(), store);
        Value(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken)); Assert.Equal(1, store.Writes);
        var uncertain = new Backing { ThrowAfterWrite = true, FailReadback = true }; await using var second = Broker(Scope(), uncertain);
        var refused = await second.InitializeNewInstallationAsync(TestContext.Current.CancellationToken);
        Assert.Equal("dependency.unavailable", Code(refused)); Assert.Equal(EffectCertainty.Unknown, Failure(refused).Effect);
        var recovered = Value(await second.InitializeNewInstallationAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, uncertain.Writes);
        Assert.Equal(recovered.GetPublicKey(), Value(await second.OpenExistingAsync(recovered, TestContext.Current.CancellationToken)).GetPublicKey());
    }

    [Fact]
    public async Task MissingReadbackRemainsUnknownAndNeverInstallsAnotherKey()
    {
        var store = new Backing { DropWrite = true }; await using var broker = Broker(Scope(), store);
        Assert.Equal(EffectCertainty.Unknown, Failure(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken)).Effect);
        Assert.Equal(EffectCertainty.Unknown, Failure(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken)).Effect);
        Assert.Equal(1, store.Writes);
    }

    [Fact]
    public async Task PostCommitSynchronizationFailureNeverRelabelsTheWriteAsNoEffect()
    {
        var store = new Backing(); await using var broker = Broker(Scope(), store);
        store.AfterWrite = () =>
        {
            // Fault-inject only our owned synchronization dependency from its owner thread after real record insertion.
            using var lostLease = new Mutex(false, MutexName(broker)); lostLease.ReleaseMutex();
        };
        var failed = await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken);
        Assert.Equal("dependency.unavailable", Code(failed)); Assert.Equal(EffectCertainty.Happened, Failure(failed).Effect);
        store.AfterWrite = null;
        Value(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken)); Assert.Equal(1, store.Writes);
    }

    [Fact]
    public async Task ConcurrentBrokersSerializeOneRealKeyCreation()
    {
        var scope = Scope(); var store = new Backing();
        await using var first = Broker(scope, store); await using var second = Broker(scope, store);
        var results = await Task.WhenAll(Enumerable.Range(0, 24).Select(index => (index % 2 == 0 ? first : second)
            .InitializeNewInstallationAsync(TestContext.Current.CancellationToken).AsTask()));
        var publicKey = Value(results[0]).GetPublicKey();
        Assert.All(results, result => Assert.Equal(publicKey, Value(result).GetPublicKey())); Assert.Equal(1, store.Writes);
    }

    [Fact]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031", Justification = "The owned holder thread captures its actual exception for an asserting parent after bounded join instead of crashing the test process.")]
    public async Task NamedMutexDeadlineAndCancellationRefuseBeforeTouchingTheStore()
    {
        var store = new Backing();
        var broker = new InstallationCredentialBroker(Scope(), store, new Principal(), TimeSpan.FromMilliseconds(150));
        await using var lease = broker.ConfigureAwait(true);
        using var held = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        Exception? holderFault = null;
        var holder = new Thread(() =>
        {
            try
            {
                using var mutex = new Mutex(false, MutexName(broker)); mutex.WaitOne();
                try { held.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken)); }
                finally { mutex.ReleaseMutex(); }
            }
            catch (Exception exception) { holderFault = exception; held.Set(); }
        });
        holder.Start();
        Assert.True(held.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        try
        {
            var timedOut = await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken);
            Assert.Equal("dependency.timeout", Code(timedOut)); Assert.Equal(EffectCertainty.DidNotHappen, Failure(timedOut).Effect);
            using var canceled = new CancellationTokenSource(TimeSpan.FromMilliseconds(30));
            var outcome = await broker.InitializeNewInstallationAsync(canceled.Token);
            Assert.Equal(OutcomeKind.Cancelled, outcome.Kind); Assert.Equal(EffectCertainty.DidNotHappen, outcome.CancellationEffect);
            Assert.Equal(0, store.Writes); Assert.Empty(store.ReadBuffers);
        }
        finally { release.Set(); Assert.True(holder.Join(TimeSpan.FromSeconds(10))); }
        Assert.Null(holderFault);
        Value(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AbandonedMutexRereadsTheActualExistingTuple()
    {
        var store = new Backing(); await using var broker = Broker(Scope(), store);
        var original = Value(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken));
        using var abandoned = new Mutex(false, MutexName(broker));
        var holder = new Thread(() => abandoned.WaitOne()); holder.Start(); Assert.True(holder.Join(TimeSpan.FromSeconds(10)));
        Assert.Equal(original.GetPublicKey(), Value(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken)).GetPublicKey());
        Assert.Equal(1, store.Writes);
    }

    [Fact]
    public async Task BoundedAdmissionRefusesExcessAndCanceledWaitersDoNotScheduleNativeWrites()
    {
        var store = new Backing(); using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        store.BeforeWrite = () => { entered.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken)); };
        await using var broker = Broker(Scope(), store);
        var first = broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken).AsTask();
        Assert.True(entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        using var queuedCancellation = new CancellationTokenSource();
        try
        {
            var queued = Enumerable.Range(0, 31).Select(_ => broker.InitializeNewInstallationAsync(queuedCancellation.Token).AsTask()).ToArray();
            Assert.Equal("capacity.busy", Code(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken)));
            await queuedCancellation.CancelAsync();
            var refused = await Task.WhenAll(queued);
            Assert.All(refused, static item => { Assert.Equal(OutcomeKind.Cancelled, item.Kind); Assert.Equal(EffectCertainty.DidNotHappen, item.CancellationEffect); });
        }
        finally { release.Set(); }
        Value(await first.ConfigureAwait(true)); Assert.Equal(1, store.Writes);
    }

    [Fact]
    public async Task CancellationBeforeWriteHasNoEffectAndAfterConfirmedWriteReportsHappened()
    {
        var store = new Backing(); await using var broker = Broker(Scope(), store);
        using var before = new CancellationTokenSource(); await before.CancelAsync();
        var refused = await broker.InitializeNewInstallationAsync(before.Token);
        Assert.Equal(OutcomeKind.Cancelled, refused.Kind); Assert.Equal(EffectCertainty.DidNotHappen, refused.CancellationEffect); Assert.Equal(0, store.Writes);
        using var during = new CancellationTokenSource(); store.AfterWrite = during.Cancel;
        var committed = await broker.InitializeNewInstallationAsync(during.Token);
        Assert.Equal(OutcomeKind.Cancelled, committed.Kind); Assert.Equal(EffectCertainty.Happened, committed.CancellationEffect);
        Value(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken)); Assert.Equal(1, store.Writes);
    }

    [Fact]
    public async Task DisposalJoinsHeldNativeAdapterWorkAndAllCallersObserveOneDrain()
    {
        var store = new Backing(); using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        store.BeforeWrite = () => { entered.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken)); };
        var broker = Broker(Scope(), store);
        var running = broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken).AsTask();
        Assert.True(entered.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        try
        {
            var first = broker.DisposeAsync().AsTask(); var second = broker.DisposeAsync().AsTask();
            Assert.Same(first, second); Assert.False(first.IsCompleted);
            Assert.Equal("state.gone", Code(await broker.InitializeNewInstallationAsync(TestContext.Current.CancellationToken)));
            release.Set(); await first.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            var outcome = await running.ConfigureAwait(true);
            Assert.True(outcome.Kind == OutcomeKind.Success || outcome.Kind == OutcomeKind.Cancelled && outcome.CancellationEffect == EffectCertainty.Happened);
        }
        finally { release.Set(); await broker.DisposeAsync().ConfigureAwait(true); }
    }

    [Fact]
    public void ClosedRecordAuthenticatesScopeCanonicalEncodingAndActualIndependentP256Signature()
    {
        var scope = RandomNumberGenerator.GetBytes(32);
        var record = InstallationCredentialRecord.Create(scope, out var identity);
        try
        {
            using var privateKey = InstallationCredentialRecord.Open(record, scope, out var reopened);
            Assert.Equal(identity.GetPublicKey(), reopened.GetPublicKey());
            using var publicKey = ECDsa.Create(); publicKey.ImportSubjectPublicKeyInfo(identity.GetPublicKey(), out _);
            var signature = privateKey.SignData("component-test-only"u8, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Assert.Equal(64, signature.Length);
            Assert.True(publicKey.VerifyData("component-test-only"u8, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            Assert.False(publicKey.VerifyData("changed-component-test"u8, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            scope[0] ^= 1; Assert.Throws<InvalidDataException>(() => InstallationCredentialRecord.Open(record, scope, out _));
            scope[0] ^= 1;
            Assert.Throws<InvalidDataException>(() => InstallationCredentialRecord.Open([.. record, 0], scope, out _));
            record[60] ^= 1; Assert.ThrowsAny<Exception>(() => InstallationCredentialRecord.Open(record, scope, out _));
        }
        finally { CryptographicOperations.ZeroMemory(record); }
        Assert.Throws<ArgumentOutOfRangeException>(() => new InstallationCredentialIdentity(0, identity.GetPublicKey()));
    }

    [Fact]
    public void AbsentAdaptersAndRequiredOsIsolationAreExplicitTypedRefusals()
    {
        var scope = Scope();
        Assert.Equal("security.isolation_unavailable", Code(InstallationCredentialBroker.CreateForCurrentPlatform(scope, SecretIsolationPolicy.RequireOsEnforcedPerApplication)));
        var absent = new InstallationCredentialScope(scope.Realm, scope.Application, InstallationCredentialPlatform.MacOs, scope.Installation);
        Assert.Equal(InstallationCredentialSupport.Unsupported, InstallationCredentialBroker.GetPlatformSupport(InstallationCredentialPlatform.MacOs));
        Assert.Equal(InstallationCredentialSupport.Unsupported, InstallationCredentialBroker.GetPlatformSupport(InstallationCredentialPlatform.Linux));
        Assert.Equal("security.isolation_unavailable", Code(InstallationCredentialBroker.CreateForCurrentPlatform(absent, SecretIsolationPolicy.AllowSameUserSharedStore)));
    }

    [Fact(Skip = "Explicit local Windows Credential Manager opt-in; not OS sibling isolation.", SkipUnless = nameof(LocalWindowsStoreEnabled))]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task ActualWindowsProtectedKeySurvivesBrokerRestartAndIsRemovedOnlyByOwnedTestCleanup()
    {
        var scope = Scope(); string? target = null;
        try
        {
            InstallationCredentialIdentity identity;
            await using (var first = Value(InstallationCredentialBroker.CreateForCurrentPlatform(scope, SecretIsolationPolicy.AllowSameUserSharedStore)))
            {
                target = first.StorageTarget; Assert.Equal(SecretStoreIsolation.SameUserShared, first.IsolationAssurance);
                identity = Value(await first.InitializeNewInstallationAsync(TestContext.Current.CancellationToken));
            }
            await using var restarted = Value(InstallationCredentialBroker.CreateForCurrentPlatform(scope, SecretIsolationPolicy.AllowSameUserSharedStore));
            Assert.Equal(identity.GetPublicKey(), Value(await restarted.OpenExistingAsync(identity, TestContext.Current.CancellationToken)).GetPublicKey());
        }
        finally { if (target is not null) Assert.True(new WindowsCredentialManagerSecretStore().Delete(target)); }
    }

    [Fact(Skip = "Explicit local Windows protected-store/process diagnostic; no different-user isolation claim.", SkipUnless = nameof(LocalWindowsStoreEnabled))]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task ActualOwnedProcessesAndParentInitializeOneStableWindowsKey()
    {
        var scope = Scope(); await using var parent = Value(InstallationCredentialBroker.CreateForCurrentPlatform(scope, SecretIsolationPolicy.AllowSameUserSharedStore));
        using var first = StartChild("initialize", scope); using var second = StartChild("initialize", scope);
        try
        {
            var initialized = parent.InitializeNewInstallationAsync(TestContext.Current.CancellationToken).AsTask();
            var firstKey = await ReadChildAsync(first, TestContext.Current.CancellationToken);
            var secondKey = await ReadChildAsync(second, TestContext.Current.CancellationToken);
            var expected = "KEY 1 " + Convert.ToBase64String(Value(await initialized.ConfigureAwait(true)).GetPublicKey());
            Assert.Equal(expected, firstKey); Assert.Equal(expected, secondKey);
            await WaitForChildExitAsync(first, TestContext.Current.CancellationToken); await WaitForChildExitAsync(second, TestContext.Current.CancellationToken);
            Assert.Equal(0, first.ExitCode); Assert.Equal(0, second.ExitCode);
        }
        finally { StopChild(first); StopChild(second); new WindowsCredentialManagerSecretStore().Delete(parent.StorageTarget); }
    }

    [Fact(Skip = "Explicit local Windows owned-process abandonment diagnostic; not remote or power-loss acceptance.", SkipUnless = nameof(LocalWindowsStoreEnabled))]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task ActualKilledMutexOwnerIsReconciledWithoutChangingTheProtectedKey()
    {
        var scope = Scope(); await using var parent = Value(InstallationCredentialBroker.CreateForCurrentPlatform(scope, SecretIsolationPolicy.AllowSameUserSharedStore));
        try
        {
            var expected = Value(await parent.InitializeNewInstallationAsync(TestContext.Current.CancellationToken));
            using var holder = StartChild("abandon", scope);
            try { Assert.Equal("HELD", await ReadChildAsync(holder, TestContext.Current.CancellationToken)); }
            finally { StopChild(holder); }
            Assert.Equal(expected.GetPublicKey(), Value(await parent.OpenExistingAsync(expected, TestContext.Current.CancellationToken)).GetPublicKey());
            Assert.Equal(expected.GetPublicKey(), Value(await parent.InitializeNewInstallationAsync(TestContext.Current.CancellationToken)).GetPublicKey());
        }
        finally { new WindowsCredentialManagerSecretStore().Delete(parent.StorageTarget); }
    }

    private static Process StartChild(string mode, InstallationCredentialScope scope)
    {
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
        var assembly = Path.Combine(AppContext.BaseDirectory, "ArcForges.Security.Secrets.Tests.dll");
        start.ArgumentList.Add(assembly);
        start.Environment["DOTNET_STARTUP_HOOKS"] = assembly;
        start.Environment["ARCFORGES_INSTALLATION_CREDENTIAL_CHILD"] = mode;
        start.Environment["ARCFORGES_INSTALLATION_CREDENTIAL_REALM"] = scope.Realm.Value.ToString("N");
        start.Environment["ARCFORGES_INSTALLATION_CREDENTIAL_INSTALLATION"] = scope.Installation.Value.ToString("N");
        return Process.Start(start) ?? throw new InvalidOperationException("Owned custody diagnostic process failed to start.");
    }

    private static async Task<string> ReadChildAsync(Process child, CancellationToken cancellationToken)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); bounded.CancelAfter(TimeSpan.FromSeconds(15));
        var line = await child.StandardOutput.ReadLineAsync(bounded.Token).ConfigureAwait(false);
        if (line is null || line.Length > 256) throw new InvalidDataException("Owned child returned no bounded public metadata.");
        return line;
    }
    private static void StopChild(Process child)
    {
        if (!child.HasExited) child.Kill(entireProcessTree: true);
        Assert.True(child.WaitForExit(10_000), "Owned diagnostic process did not confirm exit.");
    }
    private static async Task WaitForChildExitAsync(Process child, CancellationToken cancellationToken)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(TimeSpan.FromSeconds(15));
        await child.WaitForExitAsync(bounded.Token).ConfigureAwait(false);
    }

    private static InstallationCredentialScope Scope() => new(new RealmId(Guid.NewGuid()), SecretApplicationDimension.ArcScope,
        InstallationCredentialPlatform.Windows, new InstallationId(Guid.NewGuid()));
    private static InstallationCredentialBroker Broker(InstallationCredentialScope scope, Backing store)
        => new(scope, store, new Principal(), TimeSpan.FromSeconds(10));
    private static string MutexName(InstallationCredentialBroker broker) => "Global\\ArcForges.InstallationCredential.v1."
        + broker.StorageTarget["ArcForges.Secrets.v1.".Length..];
    private static T Value<T>(Outcome<T> outcome) { Assert.True(outcome.TryGetValue(out var value), outcome.TryGetFailure(out var failure) ? failure.Code : outcome.Kind.ToString()); return value; }
    private static TypedFailure Failure<T>(Outcome<T> outcome) { Assert.True(outcome.TryGetFailure(out var failure)); return failure; }
    private static string Code<T>(Outcome<T> outcome) => Failure(outcome).Code;
    private sealed class Principal : IInstallationPrincipal
    {
        public string Binding => "component-principal";
        public bool Current { get; set; } = true;
        public bool IsCurrent() => Current;
    }
    private sealed class Backing : ISecretBackingStore
    {
        private readonly Dictionary<string, byte[]> _values = [];
        private bool _readbackFault;
        internal List<byte[]> ReadBuffers { get; } = [];
        internal string[] Targets { get { lock (_values) return _values.Keys.ToArray(); } }
        internal int Writes { get; private set; }
        internal bool ThrowAfterWrite { get; init; }
        internal bool FailReadback { get; init; }
        internal bool DropWrite { get; init; }
        internal Action? BeforeWrite { get; set; }
        internal Action? AfterWrite { get; set; }
        public SecretStoreIsolation Isolation => SecretStoreIsolation.SameUserShared;
        public void Write(string opaqueTarget, ReadOnlySpan<byte> secret)
        {
            BeforeWrite?.Invoke();
            lock (_values) { Writes++; if (!DropWrite) _values[opaqueTarget] = secret.ToArray(); _readbackFault = FailReadback; }
            AfterWrite?.Invoke(); if (ThrowAfterWrite) throw new IOException("Unavailable backing adapter reply.");
        }
        public byte[]? Read(string opaqueTarget)
        {
            lock (_values)
            {
                if (_readbackFault) { _readbackFault = false; throw new IOException("Unavailable backing adapter readback."); }
                if (!_values.TryGetValue(opaqueTarget, out var value)) return null;
                var owned = (byte[])value.Clone(); ReadBuffers.Add(owned); return owned;
            }
        }
        public bool Delete(string opaqueTarget) { lock (_values) return _values.Remove(opaqueTarget); }
        internal void Corrupt() { lock (_values) _values.Values.Single()[0] ^= 1; }
    }
}
