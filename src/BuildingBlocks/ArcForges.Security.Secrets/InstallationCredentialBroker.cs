// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;

namespace ArcForges.Security.Secrets;

/// <summary>
/// Purpose-separated installation key custody before account authentication. The owning first-party host supplies
/// the real installation namespace; SameUserShared is explicitly not malicious sibling OS isolation.
/// </summary>
public sealed class InstallationCredentialBroker : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly ISecretBackingStore _store;
    private readonly IInstallationPrincipal _principal;
    private readonly byte[] _scopeHash;
    private readonly string _target;
    private readonly Mutex _mutex;
    private readonly SemaphoreSlim _serial = new(1, 1);
    private readonly CancellationTokenSource _retirement = new();
    private readonly TimeSpan _timeout;
    private TaskCompletionSource _drained = CompletedDrain();
    private Task? _disposeTask;
    private int _active;
    private bool _closed;
    private InstallationCredentialIdentity? _unresolvedWrite;

    internal InstallationCredentialBroker(InstallationCredentialScope scope, ISecretBackingStore store,
        IInstallationPrincipal principal, TimeSpan timeout)
    {
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _principal = principal ?? throw new ArgumentNullException(nameof(principal));
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30)) throw new ArgumentOutOfRangeException(nameof(timeout));
        _timeout = timeout; IsolationAssurance = store.Isolation;
        _scopeHash = ComputeScopeHash(scope, principal.Binding);
        _target = "ArcForges.Secrets.v1." + Convert.ToHexString(_scopeHash);
        // Global is necessary across logon sessions of the same Windows user. Default OS access checks remain;
        // the namespace hash is not a claim of per-application isolation or a substitute for an OS ACL.
        _mutex = new Mutex(false, "Global\\ArcForges.InstallationCredential.v1." + Convert.ToHexString(_scopeHash));
    }

    public InstallationCredentialScope Scope { get; }
    public SecretStoreIsolation IsolationAssurance { get; }
    internal string StorageTarget => _target;

    public static InstallationCredentialSupport GetPlatformSupport(InstallationCredentialPlatform platform)
        => OperatingSystem.IsWindows() && platform == InstallationCredentialPlatform.Windows
            ? InstallationCredentialSupport.WindowsSameUserShared : InstallationCredentialSupport.Unsupported;

    /// <summary>Real available Windows composition; absent Mac/Linux backing adapters return a typed refusal.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "A successful typed outcome transfers the actual broker to its caller, which joins DisposeAsync; no broker is allocated on unsupported composition.")]
    [SuppressMessage("Design", "CA1031", Justification = "Unavailable OS identity or named-mutex infrastructure is a typed pre-effect refusal, never a fake protected-store fallback.")]
    public static Outcome<InstallationCredentialBroker> CreateForCurrentPlatform(InstallationCredentialScope scope,
        SecretIsolationPolicy isolationPolicy, TimeSpan? operationTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (!Enum.IsDefined(isolationPolicy)) throw new ArgumentOutOfRangeException(nameof(isolationPolicy));
        if (GetPlatformSupport(scope.Platform) == InstallationCredentialSupport.Unsupported
            || isolationPolicy == SecretIsolationPolicy.RequireOsEnforcedPerApplication)
            return Failure<InstallationCredentialBroker>("security.isolation_unavailable", EffectCertainty.DidNotHappen);
        if (!OperatingSystem.IsWindows()) return Failure<InstallationCredentialBroker>("security.isolation_unavailable", EffectCertainty.DidNotHappen);
        var timeout = operationTimeout ?? TimeSpan.FromSeconds(10);
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30)) throw new ArgumentOutOfRangeException(nameof(operationTimeout));
        try
        {
            return Outcome.Success(new InstallationCredentialBroker(scope, new WindowsCredentialManagerSecretStore(),
                new WindowsInstallationPrincipal(), timeout));
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        { return Failure<InstallationCredentialBroker>("dependency.unavailable", EffectCertainty.DidNotHappen); }
    }

    /// <summary>
    /// Explicit first-installation initialization. Valid existing protected state is reused; corruption or an
    /// unresolved previous write never causes replacement. Login uses OpenExistingAsync and never rotates a key.
    /// </summary>
    public ValueTask<Outcome<InstallationCredentialIdentity>> InitializeNewInstallationAsync(CancellationToken cancellationToken = default)
        => RunAsync(Initialize, cancellationToken);

    /// <summary>Opens only the actual expected stable key. Missing/corrupt state is a refusal, never regeneration.</summary>
    public ValueTask<Outcome<InstallationCredentialIdentity>> OpenExistingAsync(InstallationCredentialIdentity expected,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expected);
        return RunAsync((_, token) => ReadExisting(expected, token), cancellationToken);
    }

    private Outcome<InstallationCredentialIdentity> ReadExisting(InstallationCredentialIdentity expected, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var raw = _store.Read(_target);
        if (raw is null) return Failure<InstallationCredentialIdentity>("state.not_found", EffectCertainty.DidNotHappen);
        try
        {
            using var key = InstallationCredentialRecord.Open(raw, _scopeHash, out var identity);
            if (!identity.Matches(expected)) return Failure<InstallationCredentialIdentity>("conflict.revision_mismatch", EffectCertainty.DidNotHappen);
            if (_unresolvedWrite is not null && !identity.Matches(_unresolvedWrite))
                return Failure<InstallationCredentialIdentity>("dependency.unavailable", EffectCertainty.Unknown);
            _unresolvedWrite = null;
            token.ThrowIfCancellationRequested();
            return Outcome.Success(identity);
        }
        catch (Exception exception) when (exception is InvalidDataException or CryptographicException or ArgumentException)
        { return Failure<InstallationCredentialIdentity>("resource.integrity_failed", EffectCertainty.DidNotHappen); }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }

    [SuppressMessage("Design", "CA1031", Justification = "Any protected-store write failure requires exact readback reconciliation before returning; external exception details never escape.")]
    private Outcome<InstallationCredentialIdentity> Initialize(OperationEffects effects, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var raw = _store.Read(_target);
        if (raw is not null)
        {
            try
            {
                using var key = InstallationCredentialRecord.Open(raw, _scopeHash, out var identity);
                if (_unresolvedWrite is not null && !identity.Matches(_unresolvedWrite))
                    return Failure<InstallationCredentialIdentity>("dependency.unavailable", EffectCertainty.Unknown);
                _unresolvedWrite = null; token.ThrowIfCancellationRequested(); return Outcome.Success(identity);
            }
            catch (Exception exception) when (exception is InvalidDataException or CryptographicException or ArgumentException)
            { return Failure<InstallationCredentialIdentity>("resource.integrity_failed", EffectCertainty.DidNotHappen); }
            finally { CryptographicOperations.ZeroMemory(raw); }
        }
        if (_unresolvedWrite is not null) return Failure<InstallationCredentialIdentity>("dependency.unavailable", EffectCertainty.Unknown);
        var candidate = InstallationCredentialRecord.Create(_scopeHash, out var created);
        try
        {
            token.ThrowIfCancellationRequested();
            _unresolvedWrite = created;
            effects.Certainty = EffectCertainty.Unknown;
            try { _store.Write(_target, candidate); }
            catch (Exception exception) when (exception is not OutOfMemoryException) { /* Reconcile actual state before classifying or retrying a write. */ }
            byte[]? readback;
            try { readback = _store.Read(_target); }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                return token.IsCancellationRequested ? Outcome.Cancelled<InstallationCredentialIdentity>(EffectCertainty.Unknown)
                : Failure<InstallationCredentialIdentity>("dependency.unavailable", EffectCertainty.Unknown);
            }
            if (readback is null) return token.IsCancellationRequested ? Outcome.Cancelled<InstallationCredentialIdentity>(EffectCertainty.Unknown)
                : Failure<InstallationCredentialIdentity>("dependency.unavailable", EffectCertainty.Unknown);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(candidate, readback))
                    return token.IsCancellationRequested ? Outcome.Cancelled<InstallationCredentialIdentity>(EffectCertainty.Unknown)
                        : Failure<InstallationCredentialIdentity>("dependency.unavailable", EffectCertainty.Unknown);
                _unresolvedWrite = null;
                effects.Certainty = EffectCertainty.Happened;
                return token.IsCancellationRequested ? Outcome.Cancelled<InstallationCredentialIdentity>(EffectCertainty.Happened) : Outcome.Success(created);
            }
            finally { CryptographicOperations.ZeroMemory(readback); }
        }
        finally { CryptographicOperations.ZeroMemory(candidate); }
    }

    [SuppressMessage("Design", "CA1031", Justification = "External protected-store failures become a closed typed outcome; no exception message, target or key escapes.")]
    private async ValueTask<Outcome<T>> RunAsync<T>(Func<OperationEffects, CancellationToken, Outcome<T>> operation, CancellationToken caller)
    {
        lock (_gate)
        {
            if (_closed) return Failure<T>("state.gone", EffectCertainty.DidNotHappen);
            if (caller.IsCancellationRequested) return Outcome.Cancelled<T>(EffectCertainty.DidNotHappen);
            if (_active >= 32) return Failure<T>("capacity.busy", EffectCertainty.DidNotHappen);
            if (_active++ == 0) _drained = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        bool serial = false;
        var effects = new OperationEffects();
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(caller, _retirement.Token);
        bounded.CancelAfter(_timeout);
        try
        {
            await _serial.WaitAsync(bounded.Token).ConfigureAwait(false); serial = true;
            // The mutex owner remains on this one thread through every read/write/readback and ReleaseMutex.
            return await Task.Run(() => WithMutex(operation, effects, bounded.Token), CancellationToken.None).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return caller.IsCancellationRequested || _retirement.IsCancellationRequested ? Outcome.Cancelled<T>(effects.Certainty)
            : Failure<T>("dependency.timeout", effects.Certainty);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        { return Failure<T>("dependency.unavailable", effects.Certainty); }
        finally
        {
            if (serial) _serial.Release();
            lock (_gate) { if (--_active == 0) _drained.TrySetResult(); }
        }
    }

    private Outcome<T> WithMutex<T>(Func<OperationEffects, CancellationToken, Outcome<T>> operation, OperationEffects effects, CancellationToken token)
    {
        bool acquired = false;
        try
        {
            token.ThrowIfCancellationRequested();
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    var result = WaitHandle.WaitAny([_mutex, token.WaitHandle]);
                    if (result != 0) throw new OperationCanceledException(token);
                }
                else
                {
                    // Unix named mutexes cannot participate in WaitAny with the token event.
                    // Retain the actual thread-affine named mutex, with bounded cancellation checks.
                    while (!_mutex.WaitOne(20)) token.ThrowIfCancellationRequested();
                }
                acquired = true;
            }
            catch (AbandonedMutexException exception) when (exception.MutexIndex == 0 || !OperatingSystem.IsWindows()) { acquired = true; }
            token.ThrowIfCancellationRequested();
            if (!_principal.IsCurrent()) return Failure<T>("perm.resource_denied", EffectCertainty.DidNotHappen);
            return operation(effects, token);
        }
        finally { if (acquired) _mutex.ReleaseMutex(); }
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            _closed = true;
            _disposeTask ??= DisposeCoreAsync(_drained.Task);
            return new ValueTask(_disposeTask);
        }
    }

    private async Task DisposeCoreAsync(Task drained)
    {
        await Task.Yield();
        try { await _retirement.CancelAsync().ConfigureAwait(false); }
        finally
        {
            await drained.ConfigureAwait(false);
            _mutex.Dispose(); _serial.Dispose(); _retirement.Dispose();
        }
    }

    private static TaskCompletionSource CompletedDrain()
    {
        var result = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); result.SetResult(); return result;
    }

    private static byte[] ComputeScopeHash(InstallationCredentialScope scope, string principal)
    {
        if (string.IsNullOrEmpty(principal) || principal.Length > 256) throw new ArgumentException("A bounded current OS principal is required.", nameof(principal));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("arcforges.installation-private-key.v1\0"u8);
        Span<byte> id = stackalloc byte[16];
        scope.Realm.Value.TryWriteBytes(id, bigEndian: true, out _); hash.AppendData(id);
        scope.Installation.Value.TryWriteBytes(id, bigEndian: true, out _); hash.AppendData(id);
        hash.AppendData([(byte)scope.Platform]);
        AppendBoundedText(hash, scope.Application.ProductId); AppendBoundedText(hash, principal);
        return hash.GetHashAndReset();
    }

    private static void AppendBoundedText(IncrementalHash hash, string value)
    {
        var bytes = new UTF8Encoding(false, true).GetBytes(value);
        Span<byte> length = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)bytes.Length));
        hash.AppendData(length); hash.AppendData(bytes);
    }
    private static Outcome<T> Failure<T>(string code, EffectCertainty effect) => Outcome.Failure<T>(TypedFailure.Create(code, effect: effect));
    private sealed class OperationEffects
    {
        internal EffectCertainty Certainty { get; set; } = EffectCertainty.DidNotHappen;
    }
}

internal interface IInstallationPrincipal
{
    string Binding { get; }
    bool IsCurrent();
}

internal sealed class WindowsInstallationPrincipal : IInstallationPrincipal
{
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal WindowsInstallationPrincipal()
    {
        using var identity = WindowsIdentity.GetCurrent();
        Binding = identity.User?.Value ?? throw new InvalidOperationException("A current Windows user SID is required.");
    }
    public string Binding { get; }
    public bool IsCurrent()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        return StringComparer.Ordinal.Equals(Binding, identity.User?.Value);
    }
}
