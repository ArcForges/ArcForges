// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Node.Store;
using ArcForges.Security.Secrets;

namespace ArcForges.Tests;

/// <summary>
/// The isolated secret-store backend of 16-testing-strategy section 2: an in-memory <see cref="ISecretBackingStore"/>, one instance per
/// test (or per in-process node, so its restarts keep their keys), reporting the backend and protection the node's selection reports
/// (<see cref="NodeSecretStores.TestBackend"/>). Routine tests never reach a real OS secret store (the user's decisions of 2026-10-17);
/// node processes started with <c>--test-mode</c> use the node's file-backed equivalent in their data root instead.
/// <para>Optional scripted faults, for failure-injection tests: the backend unavailable, failing writes, a write that reports success but
/// is not readable later (lost write), and a delete that reports success while the value is still readable (a stale read after delete,
/// L-26). Calls are counted, so a test can show what the node did not do (for example, no read-back after a write: 04 section 2).</para>
/// <para>Cleanup verification (test verification, not production behaviour): <see cref="Remaining"/> reads each listed name back and
/// <see cref="Names"/> lists everything still held, so a fixture reports a leak by name; nothing is ever deleted by pattern.</para>
/// </summary>
internal sealed class IsolatedSecretStore : ISecretBackingStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, byte[]> _entries = new(StringComparer.Ordinal);
    private int _loseWrites;
    private int _loseDeletes;
    private int _failWrites;
    private bool _unavailable;

    public IsolatedSecretStore(SecretStoreBackend? backend = null, SecretStoreProtection? protection = null)
    {
        Backend = backend ?? NodeSecretStores.TestBackend;
        Protection = protection ?? NodeSecretStores.TestProtection;
    }

    /// <summary>The backend this store reports.</summary>
    public SecretStoreBackend Backend { get; }

    /// <summary>The protection this store reports.</summary>
    public SecretStoreProtection Protection { get; }

    /// <summary>The node's view of this store (a new instance each time, over the same entries).</summary>
    public NodeSecretStore Selection => new(this, Backend, Protection, fallbackReason: null, isolated: true);

    public SecretStoreIsolation Isolation => SecretStoreIsolation.SameUserShared;

    public int Writes { get; private set; }

    public int Reads { get; private set; }

    public int Deletes { get; private set; }

    /// <summary>Every call fails with <see cref="IOException"/> while set (backend unavailable).</summary>
    public bool Unavailable
    {
        get
        {
            lock (_gate) return _unavailable;
        }

        set
        {
            lock (_gate) _unavailable = value;
        }
    }

    /// <summary>The next <paramref name="count"/> writes fail with <see cref="IOException"/>.</summary>
    public void FailWrites(int count)
    {
        lock (_gate) _failWrites = count;
    }

    /// <summary>The next <paramref name="count"/> writes report success but store nothing (lost write).</summary>
    public void LoseWrites(int count)
    {
        lock (_gate) _loseWrites = count;
    }

    /// <summary>The next <paramref name="count"/> deletes report success but the value stays readable (stale read after delete, L-26).</summary>
    public void LoseDeletes(int count)
    {
        lock (_gate) _loseDeletes = count;
    }

    public void Write(string opaqueTarget, ReadOnlySpan<byte> secret)
    {
        NodeSecretStores.ValidateTarget(opaqueTarget);
        lock (_gate)
        {
            Writes++;
            ThrowIfUnavailable();
            if (_failWrites > 0)
            {
                _failWrites--;
                throw new IOException("Scripted fault: the isolated secret store failed the write.");
            }

            if (secret.IsEmpty || secret.Length > TestDataRootSecretStore.MaximumSecretBytes)
            {
                throw new ArgumentOutOfRangeException(nameof(secret), "Secret values must be non-empty and within the OS credential-store bound.");
            }

            if (_loseWrites > 0)
            {
                _loseWrites--;
                return;
            }

            if (_entries.Remove(opaqueTarget, out var previous))
            {
                CryptographicOperations.ZeroMemory(previous);
            }

            _entries[opaqueTarget] = secret.ToArray();
        }
    }

    public byte[]? Read(string opaqueTarget)
    {
        NodeSecretStores.ValidateTarget(opaqueTarget);
        lock (_gate)
        {
            Reads++;
            ThrowIfUnavailable();
            return _entries.TryGetValue(opaqueTarget, out var value) ? (byte[])value.Clone() : null;
        }
    }

    public bool Delete(string opaqueTarget)
    {
        NodeSecretStores.ValidateTarget(opaqueTarget);
        lock (_gate)
        {
            Deletes++;
            ThrowIfUnavailable();
            if (!_entries.ContainsKey(opaqueTarget))
            {
                return false;
            }

            if (_loseDeletes > 0)
            {
                _loseDeletes--;
                return true;
            }

            _entries.Remove(opaqueTarget, out var removed);
            CryptographicOperations.ZeroMemory(removed);
            return true;
        }
    }

    /// <summary>The names held now, in order (test verification).</summary>
    public IReadOnlyList<string> Names()
    {
        lock (_gate) return [.. _entries.Keys.Order(StringComparer.Ordinal)];
    }

    /// <summary>
    /// Test verification after a delete: reads each of <paramref name="names"/> back once (bypassing the scripted faults and the call
    /// counts) and returns those still present, by name.
    /// </summary>
    public List<string> Remaining(IEnumerable<string> names)
    {
        lock (_gate) return [.. names.Where(_entries.ContainsKey)];
    }

    /// <summary>
    /// The fixture's end: every name still held is a leak, reported by name (after the test's own deletes), except those in
    /// <paramref name="reported"/>, which the fixture already reported; the entries are then zeroed and dropped with the store.
    /// </summary>
    public List<string> TakeLeaks(IEnumerable<string>? reported = null)
    {
        lock (_gate)
        {
            var known = new HashSet<string>(reported ?? [], StringComparer.Ordinal);
            var leaks = _entries.Keys.Where(name => !known.Contains(name)).Order(StringComparer.Ordinal)
                .Select(name => "isolated secret store entry " + name).ToList();
            foreach (var value in _entries.Values)
            {
                CryptographicOperations.ZeroMemory(value);
            }

            _entries.Clear();
            return leaks;
        }
    }

    private void ThrowIfUnavailable()
    {
        if (_unavailable)
        {
            throw new IOException("Scripted fault: the isolated secret store is unavailable.");
        }
    }
}
