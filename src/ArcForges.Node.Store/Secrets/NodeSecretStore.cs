// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Security.Secrets;

namespace ArcForges.Node.Store;

/// <summary>
/// The secret store the node keeps its node data key in: a backing store with the backend and protection it reports (recorded
/// per key in the store and logged). Production builds it from DesktopPlatform's selection (<see cref="NodeSecretStores.ForNode"/>);
/// a node started with <c>--test-mode</c>, and every test, gets an isolated backend with the same reported labels instead
/// (16-testing-strategy section 2; 02-node-service section 4).
/// </summary>
internal sealed class NodeSecretStore
{
    /// <summary>Creates the store from its parts.</summary>
    /// <param name="store">The backing store.</param>
    /// <param name="backend">The backend it reports.</param>
    /// <param name="protection">How it reports protecting values at rest.</param>
    /// <param name="fallbackReason">Why the OS secret store was not selected, or <see langword="null"/>.</param>
    /// <param name="isolated">Whether it is an isolated test backend (never an OS-wide store).</param>
    public NodeSecretStore(ISecretBackingStore store, SecretStoreBackend backend, SecretStoreProtection protection, string? fallbackReason = null,
        bool isolated = false)
    {
        Store = store ?? throw new ArgumentNullException(nameof(store));
        Backend = backend;
        Protection = protection;
        FallbackReason = fallbackReason;
        Isolated = isolated;
    }

    /// <summary>The backing store.</summary>
    public ISecretBackingStore Store { get; }

    /// <summary>The backend new keys are recorded with.</summary>
    public SecretStoreBackend Backend { get; }

    /// <summary>How the backend protects the key at rest.</summary>
    public SecretStoreProtection Protection { get; }

    /// <summary>Why the OS secret store was not selected, or <see langword="null"/>.</summary>
    public string? FallbackReason { get; }

    /// <summary>Whether this is an isolated test backend: the node then uses no OS-wide secret store.</summary>
    public bool Isolated { get; }

    /// <summary>The store DesktopPlatform's selection chose, with its reported backend and protection.</summary>
    public static NodeSecretStore FromSelection(SecretStoreSelection selection)
    {
        ArgumentNullException.ThrowIfNull(selection);
        return new NodeSecretStore(selection.Store, selection.Backend, selection.Protection, selection.FallbackReason);
    }
}

/// <summary>
/// The file-backed isolated secret store of a node started with <c>--test-mode</c> (02-node-service section 4; 16-testing-strategy
/// section 2): one file per secret under <c>&lt;data root&gt;/run/test-secrets/</c>, so the keys of a test node survive its restart and
/// are removed with its data root. It is not an OS-wide store: the user's Credential Manager or Secret Service is never contacted. On
/// Linux each file is 0600 in a 0700 directory; on Windows the files inherit the data root's access list (the user's temporary
/// directory in tests). Each write replaces the file atomically by rename. Targets are the canonical
/// <c>ArcForges.Secrets.v1.</c> names the OS adapters accept, so a value valid here is valid there.
/// </summary>
internal sealed class TestDataRootSecretStore : ISecretBackingStore
{
    /// <summary>The directory under <c>run/</c> that holds the secrets.</summary>
    public const string DirectoryName = "test-secrets";

    /// <summary>The value bound of the OS adapters (Windows Credential Manager blobs).</summary>
    public const int MaximumSecretBytes = 2560;

    private const string TemporarySuffix = ".tmp";
    private static readonly Lock Gate = new();

    /// <summary>Creates the store for an absolute data root (nothing is created until the first write).</summary>
    public TestDataRootSecretStore(string dataRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        if (!Path.IsPathFullyQualified(dataRoot))
        {
            throw new ArgumentException("The node data root must be an absolute path.", nameof(dataRoot));
        }

        Directory = Path.Combine(Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataRoot)), "run", DirectoryName);
    }

    /// <summary>The directory of the secret files.</summary>
    public string Directory { get; }

    /// <summary>Every process of the user can read the files, as with Credential Manager.</summary>
    public SecretStoreIsolation Isolation => SecretStoreIsolation.SameUserShared;

    /// <inheritdoc />
    public void Write(string opaqueTarget, ReadOnlySpan<byte> secret)
    {
        NodeSecretStores.ValidateTarget(opaqueTarget);
        if (secret.IsEmpty || secret.Length > MaximumSecretBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(secret), "Secret values must be non-empty and within the OS credential-store bound.");
        }

        lock (Gate)
        {
            StorePaths.CreatePrivateDirectory(Directory);
            var target = Path.Combine(Directory, opaqueTarget);
            var temporary = Path.Combine(Directory, "." + opaqueTarget + "." + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8)) + TemporarySuffix);
            var renamed = false;
            try
            {
                var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, BufferSize = 0 };
                if (!OperatingSystem.IsWindows())
                {
                    options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                }

                using (var stream = new FileStream(temporary, options))
                {
                    stream.Write(secret);
                    stream.Flush(flushToDisk: true);
                }

                File.Move(temporary, target, overwrite: true);
                renamed = true;
            }
            finally
            {
                if (!renamed)
                {
                    TryDelete(temporary);
                }
            }
        }
    }

    /// <inheritdoc />
    public byte[]? Read(string opaqueTarget)
    {
        NodeSecretStores.ValidateTarget(opaqueTarget);
        lock (Gate)
        {
            try
            {
                return File.ReadAllBytes(Path.Combine(Directory, opaqueTarget));
            }
            catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
            {
                return null;
            }
        }
    }

    /// <inheritdoc />
    public bool Delete(string opaqueTarget)
    {
        NodeSecretStores.ValidateTarget(opaqueTarget);
        lock (Gate)
        {
            var path = Path.Combine(Directory, opaqueTarget);
            if (!File.Exists(path))
            {
                return false;
            }

            File.Delete(path);
            return true;
        }
    }

    /// <summary>The names of the secrets this store holds now (test verification of cleanup; never used to delete by pattern).</summary>
    public IReadOnlyList<string> Names()
    {
        lock (Gate)
        {
            return System.IO.Directory.Exists(Directory)
                ? [.. System.IO.Directory.EnumerateFiles(Directory).Select(Path.GetFileName).OfType<string>()
                    .Where(name => !name.StartsWith('.')).Order(StringComparer.Ordinal)]
                : [];
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
