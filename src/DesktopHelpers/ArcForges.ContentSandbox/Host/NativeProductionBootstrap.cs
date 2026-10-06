// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using ArcForges.Native.Abstractions;

namespace ArcForges.ContentSandbox.Host;

/// <summary>Complete authenticated native bootstrap received only through the inherited parent-owned launch frame.</summary>
internal sealed class NativeProductionBootstrap : IDisposable
{
    private readonly List<NativeVerifiedRuntime> _runtimes = [];
    private LinuxNativeRuntimeLoadPlatform? _platformLifetime;
    private int _disposed;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000", Justification = "The returned bootstrap owns every runtime and directory lease; failure disposes that complete owner before rethrowing.")]
    internal static NativeProductionBootstrap Load(ReadOnlySpan<byte> bytes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var lifetime = new NativeProductionBootstrap();
        try
        {
            if (bytes.SequenceEqual("{\"fixture\":true}"u8))
            {
                // The Broker's friend-only fixture option is never exposed to product callers.
                // This branch retains explicit unsigned local component fixtures, not production evidence.
                NativeLoader.ConfigureLocalFixture();
                return lifetime;
            }

            if (bytes.Length is 0 or > 8192) { throw new InvalidDataException("The helper has no bounded authenticated native release bootstrap."); }
            using var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            Closed(root, ["directory", "keys", "libraries", "schemaVersion"]);
            if (root.GetProperty("schemaVersion").GetInt32() != 1) { throw new InvalidDataException("The native bootstrap schema is unsupported."); }
            var directory = Text(root, "directory", 1024);
            if (!Path.IsPathFullyQualified(directory) || Path.GetFullPath(directory) != directory) { throw new InvalidDataException("The native root is not the explicit canonical installation locator."); }
            var keyRows = root.GetProperty("keys");
            if (keyRows.ValueKind != JsonValueKind.Array || keyRows.GetArrayLength() is 0 or > 8) { throw new InvalidDataException("The native publisher inventory is outside its bound."); }
            var keys = new List<KeyValuePair<string, byte[]>>();
            foreach (var row in keyRows.EnumerateArray())
            {
                Closed(row, ["keyId", "spki"]);
                var encoded = Text(row, "spki", 700);
                var spki = Convert.FromBase64String(encoded);
                if (Convert.ToBase64String(spki) != encoded) { throw new InvalidDataException("The approved publisher key is not canonical."); }
                keys.Add(new(Text(row, "keyId", 128), spki));
            }

            var trust = new NativePublisherTrust(keys);
            var libraryRows = root.GetProperty("libraries");
            if (libraryRows.ValueKind != JsonValueKind.Array || libraryRows.GetArrayLength() != 2) { throw new InvalidDataException("The production helper requires the exact Image/Pdf cohort."); }
            var identities = new Dictionary<string, NativeRuntimeIdentity>(StringComparer.Ordinal);
            foreach (var row in libraryRows.EnumerateArray())
            {
                Closed(row, ["library", "manifestSha256", "packageVersion", "profileSha256", "rid", "sourceCommit"]);
                var identity = new NativeRuntimeIdentity(Text(row, "rid", 32), Text(row, "library", 32), Text(row, "packageVersion", 128),
                    Text(row, "sourceCommit", 40), Text(row, "profileSha256", 64), Text(row, "manifestSha256", 64));
                identity.Validate();
                if (!identities.TryAdd(identity.Library, identity)) { throw new InvalidDataException("The production helper repeats a native family."); }
            }

            var image = identities["ArcImageNative"];
            var pdf = identities["ArcPdfNative"];
            if (image.Rid != pdf.Rid || image.PackageVersion != pdf.PackageVersion || image.SourceCommit != pdf.SourceCommit)
            {
                throw new InvalidDataException("The helper cannot compose mixed native publication cohorts.");
            }

            INativeRuntimeLoadPlatform platform;
            if (OperatingSystem.IsWindows()) { platform = new WindowsNativeRuntimeLoadPlatform(); }
            else if (OperatingSystem.IsLinux())
            {
                var linux = new LinuxNativeRuntimeLoadPlatform(directory);
                lifetime._platformLifetime = linux;
                platform = linux;
            }
            else { throw new PlatformNotSupportedException("An authenticated macOS XPC runtime requires its packaged platform adapter."); }
            var runtimes = new Dictionary<string, NativeVerifiedRuntime>(StringComparer.Ordinal);
            foreach (var identity in identities.Values)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var manifest = Read(platform, directory, identity.Library + ".manifest.json", 1024 * 1024, cancellationToken);
                var envelope = Read(platform, directory, identity.Library + ".signature.json", 8192, cancellationToken);
                var profile = Read(platform, directory, identity.Library + ".profile.json", 1024 * 1024, cancellationToken);
                if (Convert.ToHexStringLower(SHA256.HashData(profile)) != identity.ProfileSha256) { throw new InvalidDataException("The native runtime policy differs from its signed immutable profile."); }
                using var policy = JsonDocument.Parse(profile, new JsonDocumentOptions { MaxDepth = 8 });
                var value = policy.RootElement;
                Closed(value, ["library", "producerProfileSha256", "rid", "schemaVersion", "systemImports", "systemPolicySha256"]);
                if (value.GetProperty("schemaVersion").GetInt32() != 1 || Text(value, "library", 32) != identity.Library || Text(value, "rid", 32) != identity.Rid)
                {
                    throw new InvalidDataException("The authenticated native runtime profile has a different identity.");
                }

                foreach (var field in new[] { "producerProfileSha256", "systemPolicySha256" })
                {
                    var hash = Text(value, field, 64);
                    if (hash.Length != 64 || hash.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))) { throw new InvalidDataException("The native runtime policy is not bound to its admitted producer/system profile."); }
                }

                var imports = value.GetProperty("systemImports");
                if (imports.ValueKind != JsonValueKind.Array || imports.GetArrayLength() > 256) { throw new InvalidDataException("The exact system import inventory exceeds its bound."); }
                var allowed = new HashSet<string>(image.Rid.StartsWith("win-", StringComparison.Ordinal) ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
                foreach (var import in imports.EnumerateArray())
                {
                    if (import.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(import.GetString()) || import.GetString()!.Length > 512
                        || import.GetString()!.Contains('*', StringComparison.Ordinal) || !allowed.Add(import.GetString()!)) { throw new InvalidDataException("The system import policy is not a closed exact identity inventory."); }
                }

                var runtime = NativeVerifiedRuntime.Open(directory, manifest, envelope, identity, trust, allowed, platform, cancellationToken);
                lifetime._runtimes.Add(runtime);
                runtimes.Add(identity.Library, runtime);
            }

            NativeLoader.ConfigureProduction(runtimes);
            return lifetime;
        }
        catch (Exception primary)
        {
            try { lifetime.Dispose(); }
            catch (AggregateException cleanup) { throw new AggregateException("Native bootstrap admission and cleanup failed.", primary, cleanup); }
            throw;
        }
    }

    private static byte[] Read(INativeRuntimeLoadPlatform platform, string directory, string name, int maximum, CancellationToken cancellationToken)
    {
        using var file = platform.Open(directory, name, cancellationToken);
        if (file.Bytes.Length is 0 || file.Bytes.Length > maximum) { throw new InvalidDataException("The native release sidecar exceeds its bound."); }
        var bytes = new byte[checked((int)file.Bytes.Length)];
        file.Bytes.Position = 0;
        file.Bytes.ReadExactly(bytes);
        cancellationToken.ThrowIfCancellationRequested();
        return bytes;
    }

    private static string Text(JsonElement root, string field, int maximum)
    {
        var value = root.GetProperty(field);
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(value.GetString()) || value.GetString()!.Length > maximum) { throw new InvalidDataException("Invalid native bootstrap field: " + field); }
        return value.GetString()!;
    }

    private static void Closed(JsonElement root, string[] fields)
    {
        if (root.ValueKind != JsonValueKind.Object) { throw new InvalidDataException("The native bootstrap contract must be an object."); }
        var actual = root.EnumerateObject().Select(p => p.Name).ToArray();
        if (actual.Length != fields.Length || actual.Distinct(StringComparer.Ordinal).Count() != actual.Length || !actual.Order(StringComparer.Ordinal).SequenceEqual(fields.Order(StringComparer.Ordinal)))
        {
            throw new InvalidDataException("The native bootstrap contract has missing, duplicate or unknown fields.");
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031", Justification = "Attempt every native runtime and pinned directory release even if an earlier cleanup fails.")]
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) { return; }
        var errors = new List<Exception>();
        for (var index = _runtimes.Count - 1; index >= 0; index--)
        {
            try { _runtimes[index].Dispose(); } catch (Exception error) { errors.Add(error); }
        }

        try { if (OperatingSystem.IsLinux()) { _platformLifetime?.Dispose(); } } catch (Exception error) { errors.Add(error); }
        if (errors.Count != 0) { throw new AggregateException("Native production bootstrap cleanup failed.", errors); }
    }
}
