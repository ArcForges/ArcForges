// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.Native.Abstractions;

namespace ArcForges.ContentSandbox.Broker;

/// <summary>An immutable native artifact selected by the product's authenticated installation inventory.</summary>
public sealed record ContentSandboxNativeRelease(string Library, string ProfileSha256, string ManifestSha256);

/// <summary>Approved release publisher keys and the exact installed Image/Pdf cohort, copied before the first launch.</summary>
public sealed class ContentSandboxReleaseTrust
{
    private readonly byte[] _bootstrap;

    /// <summary>Builds the trusted launch inventory from application-owned release pins; downloaded files cannot supply their own approval keys.</summary>
    public ContentSandboxReleaseTrust(string nativeDirectory, string rid, string packageVersion, string sourceCommit,
        IReadOnlyDictionary<string, ReadOnlyMemory<byte>> approvedPublisherKeys, IReadOnlyCollection<ContentSandboxNativeRelease> libraries)
    {
        ArgumentNullException.ThrowIfNull(approvedPublisherKeys);
        ArgumentNullException.ThrowIfNull(libraries);
        if (!Path.IsPathFullyQualified(nativeDirectory) || Path.GetFullPath(nativeDirectory) != nativeDirectory)
        {
            throw new ArgumentException("The native release directory must be an explicit canonical installation locator.", nameof(nativeDirectory));
        }

        var keys = approvedPublisherKeys.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => new KeyValuePair<string, byte[]>(p.Key, p.Value.ToArray())).ToArray();
        _ = new NativePublisherTrust(keys);
        if (libraries.Count != 2 || libraries.Any(p => p is null) || libraries.Select(p => p.Library).Distinct(StringComparer.Ordinal).Count() != 2)
        {
            throw new ArgumentException("The release must name exactly one Image and one Pdf native artifact.", nameof(libraries));
        }

        var identities = libraries.OrderBy(p => p.Library, StringComparer.Ordinal).Select(p => new NativeRuntimeIdentity(rid, p.Library, packageVersion,
            sourceCommit, p.ProfileSha256, p.ManifestSha256)).ToArray();
        foreach (var identity in identities) { identity.Validate(); }
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("directory", nativeDirectory);
            writer.WriteStartArray("keys");
            foreach (var pair in keys)
            {
                writer.WriteStartObject(); writer.WriteString("keyId", pair.Key); writer.WriteString("spki", Convert.ToBase64String(pair.Value)); writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteStartArray("libraries");
            foreach (var identity in identities)
            {
                writer.WriteStartObject();
                writer.WriteString("library", identity.Library);
                writer.WriteString("manifestSha256", identity.ManifestSha256);
                writer.WriteString("packageVersion", identity.PackageVersion);
                writer.WriteString("profileSha256", identity.ProfileSha256);
                writer.WriteString("rid", identity.Rid);
                writer.WriteString("sourceCommit", identity.SourceCommit);
                writer.WriteEndObject();
            }

            writer.WriteEndArray(); writer.WriteNumber("schemaVersion", 1); writer.WriteEndObject();
        }

        _bootstrap = stream.ToArray();
        if (_bootstrap.Length > ContentSandboxLaunchFrame.MaxNativeBootstrapBytes)
        {
            throw new ArgumentException("The complete native release trust exceeds its launch bound.", nameof(approvedPublisherKeys));
        }
    }

    internal byte[] Encode() => _bootstrap.ToArray();
}
