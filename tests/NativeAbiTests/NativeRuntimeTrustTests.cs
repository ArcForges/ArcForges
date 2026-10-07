// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Native.Abstractions;
using Xunit;

namespace ArcForges.Tests.NativeAbiTests;

/// <summary>Real ES256 verification. Generated keys are component fixtures, never production release signing evidence.</summary>
public sealed class NativeRuntimeTrustTests
{
    private static readonly byte[] Manifest = Encoding.UTF8.GetBytes("{\"schemaVersion\":1}");
    private static void Verify(NativePublisherTrust trust, byte[] envelope, byte[] manifest, NativeRuntimeIdentity identity) =>
        trust.Verify(envelope, manifest, identity, TestContext.Current.CancellationToken);

    private static NativeRuntimeIdentity Identity(string rid = "win-x64") => new(rid, "ArcPdfNative", "1.0.0-ci.108.1",
        new string('a', 40), new string('b', 64), Convert.ToHexStringLower(SHA256.HashData(Manifest)));

    private static byte[] Envelope(ECDsa signer, NativeRuntimeIdentity identity, string keyId = "release-1", byte[]? overridePayload = null)
    {
        var payload = overridePayload ?? NativePublisherTrust.EncodePayload(identity, keyId);
        var signature = signer.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("algorithm", "ES256");
            writer.WriteString("payload", Convert.ToBase64String(payload));
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("signature", Convert.ToBase64String(signature));
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    [Theory]
    [InlineData("win-x64")]
    [InlineData("win-arm64")]
    [InlineData("linux-x64")]
    [InlineData("linux-arm64")]
    [InlineData("osx-x64")]
    [InlineData("osx-arm64")]
    public void ActualSignaturesBindEveryClosedRidAndCopiedApprovedKey(string rid)
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var approved = signer.ExportSubjectPublicKeyInfo();
        var trust = new NativePublisherTrust([new("release-1", approved)]);
        var identity = Identity(rid);
        var envelope = Envelope(signer, identity);
        Array.Fill(approved, (byte)0); // The policy owns an immutable copy of the actual approved key.
        Parallel.For(0, 16, _ => Verify(trust, envelope, Manifest, identity));
    }

    [Fact]
    public void WrongKeySignatureOrManifestCannotAuthenticate()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var foreign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trust = new NativePublisherTrust([new("release-1", signer.ExportSubjectPublicKeyInfo())]);
        var identity = Identity();
        Assert.Throws<CryptographicException>(() => Verify(trust, Envelope(foreign, identity), Manifest, identity));
        Assert.Throws<InvalidDataException>(() => Verify(trust, Envelope(signer, identity, "foreign"), Manifest, identity));
        var envelope = Envelope(signer, identity);
        var changed = Manifest.ToArray();
        changed[^1] ^= 1;
        Assert.Throws<InvalidDataException>(() => Verify(trust, envelope, changed, identity));
        Assert.Throws<InvalidDataException>(() => Verify(trust, envelope, Manifest, identity with { SourceCommit = new string('c', 40) }));
        Assert.Throws<InvalidDataException>(() => Verify(trust, envelope, Manifest, identity with { Rid = "win-arm64" }));
        Assert.Throws<InvalidDataException>(() => Verify(trust, envelope, Manifest, identity with { ProfileSha256 = new string('c', 64) }));
        Assert.Throws<InvalidDataException>(() => Verify(trust, envelope, Manifest, identity with { PackageVersion = "1.0.0-ci.107.1" }));
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("1.0")]
    [InlineData("01.0.0")]
    [InlineData("1.0.0-")]
    [InlineData("1.0.0-ci..1")]
    [InlineData("1.0.0-ci.01")]
    [InlineData("1.0.0+metadata")]
    public void NoncanonicalReleaseVersionsCannotAcquirePublisherAuthorization(string version)
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var identity = Identity() with { PackageVersion = version };
        Assert.Throws<InvalidDataException>(() => new NativePublisherSigner(signer, "release-1").Sign(identity, Manifest, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void EvenValidSignaturesCannotAdmitUnknownOrDuplicateFieldsOrNoncanonicalPayloads()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trust = new NativePublisherTrust([new("release-1", signer.ExportSubjectPublicKeyInfo())]);
        var identity = Identity();
        var canonical = Encoding.UTF8.GetString(NativePublisherTrust.EncodePayload(identity, "release-1"));
        foreach (var changed in new[] { canonical[..^1] + ",\"unknown\":1}", canonical.Replace("\"keyId\":", "\"keyId\":\"release-1\",\"keyId\":", StringComparison.Ordinal), " " + canonical })
        {
            Assert.Throws<InvalidDataException>(() => Verify(trust, Envelope(signer, identity, overridePayload: Encoding.UTF8.GetBytes(changed)), Manifest, identity));
        }

        var envelope = Encoding.UTF8.GetString(Envelope(signer, identity));
        Assert.Throws<InvalidDataException>(() => Verify(trust, Encoding.UTF8.GetBytes(envelope[..^1] + ",\"unknown\":1}"), Manifest, identity));
    }

    [Fact]
    public void KeyCurveBoundsAndCancellationAreEnforcedBeforeTrust()
    {
        Assert.Throws<InvalidDataException>(() => new NativePublisherTrust([]));
        using var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<InvalidDataException>(() => new NativePublisherTrust([new("release-1", wrongCurve.ExportSubjectPublicKeyInfo())]));
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = signer.ExportSubjectPublicKeyInfo();
        Assert.Throws<InvalidDataException>(() => new NativePublisherTrust([new("release-1", spki), new("release-1", spki)]));
        var trust = new NativePublisherTrust([new("release-1", spki)]);
        var token = new CancellationToken(canceled: true);
        Assert.Equal(token, Assert.Throws<OperationCanceledException>(() => trust.Verify([], [], Identity(), token)).CancellationToken);
        Assert.Throws<InvalidDataException>(() => Verify(trust, new byte[8193], Manifest, Identity()));
        Assert.Throws<InvalidDataException>(() => Verify(trust, Envelope(signer, Identity()), new byte[1024 * 1024 + 1], Identity()));
        Assert.Throws<InvalidDataException>(() => Verify(trust, [], Manifest, Identity("freebsd-x64")));
    }
    private static readonly string[] OpenOrder = ["open:pdfium.dll", "open:ArcPdfNative.dll", "load:pdfium.dll", "load:ArcPdfNative.dll"];
    private static readonly string[] CloseOrder = ["free:2", "free:1", "close:ArcPdfNative.dll", "close:pdfium.dll"];
    private static readonly string[] PdfExports = ["arc_pdf_close", "arc_pdf_get_abi_version", "arc_pdf_get_build_info", "arc_pdf_get_last_error", "arc_pdf_open", "arc_pdf_page_info", "arc_pdf_render", "arc_pdf_text"];

    private static (byte[] Manifest, NativeRuntimeIdentity Identity) Closure(bool badHash = false, string? import = null, string? ownedName = null, string machine = "x64")
    {
        var bytes = Encoding.UTF8.GetBytes("actual component fixture bytes; native execution is unavailable in this adapter test");
        var digest = Convert.ToHexStringLower(SHA256.HashData(bytes));
        var manifest = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            sourceCommit = new string('a', 40),
            rid = "win-x64",
            library = "ArcPdfNative",
            abi = new { major = 1, minor = 1 },
            files = new[]
            {
                new { name = "pdfium.dll", sha256 = badHash ? new string('f', 64) : digest, machine, imports = Array.Empty<string>(), exports = Array.Empty<string>() },
                new { name = ownedName ?? "ArcPdfNative.dll", sha256 = digest, machine, imports = new[] { import ?? "pdfium.dll" }, exports = PdfExports },
            },
        });
        return (manifest, new NativeRuntimeIdentity("win-x64", "ArcPdfNative", "1.0.0-ci.108.1", new string('a', 40), new string('b', 64), Convert.ToHexStringLower(SHA256.HashData(manifest))));
    }

    [Fact]
    public async Task CompleteClosureIsAuthenticatedAndPinnedBeforeLoadingThenReleasedOnceInReverseOrder()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new NativePublisherSigner(key, "release-1");
        var trust = new NativePublisherTrust([new("release-1", key.ExportSubjectPublicKeyInfo())]);
        var closure = Closure();
        var envelope = signer.Sign(closure.Identity, closure.Manifest, TestContext.Current.CancellationToken);
        var adapter = new UnavailableNativeExecution();
        using var runtime = NativeVerifiedRuntime.Open(Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar), closure.Manifest, envelope,
            closure.Identity, trust, new HashSet<string>(StringComparer.Ordinal), adapter, TestContext.Current.CancellationToken);
        Assert.Equal(OpenOrder, adapter.Events);
        Assert.Equal((nint)2, runtime.Handle);
        await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(runtime.Dispose, TestContext.Current.CancellationToken)));
        Assert.Equal(CloseOrder, adapter.Events.Skip(4));
        Assert.Throws<ObjectDisposedException>(() => runtime.Handle);
    }

    [Theory]
    [InlineData("hash")]
    [InlineData("foreign-import")]
    [InlineData("path")]
    [InlineData("machine")]
    [InlineData("rid")]
    public void AdmissionErrorsExecuteNoNativeBytesAndReleaseEveryOpenedLease(string error)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trust = new NativePublisherTrust([new("release-1", key.ExportSubjectPublicKeyInfo())]);
        var closure = Closure(error == "hash", error == "foreign-import" ? "not-approved.dll" : null,
            error == "path" ? "../ArcPdfNative.dll" : null, error == "machine" ? "arm64" : "x64");
        var adapter = new UnavailableNativeExecution { Rid = error == "rid" ? "win-arm64" : "win-x64" };
        var envelope = new NativePublisherSigner(key, "release-1").Sign(closure.Identity, closure.Manifest, TestContext.Current.CancellationToken);
        _ = Assert.ThrowsAny<Exception>(() => NativeVerifiedRuntime.Open(Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar), closure.Manifest, envelope,
            closure.Identity, trust, new HashSet<string>(StringComparer.Ordinal), adapter, TestContext.Current.CancellationToken));
        Assert.DoesNotContain(adapter.Events, e => e.StartsWith("load:", StringComparison.Ordinal));
        Assert.Equal(adapter.Events.Count(e => e.StartsWith("open:", StringComparison.Ordinal)), adapter.Events.Count(e => e.StartsWith("close:", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("load")]
    [InlineData("export")]
    [InlineData("free")]
    [InlineData("cancel")]
    public void PartialLoadMissingExportCancellationAndCleanupFailuresRetainTruthfulOutcomes(string failure)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var closure = Closure();
        var envelope = new NativePublisherSigner(key, "release-1").Sign(closure.Identity, closure.Manifest, TestContext.Current.CancellationToken);
        var trust = new NativePublisherTrust([new("release-1", key.ExportSubjectPublicKeyInfo())]);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var adapter = new UnavailableNativeExecution { Failure = failure, Cancel = failure == "cancel" ? cancellation.Cancel : null };
        var error = Assert.ThrowsAny<Exception>(() => NativeVerifiedRuntime.Open(Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar), closure.Manifest, envelope,
            closure.Identity, trust, new HashSet<string>(StringComparer.Ordinal), adapter, cancellation.Token));
        if (failure == "cancel") { Assert.Equal(cancellation.Token, Assert.IsType<OperationCanceledException>(error).CancellationToken); }
        if (failure == "free") { Assert.IsType<AggregateException>(error); }
        Assert.Equal(2, adapter.Events.Count(e => e.StartsWith("close:", StringComparison.Ordinal)));
        Assert.Equal(failure == "load" ? 1 : 2, adapter.Events.Count(e => e.StartsWith("free:", StringComparison.Ordinal)));
    }

    /// <summary>Only native module execution is unavailable. Actual signatures, manifests, byte hashing and lifecycle run in production code.</summary>
    private sealed class UnavailableNativeExecution : INativeRuntimeLoadPlatform
    {
        private int _next;
        public string Rid { get; init; } = "win-x64";
        internal string? Failure { get; init; }
        internal Action? Cancel { get; init; }
        internal List<string> Events { get; } = [];

        public INativeRuntimeFileLease Open(string directory, string name, CancellationToken cancellationToken)
        {
            Events.Add("open:" + name);
            return new FixtureLease(name, Events);
        }

        public nint Load(string loaderPath)
        {
            Events.Add("load:" + loaderPath);
            if (Failure == "load" && _next == 1) { throw new DllNotFoundException("Unavailable second module."); }
            var result = ++_next;
            if (result == 2) { Cancel?.Invoke(); }
            return result;
        }

        public bool HasExport(nint handle, string name) => Failure is not ("export" or "free");
        public void Free(nint handle)
        {
            Events.Add("free:" + handle);
            if (Failure == "free") { throw new IOException("Injected native cleanup failure."); }
        }

        private sealed class FixtureLease(string name, List<string> events) : INativeRuntimeFileLease
        {
            private readonly MemoryStream _bytes = new(Encoding.UTF8.GetBytes("actual component fixture bytes; native execution is unavailable in this adapter test"));
            public Stream Bytes => _bytes;
            public string LoaderPath => name;
            public void Dispose() { events.Add("close:" + name); _bytes.Dispose(); }
        }
    }

}
