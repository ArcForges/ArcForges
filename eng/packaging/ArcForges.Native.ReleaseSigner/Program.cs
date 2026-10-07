// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ArcForges.Native.Abstractions;

namespace ArcForges.Native.ReleaseSigner;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
        Console.CancelKeyPress += cancel;
        try
        {
            await ReleaseCommand.RunAsync(args, cancellation.Token).ConfigureAwait(false);
            return 0;
        }
        catch (OperationCanceledException)
        {
            await Console.Error.WriteLineAsync("Native publisher operation cancelled.").ConfigureAwait(false);
            return 130;
        }
        catch (Exception e) when (e is ArgumentException or IOException or UnauthorizedAccessException
                                  or CryptographicException or InvalidOperationException or NotSupportedException or TimeoutException)
        {
            // A private-key reference, password or provider diagnostic is never printed.
            await Console.Error.WriteLineAsync("Native publisher operation refused.").ConfigureAwait(false);
            return 1;
        }
        finally { Console.CancelKeyPress -= cancel; }
    }
}

internal static class ReleaseCommand
{
    private static readonly string[] Common = ["manifest", "profile", "approved-spki", "key-id", "rid", "library", "version", "source"];

    internal static async Task RunAsync(string[] args, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(args);
        cancellationToken.ThrowIfCancellationRequested();
        if (args.Length > 0 && args[0] is "sign-helper" or "verify-helper")
        {
            await WindowsHelperSigner.RunAsync(args, cancellationToken).ConfigureAwait(false);
            return;
        }
        if (args.Length is < 17 or > 25 || args[0] is not ("sign" or "verify") || args.Length % 2 != 1)
        {
            throw new ArgumentException("Invalid closed native publisher arguments.");
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            var name = args[index];
            var value = args[index + 1];
            if (!name.StartsWith("--", StringComparison.Ordinal) || value.Length is 0 or > 4096
                || value.Contains('\0', StringComparison.Ordinal) || !values.TryAdd(name[2..], value))
            {
                throw new ArgumentException("Invalid or duplicate native publisher argument.");
            }
        }

        foreach (var name in Common) { if (!values.ContainsKey(name)) { throw new ArgumentException("Missing native publisher argument."); } }
        var allowed = Common.Concat(args[0] == "verify" ? ["signature"] : ["output", "pem", "certificate-thumbprint", "store-location"])
            .ToHashSet(StringComparer.Ordinal);
        if (values.Keys.Any(name => !allowed.Contains(name))) { throw new ArgumentException("Unknown native publisher argument."); }
        if (args[0] == "verify" && !values.ContainsKey("signature")) { throw new ArgumentException("Missing signature."); }
        if (args[0] == "sign" && (!values.ContainsKey("output")
            || values.ContainsKey("pem") == values.ContainsKey("certificate-thumbprint")
            || values.ContainsKey("store-location") != values.ContainsKey("certificate-thumbprint")))
        {
            throw new ArgumentException("Exactly one actual key provider is required.");
        }

        var manifest = await ReadBoundedAsync(values["manifest"], 1024 * 1024, cancellationToken).ConfigureAwait(false);
        var profile = await ReadBoundedAsync(values["profile"], 1024 * 1024, cancellationToken).ConfigureAwait(false);
        var approved = await ReadBoundedAsync(values["approved-spki"], 4096, cancellationToken).ConfigureAwait(false);
        var identity = new NativeRuntimeIdentity(values["rid"], values["library"], values["version"], values["source"],
            Convert.ToHexStringLower(SHA256.HashData(profile)), Convert.ToHexStringLower(SHA256.HashData(manifest)));
        identity.Validate();
        var trust = new NativePublisherTrust([new(values["key-id"], approved)]);
        if (args[0] == "verify")
        {
            var signature = await ReadBoundedAsync(values["signature"], 8192, cancellationToken).ConfigureAwait(false);
            trust.Verify(signature, manifest, identity, cancellationToken);
            return;
        }

        using var key = values.TryGetValue("pem", out var pem)
            ? await ReadPemAsync(pem, cancellationToken).ConfigureAwait(false)
            : ReadCertificate(values["certificate-thumbprint"], values["store-location"]);
        var actual = key.ExportSubjectPublicKeyInfo();
        if (!CryptographicOperations.FixedTimeEquals(actual, approved))
        {
            throw new CryptographicException("The signing key is not the independently approved publisher key.");
        }

        var envelope = new NativePublisherSigner(key, values["key-id"]).Sign(identity, manifest, cancellationToken);
        trust.Verify(envelope, manifest, identity, cancellationToken);
        await WriteNewAsync(values["output"], envelope, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<byte[]> ReadBoundedAsync(string path, int maximum, CancellationToken cancellationToken)
    {
        path = CanonicalFilePath(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length is 0 || stream.Length > maximum) { throw new InvalidDataException("Missing or unbounded native publisher input."); }
        var bytes = new byte[checked((int)stream.Length)];
        try
        {
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            var extra = new byte[1];
            if (await stream.ReadAsync(extra, cancellationToken).ConfigureAwait(false) != 0 || stream.Length != bytes.Length)
            {
                throw new InvalidDataException("Native publisher input changed during read.");
            }

            return bytes;
        }
        catch { CryptographicOperations.ZeroMemory(bytes); throw; }
    }

    private static async Task<ECDsa> ReadPemAsync(string path, CancellationToken cancellationToken)
    {
        var bytes = await ReadBoundedAsync(path, 65536, cancellationToken).ConfigureAwait(false);
        char[]? characters = null;
        ECDsa? key = null;
        try
        {
            characters = new UTF8Encoding(false, true).GetChars(bytes);
            key = ECDsa.Create();
            key.ImportFromPem(characters);
            var challenge = RandomNumberGenerator.GetBytes(32);
            _ = key.SignData(challenge, HashAlgorithmName.SHA256);
            cancellationToken.ThrowIfCancellationRequested();
            var result = key;
            key = null;
            return result;
        }
        finally
        {
            key?.Dispose();
            CryptographicOperations.ZeroMemory(bytes);
            if (characters is not null) { Array.Clear(characters); }
        }
    }

    private static ECDsa ReadCertificate(string thumbprint, string location)
    {
        if (thumbprint.Length != 40 || thumbprint.Any(c => !char.IsAsciiHexDigit(c))
            || location is not ("CurrentUser" or "LocalMachine"))
        {
            throw new ArgumentException("Invalid actual certificate-store reference.");
        }

        using var store = new X509Store(StoreName.My, location == "CurrentUser" ? StoreLocation.CurrentUser : StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        try
        {
            if (matches.Count != 1) { throw new CryptographicException("Missing or ambiguous certificate."); }
            var certificate = matches[0];
            var now = DateTime.UtcNow;
            if (!certificate.HasPrivateKey || now < certificate.NotBefore.ToUniversalTime() || now > certificate.NotAfter.ToUniversalTime()
                || certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(extension => extension.CertificateAuthority)
                || !certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(extension =>
                    extension.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.3")))
            {
                throw new CryptographicException("Certificate is not a current code-signing leaf.");
            }

            return certificate.GetECDsaPrivateKey() ?? throw new CryptographicException("Certificate lacks an actual ECDSA private provider.");
        }
        finally { foreach (var certificate in matches) { certificate.Dispose(); } }
    }

    internal static async Task WriteNewAsync(string path, byte[] bytes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length is 0 or > 8192) { throw new InvalidDataException("Unbounded native publisher output."); }
        path = CanonicalFilePath(path);
        if (File.Exists(path)) { throw new IOException("Preserve the existing signed candidate."); }
        var temporary = path + ".writing-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                FlushOwnedFile(stream);
            }

            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporary, path, overwrite: false);
        }
        finally { if (File.Exists(temporary)) { File.Delete(temporary); } }
    }

    internal static string CanonicalFilePath(string path)
    {
        path = Path.GetFullPath(path);
        for (FileSystemInfo? item = new FileInfo(path); item is not null; item = item is FileInfo file ? file.Directory : ((DirectoryInfo)item).Parent)
        {
            if (item.LinkTarget is not null || item.Exists && (item.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Linked native publisher input/output path.");
            }
        }

        return path;
    }

    // FlushAsync alone does not request stable file bytes; this explicit sync
    // durability boundary has no equivalent asynchronous flush-to-disk API.
    private static void FlushOwnedFile(FileStream stream) => stream.Flush(flushToDisk: true);
}
