// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ArcForges.Native.ReleaseSigner;

/// <summary>Real Windows SDK signing/verification. No missing credential or failed external operation becomes success.</summary>
internal static class WindowsHelperSigner
{
    // Actual installed SDK executable bytes and Microsoft signature were inspected
    // independently. This is an execution-tool pin, never helper publisher enrollment.
    internal const string ToolSha256 = "d6c04707c59a67fce9fa4bb5fe76c79445b60e1e326d8b500a2f2ba8707c590a";

    internal static async Task RunAsync(string[] args, CancellationToken cancellationToken)
    {
        if (args.Length < 5 || args.Length > 17 || args.Length % 2 != 1)
        {
            throw new ArgumentException("Invalid closed helper publisher arguments.");
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal) || args[index + 1].Length is 0 or > 4096
                || args[index + 1].Contains('\0', StringComparison.Ordinal)
                || !values.TryAdd(args[index][2..], args[index + 1]))
            {
                throw new ArgumentException("Invalid or duplicate helper publisher argument.");
            }
        }

        var required = args[0] == "verify-helper"
            ? new[] { "tool", "input", "certificate-thumbprint" }
            : new[] { "tool", "input", "input-sha256", "output", "certificate-thumbprint", "store-location", "timestamp" };
        if (values.Count != required.Length || required.Any(name => !values.ContainsKey(name)))
        {
            throw new ArgumentException("Missing or unknown helper publisher argument.");
        }

        if (args[0] == "verify-helper")
        {
            await VerifyAsync(values["tool"], values["input"], values["certificate-thumbprint"], cancellationToken).ConfigureAwait(false);
            return;
        }

        if (values["store-location"] is not ("CurrentUser" or "LocalMachine"))
        {
            throw new ArgumentException("Invalid certificate store authority.");
        }

        await SignAsync(values["tool"], values["input"], values["input-sha256"], values["output"],
            values["certificate-thumbprint"], values["store-location"] == "LocalMachine",
            new Uri(values["timestamp"], UriKind.Absolute), cancellationToken).ConfigureAwait(false);
    }

    internal static async Task VerifyAsync(string tool, string executable, string approvedSignerThumbprint, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Windows helper trust requires Windows."); }
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        operation.CancelAfter(TimeSpan.FromMinutes(2));
        try
        {
            using var toolLease = await OpenToolAsync(tool, operation.Token).ConfigureAwait(false);
            executable = ReleaseCommand.CanonicalFilePath(executable);
            using var inputLease = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (inputLease.Length is 0 or > 256 * 1024 * 1024) { throw new InvalidDataException("Unbounded actual helper executable."); }
            await InvokeAsync(tool, ["verify", "/pa", "/all", "/tw", executable], operation.Token).ConfigureAwait(false);
            await AuthenticodeIdentity.VerifySignerAsync(executable, approvedSignerThumbprint, requireRfc3161: true, operation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new TimeoutException("The helper trust verification exceeded its operation deadline.");
        }
    }

    internal static async Task SignAsync(string tool, string input, string expectedInputSha256, string output,
        string certificateThumbprint, bool machineStore, Uri timestamp, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Windows helper signing requires Windows."); }
        if (expectedInputSha256.Length != 64 || expectedInputSha256.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
            || certificateThumbprint.Length != 40 || certificateThumbprint.Any(c => !char.IsAsciiHexDigit(c))
            || !timestamp.IsAbsoluteUri || timestamp.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(timestamp.UserInfo)
            || !string.IsNullOrEmpty(timestamp.Fragment))
        {
            throw new ArgumentException("Invalid bounded helper signing authority.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        input = ReleaseCommand.CanonicalFilePath(input);
        output = ReleaseCommand.CanonicalFilePath(output);
        if (File.Exists(output)) { throw new IOException("Preserve the existing signed helper."); }
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        operation.CancelAfter(TimeSpan.FromMinutes(2));
        var temporary = output + ".signing-" + Guid.NewGuid().ToString("N") + ".exe";
        try
        {
            using var toolLease = await OpenToolAsync(tool, operation.Token).ConfigureAwait(false);
            var selectedCertificateSha256 = ValidateCertificate(certificateThumbprint, machineStore);
            RequireProtectedSigningDirectory(Path.GetDirectoryName(output)!, operation.Token);
            using var source = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous);
            if (source.Length is 0 or > 256 * 1024 * 1024) { throw new InvalidDataException("Unbounded actual helper executable."); }
            var sourceLength = source.Length;
            using (var destination = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.Asynchronous))
            using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                var buffer = new byte[65536];
                long copied = 0;
                while (true)
                {
                    var read = await source.ReadAsync(buffer, operation.Token).ConfigureAwait(false);
                    if (read == 0) { break; }
                    copied += read;
                    if (copied > sourceLength) { throw new InvalidDataException("The unsigned helper changed during copy."); }
                    hash.AppendData(buffer, 0, read);
                    await destination.WriteAsync(buffer.AsMemory(0, read), operation.Token).ConfigureAwait(false);
                }

                if (copied != sourceLength || Convert.ToHexStringLower(hash.GetHashAndReset()) != expectedInputSha256)
                {
                    throw new InvalidDataException("The unsigned helper differs from the approved actual producer.");
                }

                await destination.FlushAsync(operation.Token).ConfigureAwait(false);
                FlushOwnedFile(destination);
            }

            RequireProtectedFile(temporary);
            var arguments = new List<string> { "sign", "/fd", "SHA256", "/sha1", certificateThumbprint, "/s", "My" };
            if (machineStore) { arguments.Add("/sm"); }
            arguments.AddRange(["/tr", timestamp.AbsoluteUri, "/td", "SHA256", temporary]);
            await InvokeAsync(tool, arguments, operation.Token).ConfigureAwait(false);
            // Persist the tool's result before taking the final read-only lease.
            // The enforced protected directory/file authority forbids unprivileged
            // substitution during this handoff. Read-only access also permits the
            // real OS verifier to open its own read handle without write-sharing.
            using (var persisted = new FileStream(temporary, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                RequireProtectedFile(temporary);
                FlushOwnedFile(persisted);
            }
            using (var signedLease = new FileStream(temporary, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete,
                             65536, FileOptions.Asynchronous))
            {
                RequireProtectedFile(temporary);
                await RequireExactAuthenticodeTransformationAsync(source, signedLease, operation.Token).ConfigureAwait(false);
                await InvokeAsync(tool, ["verify", "/pa", "/all", "/tw", temporary], operation.Token).ConfigureAwait(false);
                await AuthenticodeIdentity.VerifySignerAsync(temporary, certificateThumbprint, requireRfc3161: true,
                    operation.Token, selectedCertificateSha256).ConfigureAwait(false);
                // No write-sharing is admitted. The protected parent forbids an
                // unprivileged rename; delete-sharing permits only this create-only
                // promotion while the verified original kernel bytes stay held.
                operation.Token.ThrowIfCancellationRequested();
                File.Move(temporary, output, overwrite: false);
            }
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new TimeoutException("The helper signing exceeded its operation deadline.");
        }
        finally { if (File.Exists(temporary)) { File.Delete(temporary); } }
    }

    [SupportedOSPlatform("windows")]
    internal static void RequireProtectedSigningDirectory(string directory, CancellationToken cancellationToken = default)
    {
        directory = ReleaseCommand.CanonicalFilePath(directory);
        if (!string.Equals(Path.GetPathRoot(directory), Path.GetPathRoot(Environment.SystemDirectory), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The signing installation must be on the actual OS boot drive.");
        }

        var parents = new List<DirectoryInfo>();
        for (var item = new DirectoryInfo(directory); item is not null; item = item.Parent)
        {
            if (parents.Count >= 64) { throw new InvalidDataException("The protected signing directory exceeds its depth bound."); }
            parents.Add(item);
        }
        foreach (var item in parents.AsEnumerable().Reverse())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!item.Exists || (item.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("Missing or substituted protected signing directory.");
            }

            RequireProtectedSecurity(item.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access),
                payload: string.Equals(item.FullName, directory, StringComparison.OrdinalIgnoreCase));
        }
    }

    [SupportedOSPlatform("windows")]
    private static void RequireProtectedFile(string path) => RequireProtectedSecurity(
        new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access), payload: true);

    private static readonly HashSet<string> TrustedOwners = ["S-1-5-18", "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];

    [SupportedOSPlatform("windows")]
    private static void RequireProtectedSecurity(FileSystemSecurity security, bool payload)
    {
        var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        if (descriptor.Owner is null || !TrustedOwners.Contains(descriptor.Owner.Value)
            || descriptor.DiscretionaryAcl is null || descriptor.DiscretionaryAcl.Count > 512)
        {
            throw new UnauthorizedAccessException("The actual signing installation lacks trusted OS ownership and a bounded DACL.");
        }

        const int ancestorMutation = 0x10000000 | 0x40000000 | 0x000D0040;
        var forbidden = ancestorMutation | (payload ? 0x116 : 0);
        foreach (GenericAce entry in descriptor.DiscretionaryAcl)
        {
            if (entry is not CommonAce ace || ace.AceQualifier is not (AceQualifier.AccessAllowed or AceQualifier.AccessDenied)
                || ace.IsCallback)
            {
                throw new UnauthorizedAccessException("Unsupported signing installation authority.");
            }

            if (ace.AceQualifier == AceQualifier.AccessAllowed && (ace.AceFlags & AceFlags.InheritOnly) == 0
                && (ace.AccessMask & forbidden) != 0 && !TrustedOwners.Contains(ace.SecurityIdentifier.Value))
            {
                throw new UnauthorizedAccessException("The signing installation grants unprivileged mutation authority.");
            }
        }
    }

    /// <summary>Only the SDK's checksum/security-directory update and appended certificate table can differ from compiled bytes.</summary>
    internal static async Task RequireExactAuthenticodeTransformationAsync(Stream original, Stream signed, CancellationToken cancellationToken)
    {
        if (!original.CanRead || !original.CanSeek || !signed.CanRead || !signed.CanSeek
            || original.Length is < 256 or > 256 * 1024 * 1024 || signed.Length > 264 * 1024 * 1024)
        {
            throw new InvalidDataException("Unbounded original or signed helper image.");
        }

        async Task<(long Checksum, long Security, uint CertificateOffset, uint CertificateSize)> HeaderAsync(Stream stream)
        {
            var header = new byte[64];
            stream.Position = 0;
            await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
            var pe = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(60));
            if (header[0] != 'M' || header[1] != 'Z' || pe > 1024 * 1024 || pe + 176L > stream.Length)
            {
                throw new InvalidDataException("Malformed bounded helper PE image.");
            }

            stream.Position = pe;
            var bytes = new byte[176];
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            if (!bytes.AsSpan(0, 4).SequenceEqual("PE\0\0"u8)
                || BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(24)) != 0x20b
                || BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(20)) < 152
                || BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(132)) < 5
                || (BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(22)) & 0x2002) != 2)
            {
                throw new InvalidDataException("The helper must be a real 64-bit executable PE image.");
            }

            return (pe + 88L, pe + 168L, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(168)),
                BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(172)));
        }

        var before = await HeaderAsync(original).ConfigureAwait(false);
        var after = await HeaderAsync(signed).ConfigureAwait(false);
        var certificateStart = (original.Length + 7) & ~7L;
        if (before.CertificateOffset != 0 || before.CertificateSize != 0 || before.Checksum != after.Checksum || before.Security != after.Security
            || after.CertificateOffset != certificateStart || after.CertificateSize is < 8 or > 8 * 1024 * 1024
            || certificateStart + after.CertificateSize != signed.Length)
        {
            throw new InvalidDataException("The signing transformation is not one exact appended Authenticode table.");
        }

        original.Position = 0;
        signed.Position = 0;
        var first = new byte[65536];
        var second = new byte[65536];
        long offset = 0;
        while (offset < original.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var length = (int)Math.Min(first.Length, original.Length - offset);
            await original.ReadExactlyAsync(first.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            await signed.ReadExactlyAsync(second.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            for (var index = 0; index < length; index++)
            {
                var position = offset + index;
                if (position >= before.Checksum && position < before.Checksum + 4 || position >= before.Security && position < before.Security + 8) { continue; }
                if (first[index] != second[index]) { throw new InvalidDataException("The signed helper body differs from its held compiler input."); }
            }

            offset += length;
        }

        var padding = new byte[(int)(certificateStart - original.Length)];
        await signed.ReadExactlyAsync(padding, cancellationToken).ConfigureAwait(false);
        if (padding.Any(value => value != 0)) { throw new InvalidDataException("Unexpected pre-certificate helper overlay."); }
        var certificateHeader = new byte[8];
        var remaining = (long)after.CertificateSize;
        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (remaining < 8) { throw new InvalidDataException("Truncated helper certificate table."); }
            await signed.ReadExactlyAsync(certificateHeader, cancellationToken).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadUInt32LittleEndian(certificateHeader);
            var aligned = (length + 7L) & ~7L;
            if (length < 8 || aligned > remaining || BinaryPrimitives.ReadUInt16LittleEndian(certificateHeader.AsSpan(4)) != 0x200
                || BinaryPrimitives.ReadUInt16LittleEndian(certificateHeader.AsSpan(6)) != 2)
            {
                throw new InvalidDataException("Invalid closed Authenticode certificate record.");
            }

            signed.Position += length - 8;
            var alignment = new byte[(int)(aligned - length)];
            await signed.ReadExactlyAsync(alignment, cancellationToken).ConfigureAwait(false);
            if (alignment.Any(value => value != 0)) { throw new InvalidDataException("Unexpected certificate record padding."); }
            remaining -= aligned;
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    [SupportedOSPlatform("windows")]
    private static async Task<FileStream> OpenToolAsync(string tool, CancellationToken cancellationToken)
    {
        tool = ReleaseCommand.CanonicalFilePath(tool);
        var installed = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Windows Kits", "10", "bin", "10.0.28000.0", "x64", "signtool.exe");
        if (!string.Equals(tool, installed, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Only the protected, reviewed SDK tool installation is admitted.");
        }
        RequireProtectedSigningDirectory(Path.GetDirectoryName(tool)!, cancellationToken);
        RequireProtectedFile(tool);
        var lease = new FileStream(tool, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous);
        try
        {
            if (lease.Length is 0 or > 16 * 1024 * 1024
                || Convert.ToHexStringLower(await SHA256.HashDataAsync(lease, cancellationToken).ConfigureAwait(false)) != ToolSha256)
            {
                throw new InvalidDataException("The execution tool differs from its reviewed actual SDK pin.");
            }

            return lease;
        }
        catch { await lease.DisposeAsync().ConfigureAwait(false); throw; }
    }

    private static async Task InvokeAsync(string tool, IEnumerable<string> arguments, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var start = new ProcessStartInfo(Path.GetFullPath(tool))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(tool))!,
        };
        foreach (var argument in arguments) { start.ArgumentList.Add(argument); }
        using var process = Process.Start(start) ?? throw new IOException("Cannot start the admitted signing tool.");
        try
        {
            await Task.WhenAll(process.WaitForExitAsync(deadline.Token),
                DrainAsync(process.StandardOutput, deadline), DrainAsync(process.StandardError, deadline)).ConfigureAwait(false);
            if (process.ExitCode != 0) { throw new CryptographicException("The real signing or trust-verification operation refused."); }
        }
        catch
        {
            if (!process.HasExited) { process.Kill(entireProcessTree: true); }
            await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private static async Task DrainAsync(StreamReader reader, CancellationTokenSource deadline)
    {
        var buffer = new char[1024];
        var total = 0;
        try
        {
            while (true)
            {
                var read = await reader.ReadAsync(buffer, deadline.Token).ConfigureAwait(false);
                if (read == 0) { return; }
                total += read;
                if (total > 8192) { throw new InvalidDataException("The signing tool exceeded its bounded diagnostic channel."); }
            }
        }
        catch { await deadline.CancelAsync().ConfigureAwait(false); throw; }
    }

    private static string ValidateCertificate(string thumbprint, bool machineStore)
    {
        using var store = new X509Store(StoreName.My, machineStore ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        try
        {
            var now = DateTime.UtcNow;
            if (matches.Count != 1 || !matches[0].HasPrivateKey || now < matches[0].NotBefore.ToUniversalTime()
                || now > matches[0].NotAfter.ToUniversalTime()
                || matches[0].Extensions.OfType<X509BasicConstraintsExtension>().Any(extension => extension.CertificateAuthority)
                || !matches[0].Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(extension =>
                    extension.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.3")))
            {
                throw new CryptographicException("Missing, ambiguous, or invalid actual code-signing leaf credential.");
            }
            return Convert.ToHexStringLower(SHA256.HashData(matches[0].RawData));
        }
        finally { foreach (var certificate in matches) { certificate.Dispose(); } }
    }

    private static void FlushOwnedFile(FileStream stream) => stream.Flush(flushToDisk: true);
}
