// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
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

            var arguments = new List<string> { "sign", "/fd", "SHA256", "/sha1", certificateThumbprint, "/s", "My" };
            if (machineStore) { arguments.Add("/sm"); }
            arguments.AddRange(["/tr", timestamp.AbsoluteUri, "/td", "SHA256", temporary]);
            await InvokeAsync(tool, arguments, operation.Token).ConfigureAwait(false);
            using (var signedLease = new FileStream(temporary, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                await InvokeAsync(tool, ["verify", "/pa", "/all", "/tw", temporary], operation.Token).ConfigureAwait(false);
                await AuthenticodeIdentity.VerifySignerAsync(temporary, certificateThumbprint, requireRfc3161: true,
                    operation.Token, selectedCertificateSha256).ConfigureAwait(false);
            }
            using (var signed = new FileStream(temporary, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { FlushOwnedFile(signed); }
            operation.Token.ThrowIfCancellationRequested();
            File.Move(temporary, output, overwrite: false);
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new TimeoutException("The helper signing exceeded its operation deadline.");
        }
        finally { if (File.Exists(temporary)) { File.Delete(temporary); } }
    }

    private static async Task<FileStream> OpenToolAsync(string tool, CancellationToken cancellationToken)
    {
        tool = ReleaseCommand.CanonicalFilePath(tool);
        var installed = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Windows Kits", "10", "bin", "10.0.28000.0", "x64", "signtool.exe");
        if (!string.Equals(tool, installed, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Only the protected, reviewed SDK tool installation is admitted.");
        }
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
