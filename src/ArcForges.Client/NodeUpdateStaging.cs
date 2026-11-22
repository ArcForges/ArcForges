// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcForges.Client;

/// <summary>The independent release identity required to stage an update.</summary>
public sealed record NodeUpdateArtifact(string Archive, string TrustedKey, string ArchiveSha256, string Commit, string Tree, string Python,
    string OpenSsl, string? PowerShell);

/// <summary>A fresh cohort extracted by the installed release verifier.</summary>
public sealed record NodeUpdateInstallation(string Root, string ArchiveSha256, string Commit, string Tree);

/// <summary>Verifies and stages one x64 Node cohort without touching the selected version.</summary>
public static class NodeUpdateStaging
{
    private const int MaximumDiagnostic = 16 * 1024;
    public static async Task<NodeUpdateInstallation> StageAsync(NodeUpdateArtifact artifact, string destination, bool testMode,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        RequireIdentity(artifact.Commit, 40, nameof(artifact.Commit));
        RequireIdentity(artifact.Tree, 40, nameof(artifact.Tree));
        RequireIdentity(artifact.ArchiveSha256, 64, nameof(artifact.ArchiveSha256));
        var archive = ExistingFile(artifact.Archive);
        var trustedKey = ExistingFile(artifact.TrustedKey);
        var python = ExistingFile(artifact.Python);
        var openSsl = ExistingFile(artifact.OpenSsl);
        var powerShell = OperatingSystem.IsWindows()
            ? ExistingFile(artifact.PowerShell ?? throw new ArgumentException("Windows preparation requires trusted PowerShell.", nameof(artifact)))
            : null;
        var root = Absolute(destination);
        if (File.Exists(root) || Directory.Exists(root))
        {
            throw new IOException("node_update_staging_must_be_fresh");
        }

        var rid = System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier;
        if (rid is not ("win-x64" or "linux-x64"))
        {
            throw new PlatformNotSupportedException("node_update_requires_a_signed_x64_cohort");
        }

        var active = AppContext.BaseDirectory;
        var script = Path.Combine(active, "packaging", "mxc", "verify_install.py");
        using var verifier = OpenSealedScript(script, "VerifyInstall");
        using var signature = OpenSealedScript(Path.Combine(active, "packaging", "native", "signed.py"), "Signed");
        using var mxc = OpenSealedScript(Path.Combine(active, "eng", "mxc", "stage.py"), "MxcStage");

        var launch = new ProcessStartInfo(python)
        {
            WorkingDirectory = active,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            CreateNoWindow = true,
        };
        foreach (var option in new[] { "PATH", "PYTHONHOME", "PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "OPENSSL_CONF", "OPENSSL_CONF_INCLUDE", "OPENSSL_MODULES", "OPENSSL_ENGINES", "PSModulePath" })
        {
            launch.Environment.Remove(option);
        }

        string[] arguments = ["-I", "-B", script, "--rid", rid, "--archive", archive, "--trusted-key", trustedKey,
            "--admitted-archive-sha256", artifact.ArchiveSha256, "--commit", artifact.Commit, "--tree", artifact.Tree, "--output", root,
            "--openssl", openSsl];
        foreach (var argument in arguments)
        {
            launch.ArgumentList.Add(argument);
        }

        if (powerShell is not null)
        {
            launch.ArgumentList.Add("--powershell");
            launch.ArgumentList.Add(powerShell);
        }

        if (testMode)
        {
            launch.ArgumentList.Add("--allow-candidate");
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(2));
        using var process = Process.Start(launch) ?? throw new IOException("node_update_verifier_did_not_start");
        process.StandardInput.Close();
        try
        {
            var stdout = ReadBoundedAsync(process.StandardOutput, deadline.Token);
            var stderr = ReadBoundedAsync(process.StandardError, deadline.Token);
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(deadline.Token)).ConfigureAwait(false);
            if (process.ExitCode != 0)
            {
                throw new IOException("node_update_package_refused: " + stderr.Result.Trim());
            }

            using var document = JsonDocument.Parse(stdout.Result);
            var receipt = document.RootElement;
            if (receipt.GetProperty("authentication").GetString() != "ed25519"
                || receipt.GetProperty("archiveSha256").GetString() != artifact.ArchiveSha256
                || receipt.GetProperty("commit").GetString() != artifact.Commit
                || receipt.GetProperty("tree").GetString() != artifact.Tree
                || receipt.GetProperty("rid").GetString() != rid
                || !PathEquals(receipt.GetProperty("installRoot").GetString(), root)
                || !Directory.Exists(root))
            {
                throw new IOException("node_update_installer_identity_mismatch");
            }

            return new(root, artifact.ArchiveSha256, artifact.Commit, artifact.Tree);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new IOException("node_update_verifier_deadline");
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
    }

    private static FileStream OpenSealedScript(string path, string resource)
    {
        using var embedded = typeof(NodeUpdateStaging).Assembly.GetManifestResourceStream("ArcForges.Update." + resource)
            ?? throw new IOException("node_update_verifier_build_identity_missing");
        var script = File.OpenRead(ExistingFile(path));
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(embedded), SHA256.HashData(script)))
            {
                throw new IOException("node_update_verifier_build_identity_mismatch");
            }

            return script;
        }
        catch
        {
            script.Dispose();
            throw;
        }
    }

    private static async Task<string> ReadBoundedAsync(TextReader reader, CancellationToken cancellationToken)
    {
        char[] buffer = new char[MaximumDiagnostic + 1];
        int count = await reader.ReadBlockAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (count > MaximumDiagnostic)
        {
            throw new IOException("node_update_verifier_diagnostic_too_large");
        }

        return new string(buffer, 0, count);
    }

    private static void RequireIdentity(string value, int size, string parameter)
    {
        if (value.Length != size || value.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            throw new ArgumentException("Use the complete lowercase hexadecimal release identity.", parameter);
        }
    }

    private static string ExistingFile(string path)
    {
        var absolute = Absolute(path);
        if ((File.GetAttributes(absolute) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new IOException("node_update_requires_regular_input");
        }

        return absolute;
    }

    private static string Absolute(string path) => Path.IsPathFullyQualified(path)
        ? Path.TrimEndingDirectorySeparator(Path.GetFullPath(path))
        : throw new ArgumentException("Use an absolute path.", nameof(path));

    private static bool PathEquals(string? left, string right) => string.Equals(left, right,
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
}
