// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.ComponentModel;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.CommandLine;

/// <summary>Runs a local update operation through the Host's concrete composition.</summary>
public delegate Task<NodeUpdateResponse> NodeUpdateRunner(NodeUpdateRequest request, CancellationToken cancellationToken);

internal static class UpdateCommands
{
    internal static Command Build(Func<ParseResult, Cli> factory, NodeUpdateRunner runner)
    {
        var update = new Command("update", "Stage and safely switch signed Node installations");
        update.Subcommands.Add(Apply(factory, runner));
        update.Subcommands.Add(Operate("resume", "Resume the recorded update checkpoint", NodeUpdateAction.Resume, factory, runner));
        update.Subcommands.Add(Operate("status", "Show the recorded update checkpoint and selected installation", NodeUpdateAction.Status, factory, runner));
        update.Subcommands.Add(Operate("rollback", "Return to the compatible previously selected installation", NodeUpdateAction.Rollback, factory, runner));
        update.Subcommands.Add(Restore(factory, runner));
        update.Subcommands.Add(Operate("compatibility", "Report this executable's supported store and supervisor protocol", NodeUpdateAction.Compatibility, factory, runner));
        return update;
    }

    private static Command Apply(Func<ParseResult, Cli> factory, NodeUpdateRunner runner)
    {
        var archive = Required("--archive", "Signed Node archive and its detached manifest and signature");
        var digest = Required("--archive-sha256", "Independently admitted archive SHA-256");
        var commit = Required("--commit", "Expected producer commit");
        var tree = Required("--tree", "Expected producer tree");
        var key = Required("--trusted-key", "Separately trusted Ed25519 PEM public key");
        var python = Required("--python", "Absolute path to the trusted Python executable for installation preparation");
        var openssl = Required("--openssl", "Absolute path to the trusted OpenSSL executable for signature verification");
        var powershell = new Option<string?>("--powershell") { Description = "Absolute path to trusted PowerShell. Required on Windows." };
        var previousArchive = new Option<string?>("--previous-archive") { Description = "Independently verified prior archive when adopting an existing installation" };
        var previousDigest = new Option<string?>("--previous-archive-sha256") { Description = "Independently admitted prior archive SHA-256" };
        var previousCommit = new Option<string?>("--previous-commit") { Description = "Expected prior producer commit" };
        var previousTree = new Option<string?>("--previous-tree") { Description = "Expected prior producer tree" };
        var previousKey = new Option<string?>("--previous-trusted-key") { Description = "Separately trusted prior Ed25519 public key when it differs from --trusted-key" };
        var command = new Command("apply", "Verify a complete signed replacement, fence admissions and check readiness before selection")
        {
            archive, digest, commit, tree, key, python, openssl, powershell, previousArchive, previousDigest, previousCommit, previousTree, previousKey,
        };
        V2Cli.Set(command, factory, async (cli, result, ct) =>
        {
            var app = NodeLocations.UpdateApplicationRoot(cli.TestMode);
            string?[] prior = [result.GetValue(previousArchive), result.GetValue(previousDigest), result.GetValue(previousCommit), result.GetValue(previousTree)];
            if (Array.Exists(prior, value => value is not null) && Array.Exists(prior, value => value is null))
            {
                throw new UsageException("Supply all four --previous-* options to verify a prior installation.");
            }

            var priorTrust = result.GetValue(previousKey);
            if (priorTrust is not null && prior[0] is null)
            {
                throw new UsageException("--previous-trusted-key requires the four prior archive identity options.");
            }

            var trustedKey = result.GetRequiredValue(key);
            var pythonPath = result.GetRequiredValue(python);
            var opensslPath = result.GetRequiredValue(openssl);
            var powershellPath = result.GetValue(powershell);
            var replacement = new NodeUpdateArtifact(result.GetRequiredValue(archive), trustedKey, result.GetRequiredValue(digest),
                result.GetRequiredValue(commit), result.GetRequiredValue(tree), pythonPath, opensslPath, powershellPath);
            try
            {
                NodeVersionSelection.PrepareDirectories(app);
                var candidate = await StageAsync(replacement).ConfigureAwait(false);
                var previous = prior[0] is { } path
                    ? await StageAsync(new NodeUpdateArtifact(path, priorTrust ?? trustedKey, prior[1]!, prior[2]!, prior[3]!, pythonPath, opensslPath, powershellPath)).ConfigureAwait(false)
                    : null;
                return Print(cli, await runner(new NodeUpdateRequest(NodeUpdateAction.Apply, cli.TestMode, candidate, previous), ct).ConfigureAwait(false));
            }
            catch (ArgumentException error)
            {
                throw new UsageException(error.Message);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or Win32Exception or PlatformNotSupportedException)
            {
                return Refuse(cli, error.Message);
            }

            Task<NodeUpdateInstallation> StageAsync(NodeUpdateArtifact artifact) => NodeUpdateStaging.StageAsync(artifact,
                NodeVersionSelection.InstallationDirectory(app, artifact.ArchiveSha256), cli.TestMode, ct);
        });
        return command;
    }

    private static Command Operate(string name, string description, NodeUpdateAction action, Func<ParseResult, Cli> factory, NodeUpdateRunner runner)
    {
        var command = new Command(name, description);
        V2Cli.Set(command, factory, async (cli, _, ct) => Print(cli, await runner(new NodeUpdateRequest(action, cli.TestMode), ct).ConfigureAwait(false)));
        return command;
    }

    private static Command Restore(Func<ParseResult, Cli> factory, NodeUpdateRunner runner)
    {
        var destination = Required("--destination", "Fresh absolute directory for the verified isolated store and authority restore");
        var command = new Command("restore", "Restore the recorded update backup to a separate offline directory") { destination };
        V2Cli.Set(command, factory, async (cli, result, ct) =>
        {
            try
            {
                var path = result.GetRequiredValue(destination);
                if (!Path.IsPathFullyQualified(path))
                {
                    throw new UsageException("--destination requires a fresh absolute directory.");
                }

                path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
                var active = NodeLocations.ResolveDataRoot(cli.TestMode);
                if (Contains(active, path) || Contains(path, active))
                {
                    throw new UsageException("--destination must be separate from the active Node data root.");
                }

                if (Path.GetDirectoryName(path) is not { } parent
                    || (File.GetAttributes(parent) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory)
                {
                    throw new UsageException("--destination requires an existing real parent directory.");
                }

                try
                {
                    _ = File.GetAttributes(path);
                    throw new UsageException("--destination already exists. Choose a fresh directory.");
                }
                catch (FileNotFoundException)
                {
                    // The offline restore may create this fresh leaf after its native custody checks.
                }

                return Print(cli, await runner(new NodeUpdateRequest(NodeUpdateAction.Restore, cli.TestMode, RestoreDestination: path), ct).ConfigureAwait(false));
            }
            catch (ArgumentException error)
            {
                throw new UsageException(error.Message);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                return Refuse(cli, error.Message);
            }
        });
        return command;
    }

    private static bool Contains(string root, string path)
    {
        var relative = Path.GetRelativePath(root, path);
        return !Path.IsPathRooted(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }

    private static Option<string> Required(string name, string description) => new(name) { Required = true, Description = description };

    private static int Print(Cli cli, NodeUpdateResponse response)
    {
        if (response.Refusal is not { } reason)
        {
            return V2Cli.Print(cli, response.Report);
        }

        var error = V2Cli.Error(ErrorCategory.State, "node_update_refused", reason);
        error.Effect = response.RefusalEffect;
        return V2Cli.Fail(cli, error, observations: response.Report);
    }

    private static int Refuse(Cli cli, string reason) => V2Cli.Fail(cli, V2Cli.Error(ErrorCategory.State, "node_update_refused", reason));
}
