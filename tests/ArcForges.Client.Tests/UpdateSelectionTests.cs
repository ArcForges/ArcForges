// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Client.Tests;

public sealed class UpdateSelectionTests
{
    [Fact]
    public void PublishesExactlyTheSelectedVersionAndKeepsPreviousBytes()
    {
        var scratch = Directory.CreateTempSubdirectory("arcforges-update-selection-");
        try
        {
            var app = Path.Combine(scratch.FullName, "app");
            NodeVersionSelection.PrepareDirectories(app);
            var prior = new string('1', 64);
            var candidate = new string('2', 64);
            var previousRoot = CreateCohort(app, prior);
            var candidateRoot = CreateCohort(app, candidate);

            Assert.Null(NodeVersionSelection.Read(app));
            NodeVersionSelection.Select(app, expected: null, prior);
            Assert.Equal(previousRoot, NodeVersionSelection.SelectedInstallation(app));
            Assert.Throws<IOException>(() => NodeVersionSelection.Select(app, expected: null, candidate));
            Assert.Equal(previousRoot, NodeVersionSelection.SelectedInstallation(app));

            NodeVersionSelection.Select(app, prior, candidate);
            Assert.Equal(candidateRoot, NodeVersionSelection.SelectedInstallation(app));
            Assert.Equal(prior, File.ReadAllText(Path.Combine(previousRoot, "fixture")));

            NodeVersionSelection.Select(app, candidate, prior);
            Assert.Equal(previousRoot, NodeVersionSelection.SelectedInstallation(app));
            Assert.Equal(candidate, File.ReadAllText(Path.Combine(candidateRoot, "fixture")));
        }
        finally
        {
            scratch.Delete(recursive: true);
        }
    }

    [Fact]
    public void RefusesSelectionWithUnownedIdentity()
    {
        var scratch = Directory.CreateTempSubdirectory("arcforges-update-unowned-");
        try
        {
            var app = Path.Combine(scratch.FullName, "app");
            NodeVersionSelection.PrepareDirectories(app);
            var digest = new string('1', 64);
            Assert.Throws<ArgumentException>(() => NodeVersionSelection.Select(app, expected: null, "../escape"));
            Assert.Throws<IOException>(() => NodeVersionSelection.Select(app, expected: null, digest));
            Assert.Null(NodeVersionSelection.Read(app));
        }
        finally
        {
            scratch.Delete(recursive: true);
        }
    }

    [Fact]
    public void OperatorMayAdvanceASelectionOnlyWhenTheMissingVersionIsExactlyParked()
    {
        var scratch = Directory.CreateTempSubdirectory("arcforges-update-parked-selection-");
        try
        {
            var app = Path.Combine(scratch.FullName, "app");
            NodeVersionSelection.PrepareDirectories(app);
            var previous = new string('1', 64);
            var candidate = new string('2', 64);
            var previousRoot = CreateCohort(app, previous);
            var candidateRoot = CreateCohort(app, candidate);
            NodeVersionSelection.Select(app, expected: null, previous);

            var untracked = Path.Combine(app, "versions", ".untracked");
            Directory.Move(previousRoot, untracked);
            Assert.Equal(previous, NodeVersionSelection.ReadIdentity(app));
            Assert.Throws<IOException>(() => NodeVersionSelection.Select(app, previous, candidate, allowMissingExpected: true));

            var parked = NodeVersionSelection.ParkedDirectory(previousRoot);
            Directory.Move(untracked, parked);
            Assert.Throws<IOException>(() => NodeVersionSelection.Read(app));
            Assert.Throws<IOException>(() => NodeVersionSelection.Select(app, previous, candidate));
            NodeVersionSelection.Select(app, previous, candidate, allowMissingExpected: true);
            Assert.Equal(candidateRoot, NodeVersionSelection.SelectedInstallation(app));
            Assert.Equal(previous, File.ReadAllText(Path.Combine(parked, "fixture")));
        }
        finally
        {
            scratch.Delete(recursive: true);
        }
    }

    private static string CreateCohort(string app, string identity)
    {
        var root = NodeVersionSelection.InstallationDirectory(app, identity);
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "fixture"), identity);
        return root;
    }
}
