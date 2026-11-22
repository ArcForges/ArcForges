// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;

namespace ArcForges.Client.Tests;

public sealed class UpdateLinuxCustodyTests
{
    [Fact]
    [Trait("env", "linux-real")]
    public void ParkingPreservesInodeAndRestoresExactPermissionsAcrossInterruptedMoves()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux file modes and inode-bound installation custody.");
            return;
        }

        var scratch = Directory.CreateTempSubdirectory("arcforges-update-linux-mode-");
        try
        {
            var app = Path.Combine(scratch.FullName, "app");
            NodeVersionSelection.PrepareDirectories(app);
            var archive = new string('a', 64);
            var canonical = NodeVersionSelection.InstallationDirectory(app, archive);
            var parked = NodeVersionSelection.ParkedDirectory(canonical);
            Directory.CreateDirectory(canonical, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var image = Path.Combine(canonical, "arcforges");
            File.WriteAllText(image, "fixture role bytes");
            const UnixFileMode Original = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            File.SetUnixFileMode(image, Original);
            var manifest = Path.Combine(canonical, "digests.json");
            File.WriteAllText(manifest, JsonSerializer.Serialize(new { files = new Dictionary<string, string> { ["arcforges"] = Digest(image) } }));
            var previous = new NodeUpdateInstallation(canonical, archive, new string('b', 40), new string('c', 40), Digest(manifest));

            using var originalInode = File.OpenRead(image);
            NodeUpdateInstallationCustody.Park(app, previous, testMode: true);
            Assert.True(NodeUpdateInstallationCustody.IsParked(app, archive));
            Assert.Equal(UnixFileMode.UserRead, File.GetUnixFileMode(Path.Combine(parked, "arcforges")));

            // The receipt and disabled inode can survive a commit interrupted before the directory move.
            Directory.Move(parked, canonical);
            Assert.False(NodeUpdateInstallationCustody.IsParked(app, archive));
            NodeUpdateInstallationCustody.Park(app, previous, testMode: true);
            Assert.True(NodeUpdateInstallationCustody.IsParked(app, archive));

            // A resumed operator can observe an old holder after durable reinstallation but before unlinking the receipt.
            Directory.Move(parked, canonical);
            File.SetUnixFileMode(image, Original);
            NodeUpdateInstallationCustody.FinishRestoredMode(app, previous);
            Assert.False(File.Exists(parked + ".mode"));

            NodeUpdateInstallationCustody.Park(app, previous, testMode: true);
            NodeUpdateInstallationCustody.Restore(app, previous, testMode: true);
            NodeUpdateInstallationCustody.Restore(app, previous, testMode: true);
            Assert.Equal(Original, File.GetUnixFileMode(image));
            Assert.False(File.Exists(parked + ".mode"));
            Assert.Equal(Digest(image), Convert.ToHexStringLower(SHA256.HashData(originalInode)));
        }
        finally
        {
            scratch.Delete(recursive: true);
        }
    }

    private static string Digest(string path) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
}
