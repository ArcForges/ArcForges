// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Tests;

/// <summary>Native building block only: no routed handler, authorization or durable journal is exercised here.</summary>
public sealed class WorkspaceWindowsCreateCandidateTests
{
    [Fact(Timeout = 120_000)]
    [Trait("env", "windows-real")]
    public void ExclusiveCreateUsesTheCheckedParentAndDoesNotOverwriteACompetingObject()
    {
        if (!OperatingSystem.IsWindows()) { Assert.Skip("Windows native exclusive-create candidate."); return; }
        var token = TestContext.Current.CancellationToken;
        var testRoot = Directory.CreateTempSubdirectory("arcforges-create-candidate-");
        try
        {
            var sub = Directory.CreateDirectory(Path.Combine(testRoot.FullName, "sub")).FullName;
            using var root = WorkspacePath.OpenRoot(testRoot.FullName);
            var parent = root.OpenDirectory("sub");
            var parentIdentity = WorkspacePath.Identity(parent);
            var payload = Encoding.UTF8.GetBytes("owned-stage-create-fixture-4ff5");
            using var intended = root.CreateAnonymousStage(payload, token);
            var target = Path.Combine(sub, "new.txt");
            Assert.False(File.Exists(target));
            WorkspaceObjectIdentity createdIdentity;
            using (var created = root.CreateWindowsNewTarget("sub/new.txt", parentIdentity, intended, token))
            {
                createdIdentity = created.Identity;
                Assert.True(createdIdentity.IsFile);
                Assert.Equal(1U, createdIdentity.Links);
                Assert.True(createdIdentity.SameObject(root.InspectEntry("sub/new.txt").Identity));
                Assert.True((File.GetAttributes(target) & FileAttributes.Archive) != 0);
                Assert.ThrowsAny<IOException>(() => File.ReadAllBytes(target));
                created.Guard.CheckIntact();
                intended.CheckIntact();
            }
            Assert.Empty(File.ReadAllBytes(target));
            Assert.True(createdIdentity.SameObject(root.InspectEntry("sub/new.txt").Identity));

            var collisionPath = Path.Combine(sub, "raced.txt");
            void CompetingCreate()
            {
                using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Tasks.TestLoad,
                    ["hold", "--hold-ms", "0", "--file", collisionPath])
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                }) ?? throw new InvalidOperationException("The owned competitor did not start.");
                try
                {
                    Assert.True(process.WaitForExit(5_000), "The owned competing create did not finish.");
                    Assert.Equal(0, process.ExitCode);
                }
                finally
                {
                    if (!process.HasExited)
                    {
                        process.Kill();
                        process.WaitForExit();
                    }
                }
            }
            Assert.Throws<WorkspaceCreateCollisionException>(() =>
                root.CreateWindowsNewTarget("sub/raced.txt", parentIdentity, intended, afterChecks: CompetingCreate, token));
            Assert.Equal("ready", File.ReadAllText(collisionPath));

            var wrongParentPath = Path.Combine(sub, "wrong-parent.txt");
            var error = Assert.Throws<WorkspacePathException>(() =>
                root.CreateWindowsNewTarget("sub/wrong-parent.txt", root.RootIdentity, intended, token));
            Assert.Equal("parent_identity_changed", error.Reason);
            Assert.False(File.Exists(wrongParentPath));

            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            Assert.ThrowsAny<OperationCanceledException>(() =>
                root.CreateWindowsNewTarget("sub/cancelled.txt", parentIdentity, intended, cancelled.Token));
            Assert.False(File.Exists(Path.Combine(sub, "cancelled.txt")));
            using var observed = intended.ReadVerified(token);
            Assert.Equal(SHA256.HashData(payload), observed.Sha256.ToArray());
        }
        finally
        {
            testRoot.Delete(recursive: true);
        }
    }
}
