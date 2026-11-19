// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Api;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    [Fact(Timeout = 135_000, DisableParallelization = true)]
    public async Task InstalledOfflineOwnerRunsExactInputsWithProtectedIpcAndRedactedAuthority()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var fixture = TestNode.Create();
        PrepareDataRoot(fixture.DataRoot);
        fixture.Environment[LocalSubmission.Variable] = null;
        fixture.Environment["ARCFORGES_TEST_CLIENT_IMAGES"] = null;
        fixture.Environment["CORESEC01_NATIVE_SECRET"] = "unrelated-host-value";
        var process = await fixture.StartNodeAsync();
        Id? epoch = null;
        Id? activeRun = null;
        string? secretTarget = null;
        var secrets = NodeSecretStores.ForTestDataRoot(fixture.DataRoot).Store;
        await using var channel = OpenChannel(fixture);
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
        var runs = new RunService.RunServiceClient(channel.CallInvoker);
        try
        {
            // This connection never sends a V1 Hello and has neither a Center connection nor a login.
            epoch = (await HandshakeAsync(node)).OwnerEpoch;
            var sandbox = await CreateSandboxAsync(sandboxes, epoch);
            var listed = await sandboxes.ListAsync(new SandboxServiceListRequest
            {
                Meta = Query(),
            }, deadline: Deadline, cancellationToken: Ct);
            Assert.Equal(sandbox.SandboxId, Assert.Single(Value(listed.Value, listed.Error).Sandboxes).SandboxId);

            var working = Path.Combine(sandbox.DataLocation, "work", "quoted directory");
            Directory.CreateDirectory(working);
            var payload = CopySecurityTestLoad(working);
            var guarded = Path.Combine(fixture.DataRoot, "control", "sec01-host-probe");
            const string protectedSentinel = "isolated-sec01-private-metadata";
            await File.WriteAllTextAsync(guarded, protectedSentinel, Ct);
            var argumentCanary = "sec01-argument-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24));
            var environmentCanary = "sec01-secret-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24));
            var argument = argumentCanary + " spaces \"quoted\" 星\\";
            var secret = environmentCanary + " equals=argument 星";
            var argumentDigest = Digest(argument);
            var secretDigest = Digest(secret);
            var patterns = RedactionPatterns(argumentCanary, environmentCanary, argument, secret, argumentDigest, secretDigest);
            var reference = FixtureSecretReference();
            var owner = SandboxLocalOwner.Current();
            Assert.NotNull(owner);
            secretTarget = SandboxRunSecrets.Target(fixture.DataRoot, owner, reference);
            var protectedBytes = Encoding.UTF8.GetBytes(secret);
            try
            {
                secrets.Write(secretTarget, protectedBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }

            var refused = SecurityStart("security-refused.log", FixtureSecretReference());
            var unavailable = await runs.StartAsync(refused, deadline: Deadline, cancellationToken: Ct);
            Assert.Null(unavailable.Value);
            Assert.Equal("unsupported_combination", unavailable.Error?.Code);
            Assert.Equal("run_secret_reference_unavailable", unavailable.Error!.Details.State.Reason);
            Assert.Equal(EffectCertainty.DidNotHappen, unavailable.Error.Effect);
            Assert.Empty(await ListAsync(runs, sandbox.SandboxId));
            Assert.False(File.Exists(Path.Combine(working, "security-refused.log")));

            var command = SecurityStart("security-verified.log", reference);
            var accepted = await runs.StartAsync(command, deadline: Deadline, cancellationToken: Ct);
            var run = Value(accepted.Value, accepted.Error).Run;
            activeRun = run.RunId;
            await WaitForStateAsync(fixture, runs, run.RunId, RunState.Running);
            var runId = Hex(run.RunId);
            var markerPath = Path.Combine(working, "security-verified.log");
            await TestNode.WaitAsync(() => ReadLines(markerPath).Length >= 4, NativeBound, "the full contained security witness");
            var markers = ReadLines(markerPath);
            Assert.Collection(markers,
                line => Assert.Equal("argument-verified", line),
                line => Assert.Equal("secret-verified", line),
                line => Assert.True(line is "ipc-access-denied" or "ipc-not-visible", "The payload IPC result was " + line),
                line => Assert.True(line is "metadata-access-denied" or "metadata-not-visible", "The payload metadata result was " + line));

            string? liveOfficialRequest = null;
            if (OperatingSystem.IsWindows())
            {
                liveOfficialRequest = Path.Combine(fixture.DataRoot, "control", "run-" + runId, "mxc-request.json");
                RequirePrivateWindowsRequest(liveOfficialRequest, argumentCanary, environmentCanary);
                var handoff = Path.Combine(working, "security-mxc-run-id");
                await File.WriteAllTextAsync(handoff + ".tmp", runId, Ct);
                File.Move(handoff + ".tmp", handoff);
                var observer = Path.Combine(working, "security-mxc-config.log");
                await TestNode.WaitAsync(() => ReadLines(observer).Length > 0, NativeBound, "the contained official-config refusal");
                var refusal = Assert.Single(ReadLines(observer));
                Assert.True(refusal is "metadata-access-denied" or "metadata-not-visible", "The payload official-config result was " + refusal);
                Assert.True(File.Exists(liveOfficialRequest), "The exact official request must still exist when the payload's refusal is observed.");
            }

            // Independently verify that both protected targets stayed live. AppContainer/namespace refusal is not a second-account result.
            await using (var sameOwner = OpenChannel(fixture))
            {
                var healthy = await HandshakeAsync(new NodeService.NodeServiceClient(sameOwner.CallInvoker));
                Assert.Equal(epoch, healthy.OwnerEpoch);
            }

            Assert.Equal(protectedSentinel, await File.ReadAllTextAsync(guarded, Ct));
            // The isolated test secret backing file is the intentional cleartext fixture input.
            Assert.True(secrets.Delete(secretTarget));
            secretTarget = null;
            RequireRedactedAuthority(fixture.DataRoot, patterns, liveOfficialRequest);
            await File.WriteAllTextAsync(Path.Combine(working, "security-finish"), "finish", Ct);
            var settled = await WaitForStateAsync(fixture, runs, run.RunId, RunState.Exited);
            Assert.True(settled.Exit.GroupEmptyVerified);
            if (liveOfficialRequest is not null)
            {
                Assert.False(File.Exists(liveOfficialRequest), "The exact official Windows request must be removed after verified native drain.");
                TestContext.Current.TestOutputHelper?.WriteLine("The protected official Windows request was unavailable to the contained payload and removed at native drain.");
            }
            Assert.StartsWith(Path.GetFileName(payload), settled.SafeCommandDisplay);
            Assert.DoesNotContain(working, settled.SafeCommandDisplay);
            if (settled.Exit.HasRawCode)
            {
                Assert.Equal(0, settled.Exit.RawCode);
            }

            activeRun = null;
            var receipt = await OperationAsync(node, epoch, command.Meta.CommandId);
            Assert.Equal(OperationState.Succeeded, receipt.State);
            Assert.Equal(EffectCertainty.Happened, receipt.Effect);
            Assert.Equal(run.RunId, receipt.AggregateId);
            Assert.Equal(run.RunId, Assert.Single(await ListAsync(runs, sandbox.SandboxId)).RunId);
            Assert.Empty((await WatchAsync(runs, run, StreamKind.Stdout)).Bytes);
            Assert.Empty((await WatchAsync(runs, run, StreamKind.Stderr)).Bytes);
            Assert.Equal(2, TestNode.LogEvents(fixture.NodeLog, "api.run.output.accessed")
                .Count(entry => entry.GetProperty("fields").GetProperty("run").GetString() == runId));
            Assert.False(File.Exists(Path.Combine(working, "security-refused.log")));

            RequireRedacted(unavailable.ToByteArray(), patterns, "the unavailable-reference response");
            RequireRedacted(accepted.ToByteArray(), patterns, "the typed Start reply");
            RequireRedacted(settled.ToByteArray(), patterns, "the typed Run projection");
            RequireRedacted(receipt.ToByteArray(), patterns, "the typed receipt");
            RequireRedactedAuthority(fixture.DataRoot, patterns);
            TestContext.Current.TestOutputHelper?.WriteLine(
                $"Offline owner and exact native input proof passed. Contained peer observations were {markers[2]} and {markers[3]}. "
                + "The missing reference never entered the workload. Settled authority and audit artifacts passed canary screening.");

            RunServiceStartRequest SecurityStart(string markerName, string secretReference)
            {
                var value = BuildStart(sandbox, epoch,
                    [payload, "security", markerName, fixture.Endpoint, guarded, argument, argumentDigest, secretDigest]);
                value.TerminalMode = TerminalMode.Pipes;
                value.TerminalSize = null;
                value.Environment.Clear();
                value.Environment.Add(new EnvironmentEntry { Name = "CORESEC01_NATIVE_SECRET", SecretRef = secretReference });
                return value;
            }
        }
        finally
        {
            try
            {
                if (epoch is not null && activeRun is not null && !process.HasExited)
                {
                    var current = await InspectAsync(runs, activeRun, CancellationToken.None);
                    if (current.State is RunState.Running or RunState.Starting)
                    {
                        await StopAsync(runs, BuildStop(epoch, current), CancellationToken.None);
                        await WaitForStateAsync(fixture, runs, activeRun, RunState.Exited, CancellationToken.None);
                    }
                }
            }
            finally
            {
                await StopNodeAsync(fixture, process);
                if (secretTarget is not null)
                {
                    Assert.True(secrets.Delete(secretTarget));
                }

                if (epoch is not null)
                {
                    RemoveFixtureOwnerKey(fixture.DataRoot, epoch);
                }
            }
        }
    }

    private static string CopySecurityTestLoad(string working)
    {
        var source = Environment.GetEnvironmentVariable("ARCFORGES_TESTLOAD_PATH");
        Assert.True(source is not null && Path.IsPathFullyQualified(source) && File.Exists(source),
            "The native security fixture needs the independently published TestLoad.");
        var installed = Path.Combine(working, OperatingSystem.IsWindows() ? "arcforges-testload.exe" : "arcforges-testload");
        File.Copy(source!, installed);
        if (OperatingSystem.IsLinux())
        {
            File.SetUnixFileMode(installed, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        return installed;
    }

    private static string FixtureSecretReference() => "v1:" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)) + ":1";

    private static string Digest(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    [SupportedOSPlatform("windows")]
    private static void RequirePrivateWindowsRequest(string path, string argumentCanary, string environmentCanary)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User;
        Assert.NotNull(owner);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var file = new FileInfo(path);
        Assert.True(file.Exists);
        Assert.False(file.Attributes.HasFlag(FileAttributes.ReparsePoint));
        var security = file.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        Assert.Equal(owner, security.GetOwner(typeof(SecurityIdentifier)));
        var grants = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow).ToArray();
        Assert.Contains(grants, rule => rule.IdentityReference == owner && rule.FileSystemRights.HasFlag(FileSystemRights.ReadData));
        Assert.All(grants, rule => Assert.True(rule.IdentityReference == owner || rule.IdentityReference == system,
            "The live official request must grant access only to the local owner and LocalSystem."));

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        Assert.InRange(stream.Length, 1, 4 * 1024 * 1024);
        var observed = new byte[checked((int)stream.Length)];
        try
        {
            stream.ReadExactly(observed);
            Assert.True(observed.AsSpan().IndexOf(Encoding.ASCII.GetBytes(argumentCanary)) >= 0,
                "The exact private Windows request must carry the prepared argument.");
            Assert.True(observed.AsSpan().IndexOf(Encoding.ASCII.GetBytes(environmentCanary)) >= 0,
                "The exact private Windows request must carry the resolved environment value.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(observed);
        }
    }

    private static List<byte[]> RedactionPatterns(params string[] canaries)
    {
        var values = new List<byte[]>();
        foreach (var canary in canaries)
        {
            var utf8 = Encoding.UTF8.GetBytes(canary);
            values.Add(utf8);
            values.Add(Encoding.Unicode.GetBytes(canary));
            // Also find canaries encoded inside a larger payload at any Base64 alignment.
            for (var start = 0; start < 3; start++)
            {
                var length = (utf8.Length - start) / 3 * 3;
                values.Add(Encoding.ASCII.GetBytes(Convert.ToBase64String(utf8.AsSpan(start, length))));
            }
        }

        return values;
    }

    private static void RequireRedacted(byte[] observed, List<byte[]> patterns, string artifact)
    {
        Assert.False(patterns.Any(pattern => observed.AsSpan().IndexOf(pattern) >= 0),
            "A synthetic argument or secret leaked into " + artifact + ".");
    }

    private static void RequireRedactedAuthority(string dataRoot, List<byte[]> patterns, string? liveWindowsRequest = null)
    {
        var files = Directory.EnumerateFiles(dataRoot, "*", new EnumerationOptions
        {
            AttributesToSkip = FileAttributes.ReparsePoint,
            IgnoreInaccessible = false,
            RecurseSubdirectories = true,
        });
        foreach (var path in files)
        {
            if ((OperatingSystem.IsWindows() && string.Equals(path, liveWindowsRequest, StringComparison.OrdinalIgnoreCase))
                || new FileInfo(path).Length == 0)
            {
                continue;
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Assert.InRange(stream.Length, 0, 64 * 1024 * 1024);
            var observed = new byte[checked((int)stream.Length)];
            stream.ReadExactly(observed);
            RequireRedacted(observed, patterns, Path.GetFileName(path));
        }
    }
}
