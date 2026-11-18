// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Platform.Capabilities;

namespace ArcForges.Node.Core.Tests;

public sealed partial class SandboxPolicyAdmissionTests
{
    [Fact]
    public void TheNodeRejectsAnOversizeOutputRetentionBeforeDiscovery()
    {
        var config = WindowsConfiguration();
        config.OutputRetentionBytes = SandboxPolicyAdmission.DefaultOutputRetentionBytes + 1;

        var result = SandboxPolicyAdmission.Evaluate(config, Path.GetTempPath(), MissingInstallation());

        Assert.Equal(MxcAdmissionDecision.UnsupportedCombination, result.Admission.Decision);
        Assert.Equal("output_retention_outside_node_bounds", result.Admission.Reason);
        Assert.Null(result.Config);
    }

    [Fact]
    public void SelectedNumericEgressRequiresTheExactBackendAndNeverBecomesDefaultAllow()
    {
        var config = WindowsConfiguration();
        var missing = MissingInstallation();
        config.Network!.AllowedDestinations.Add("tcp://192.0.2.10:443");

        var supported = SandboxPolicyAdmission.Evaluate(config, Path.GetTempPath(), missing);
        Assert.Equal(MxcAdmissionDecision.PrerequisiteMissing, supported.Admission.Decision);
        Assert.Equal("official_mxc_installation_missing", supported.Admission.Reason);

        config.Network.Egress = NetworkMode.Allow;
        var broad = SandboxPolicyAdmission.Evaluate(config, Path.GetTempPath(), missing);
        Assert.Equal("default_allow_egress_not_admitted", broad.Admission.Reason);
        Assert.Null(broad.Config);

        config.Network.Egress = NetworkMode.Deny;
        config.Network.AllowedDestinations[0] = "tcp://example.invalid:443";
        var dns = SandboxPolicyAdmission.Evaluate(config, Path.GetTempPath(), missing);
        Assert.Equal("unsupported_selected_destination", dns.Admission.Reason);
        Assert.Null(dns.Config);
    }


    [Fact]
    public void ARealHardLinkDoesNotGrantProtectedNodeData()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows() || OperatingSystem.IsLinux(), "Native policy platforms.");
        using var sandbox = TestPolicyDirectory.Create();
        var data = sandbox.CreateDirectory("data");
        var stage = sandbox.CreateDirectory("stage");
        var original = Path.Combine(data, "control.txt");
        File.WriteAllText(original, "protected");
        var alias = Path.Combine(sandbox.Path, "alias.txt");
        var linked = OperatingSystem.IsWindows() ? CreateHardLink(alias, original, 0) : Link(original, alias) == 0;
        Assert.True(linked, "Could not create the native hard-link fixture.");

        var config = LocalConfiguration();
        config.HostGrants.Add(new HostGrant { HostPath = alias, SandboxPath = alias, Writable = true });
        var result = SandboxPolicyAdmission.Evaluate(config, data, stage);

        Assert.Equal("host_grant_unavailable_or_unsafe", result.Admission.Reason);
        Assert.Null(result.Config);
        Assert.Equal("protected", File.ReadAllText(original));
    }

    [Fact]
    public void AnEmptyProtectedManifestProducesATypedRefusal()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows() || OperatingSystem.IsLinux(), "Native policy platforms.");
        using var sandbox = TestPolicyDirectory.Create();
        var data = sandbox.CreateDirectory("data");
        var stage = sandbox.CreateDirectory("stage");
        File.WriteAllText(Path.Combine(stage, "mxc-manifest.json"), string.Empty);

        var result = SandboxPolicyAdmission.Evaluate(LocalConfiguration(), data, stage);

        Assert.Equal(MxcAdmissionDecision.PrerequisiteMissing, result.Admission.Decision);
        Assert.Equal("official_mxc_installation_untrusted_or_unreadable", result.Admission.Reason);
        Assert.Null(result.Config);
    }

    private static SandboxConfig LocalConfiguration()
    {
        var config = WindowsConfiguration();
        if (OperatingSystem.IsLinux())
        {
            config.ProfileId = MxcProfileAdmission.LinuxProfileId;
            config.ProfileVersion = MxcProfileAdmission.LinuxProfileRevision;
        }

        return config;
    }

    private sealed class TestPolicyDirectory(string path) : IDisposable
    {
        internal string Path { get; } = path;

        internal static TestPolicyDirectory Create()
        {
            var parent = Environment.GetFolderPath(OperatingSystem.IsWindows()
                ? Environment.SpecialFolder.LocalApplicationData : Environment.SpecialFolder.UserProfile);
            var path = System.IO.Path.Combine(parent, "arcforges-policy-test-" + Guid.NewGuid().ToString("N"));
            CreatePrivateDirectory(path);
            return new TestPolicyDirectory(path);
        }

        internal string CreateDirectory(string relative)
        {
            var path = System.IO.Path.Combine(Path, relative);
            CreatePrivateDirectory(path);
            return path;
        }

        private static void CreatePrivateDirectory(string path)
        {
            if (OperatingSystem.IsLinux())
            {
                Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            else
            {
                Directory.CreateDirectory(path);
            }
        }

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateHardLinkW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateHardLink(string alias, string target, nint security);

    [LibraryImport("libc", EntryPoint = "link", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Link(string original, string alias);

    private static SandboxConfig WindowsConfiguration() => new()
    {
        ProfileId = MxcProfileAdmission.WindowsProfileId,
        ProfileVersion = MxcProfileAdmission.WindowsProfileRevision,
        Network = new NetworkPolicy { Egress = NetworkMode.Deny, Ingress = NetworkMode.Deny, HostLoopback = false },
        Resources = new ResourcePolicy { PressureAction = PressureAction.Throttle },
    };

    private static string MissingInstallation() => Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
}
