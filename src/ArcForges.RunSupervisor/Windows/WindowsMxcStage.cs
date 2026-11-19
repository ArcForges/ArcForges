// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Node.Platform.Capabilities;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.RunSupervisor;

[SupportedOSPlatform("windows")]
internal sealed class WindowsMxcStage : IDisposable
{
    // The same Microsoft artifact cohort pinned by MxcProfileAdmission.
    private static readonly (string Name, string Sha256)[] Members =
    [
        ("mxc_ffi.dll", "bd45522f06dc9cc8001dcd5d7320bc2bf303fb08a39bf10f3404bd9a8001812c"),
        ("plm.exe", "beffc9c9ab974ca9e7455089fd8ecb36eb8c92811ddd1705db91370a689692c3"),
        ("wslcsdk.dll", "8d4d55d4283fb32a5909b57e78b576d01363d7b28bb9b2595115e80faf61db5b"),
        ("wxc-exec.exe", "090f5d1f7bb93104ab08dcd4e8034ef954aeefcdaf6658dde5f7dff4cfc12f3a"),
        ("wxc-wslc-daemon.exe", "84f61c1bc13abde8da1c3f2ff100e6d59368ecaabdbfeca939e6fdb696202d0c"),
    ];

    private readonly List<WindowsMxcPathLease> _leases = [];

    private WindowsMxcStage(string directory)
    {
        Directory = directory;
        Executor = Path.Combine(directory, "wxc-exec.exe");
    }

    internal string Directory { get; }
    internal string Executor { get; }

    internal static WindowsMxcStage Open(RunLaunchSpec spec)
    {
        if (RuntimeInformation.ProcessArchitecture != Architecture.X64
            || RuntimeInformation.RuntimeIdentifier != "win-x64"
            || spec.ProfileId != MxcProfileAdmission.WindowsProfileId
            || spec.ProfileVersion != MxcProfileAdmission.WindowsProfileRevision)
        {
            throw new InvalidDataException("This owner is outside the admitted Windows MXC cohort.");
        }

        var directory = Path.GetFullPath(spec.InstallationRoot);
        var stage = new WindowsMxcStage(directory);
        try
        {
            stage._leases.Add(WindowsMxcPathLease.Open(directory, directory: true));
            var manifestFile = stage.Hold("mxc-manifest.json");
            using var manifest = JsonDocument.Parse(manifestFile.Read(65_536));
            var root = manifest.RootElement;
            if (root.GetProperty("version").GetString() != "1.0.1"
                || root.GetProperty("schema").GetString() != "1.0.0"
                || root.GetProperty("rid").GetString() != "win-x64"
                || root.GetProperty("source").GetString() != "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
                || root.GetProperty("packageSha256").GetString() != "d47b1f70c3fcaaed1705a0c3872807e2878fe8c1b778c0dd9eb9325bf421a672"
                || root.GetProperty("releaseSha256").GetString() != "0e832239454ba7fcd338ff56218a287eef4c0a01c1484084b869f55feff8abe9")
            {
                throw new InvalidDataException("The held MXC manifest does not identify the pinned Microsoft distribution.");
            }

            var recorded = root.GetProperty("files").EnumerateArray().ToDictionary(
                item => item.GetProperty("path").GetString() ?? string.Empty,
                item => item.GetProperty("sha256").GetString(), StringComparer.Ordinal);
            foreach (var (name, hash) in Members)
            {
                if (!recorded.TryGetValue(name, out var expected) || expected != hash || stage.Hold(name).Hash(512L * 1024 * 1024) != hash)
                {
                    throw new InvalidDataException("The installed native Microsoft MXC cohort differs from its pinned artifact.");
                }
            }

            return stage;
        }
        catch
        {
            stage.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        foreach (var lease in _leases) lease.Dispose();
        _leases.Clear();
    }

    private WindowsMxcPathLease Hold(string name)
    {
        var handle = WindowsMxcPathLease.Open(Path.Combine(Directory, name), directory: false);
        _leases.Add(handle);
        return handle;
    }
}
