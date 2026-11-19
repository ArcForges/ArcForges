// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.Versioning;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.RunSupervisor.Protocol;

namespace ArcForges.RunSupervisor;

[SupportedOSPlatform("windows")]
internal sealed class WindowsRunPathBindings : IDisposable
{
    private readonly List<WindowsMxcPathLease> _identities = [];
    private readonly List<WindowsMxcPathLease> _privateDirectories = [];

    internal static WindowsRunPathBindings Open(RunLaunchSpec spec)
    {
        var fields = spec.PrivateRootIdentity?.Split(':');
        if (fields is not { Length: 7 } || fields[0] != "1" || fields[1] != spec.SandboxId || fields[3] != "1")
        {
            throw new InvalidDataException("The Windows private Sandbox root identity is missing or malformed.");
        }

        var root = Path.GetFullPath(spec.PrivateRoot);
        var sandboxParent = Path.GetDirectoryName(root) ?? throw new InvalidDataException("The Windows Sandbox parent is missing.");
        var dataRoot = Path.GetDirectoryName(sandboxParent) ?? throw new InvalidDataException("The Windows Sandbox data root is missing.");
        var bindings = new WindowsRunPathBindings();
        try
        {
            bindings._identities.Add(WindowsMxcPathLease.OpenGrant(dataRoot, Binding(fields[4])));
            bindings._identities.Add(WindowsMxcPathLease.OpenGrant(sandboxParent, Binding(fields[5])));
            bindings._identities.Add(WindowsMxcPathLease.OpenGrant(root, Binding(fields[6])));
            bindings._privateDirectories.Add(WindowsMxcPathLease.Open(root, directory: true, privateObject: true));
            foreach (var directory in WindowsRunPolicy.PrivateDirectories(root))
            {
                bindings._privateDirectories.Add(WindowsMxcPathLease.Open(directory, directory: true, privateObject: true));
            }

            foreach (var mount in spec.Mounts)
            {
                bindings._identities.Add(WindowsMxcPathLease.OpenGrant(mount.HostPath, mount.NativeIdentity));
            }

            if (spec.Argv.Length == 0)
            {
                throw new InvalidDataException("The Windows Run lacks a bound executable.");
            }

            bindings._identities.Add(WindowsMxcPathLease.OpenExecutable(spec.Argv[0], spec.ExecutableIdentity));
            bindings._identities.Add(WindowsMxcPathLease.OpenGrant(spec.WorkingDirectory, spec.WorkingDirectoryIdentity));
            return bindings;
        }
        catch
        {
            bindings.Dispose();
            throw;
        }
    }

    internal void RequireStable()
    {
        foreach (var identity in _identities) identity.RequireStableGrant();
    }

    public void Dispose()
    {
        foreach (var binding in _privateDirectories) binding.Dispose();
        foreach (var binding in _identities) binding.Dispose();
    }

    private static string Binding(string value) => "1:" + Convert.ToHexStringLower(Convert.FromBase64String(value));
}
