// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipes;
using System.Runtime.Versioning;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Native;
using ArcForges.LocalRpc;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ContentSandbox.Host;

/// <summary>
/// The process entry of a launched helper: read the one launch frame from the inherited standard input, wrap exactly the resources it
/// lists, bring the operating-system profile into force and verify it, and only then run the host. A frame that is malformed, an inventory
/// that is not the closed set, or a profile that cannot be enforced and verified ends the process before any parser exists.
/// </summary>
internal static class HelperEntry
{
    /// <summary>Runs the helper process with the parser compositions of this build.</summary>
    [SuppressMessage("Design", "CA1031", Justification = "Every start-up failure maps to a distinct exit code; nothing is reported to the parent in prose.")]
    [SuppressMessage("Reliability", "CA2000", Justification = "The resources are disposed by the await-using below.")]
    internal static async Task<int> RunAsync(ParserProfiles parsers)
    {
        ArgumentNullException.ThrowIfNull(parsers);
        ContentSandboxLaunchFrame frame;
        try
        {
            using var standardInput = Console.OpenStandardInput();
            frame = await ContentSandboxLaunchFrame.ReadAsync(standardInput, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is FormatException or EndOfStreamException or IOException or InvalidOperationException)
        {
            return ContentSandboxContract.ExitLaunchFrameInvalid;
        }

        using (frame)
        {
            HelperFacts.Record(frame);
            if (frame.Profile != ProfileEnforcement.ThisPlatform)
            {
                return ContentSandboxContract.ExitIsolationUnavailable;
            }

            LocalRpcChildBootstrap bootstrap;
            try
            {
                bootstrap = LocalRpcChildBootstrap.FromResource(frame.BootstrapResource);
            }
            catch (Exception exception) when (exception is FormatException or ArgumentException or InvalidOperationException)
            {
                return ContentSandboxContract.ExitLaunchFrameInvalid;
            }

            using (bootstrap)
            {
                HelperResources resources;
                try
                {
                    resources = OpenResources(frame);
                }
                catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or IOException or PlatformNotSupportedException)
                {
                    await Console.Error.WriteLineAsync("inventory: " + exception.GetType().Name + ": " + exception.Message).ConfigureAwait(false);
                    return ContentSandboxContract.ExitInventoryInvalid;
                }

                await using (resources.ConfigureAwait(false))
                {
                    if (OperatingSystem.IsLinux() && !EndWithTheParent(bootstrap.Descriptor.Parent.ProcessId))
                    {
                        return ContentSandboxContract.ExitParentLost;
                    }

                    if (!ProfileEnforcement.TryApplyAndVerify(frame, bootstrap.Descriptor.Parent))
                    {
                        return ContentSandboxContract.ExitIsolationUnavailable;
                    }

                    var parentId = bootstrap.Descriptor.Parent.ProcessId;
                    Func<bool>? parentLost = OperatingSystem.IsLinux() ? () => LinuxNative.GetParentProcessId() != parentId : null;
                    return await ContentSandboxHost.RunAsync(frame, bootstrap, resources, parsers, TimeProvider.System, CancellationToken.None, parentLost: parentLost).ConfigureAwait(false);
                }
            }
        }
    }

    /// <summary>
    /// Asks the kernel to kill this process when its parent dies, then checks the parent is still there (the race between spawn and this call).
    /// The signal follows the parent thread that spawned the helper, so the parent-lost poll of the host stays as the second line; the first line on
    /// Linux is the supervising parent, which kills the process on every orderly and failed path. A wedged helper outliving a killed parent is
    /// therefore bounded by the kernel signal only, not by a Job Object as on Windows.
    /// </summary>
    private static bool EndWithTheParent(int parentId) =>
        LinuxNative.Prctl(LinuxNative.PrSetParentDeathSignal, LinuxNative.SigKill, 0, 0, 0) == 0 && LinuxNative.GetParentProcessId() == parentId;

    private static HelperResources OpenResources(ContentSandboxLaunchFrame frame)
    {
        if (OperatingSystem.IsWindows())
        {
            return OpenWindowsResources(frame);
        }

        if (OperatingSystem.IsLinux())
        {
            return LinuxResources.Open(frame);
        }

        throw new PlatformNotSupportedException("No restricted launch profile exists for this operating system.");
    }

    [SupportedOSPlatform("windows")]
    [SuppressMessage("Reliability", "CA2000", Justification = "Every wrapper is owned by the returned resources or disposed on failure below.")]
    private static HelperResources OpenWindowsResources(ContentSandboxLaunchFrame frame)
    {
        var opened = new List<IDisposable>();
        try
        {
            var control = OpenPipe(frame, ContentSandboxHandleRole.Control);
            opened.Add(control);
            var service = OpenPipe(frame, ContentSandboxHandleRole.Service);
            opened.Add(service);
            var input = WindowsMappedView.Map(Require(frame, ContentSandboxHandleRole.Input), checked((long)frame.InputLength), writable: false);
            opened.Add(input);
            var slots = new List<IHelperSlot>();
            for (var index = 0; index < frame.SlotCapacities.Count; index++)
            {
                var role = (ContentSandboxHandleRole)((int)ContentSandboxHandleRole.Slot0 + index);
                var slot = WindowsMappedView.Map(Require(frame, role), checked((long)frame.SlotCapacities[index]), writable: true);
                opened.Add(slot);
                slots.Add(slot);
            }

            return new HelperResources(control, service, input, slots);
        }
        catch
        {
            foreach (var resource in opened)
            {
                resource.Dispose();
            }

            throw;
        }
    }

    [SupportedOSPlatform("windows")]
    [SuppressMessage("Reliability", "CA2000", Justification = "The stream owns the handle and is owned by the returned resources.")]
    private static NamedPipeClientStream OpenPipe(ContentSandboxLaunchFrame frame, ContentSandboxHandleRole role)
    {
        var handle = new SafePipeHandle((nint)Require(frame, role), true);
        try
        {
            return new NamedPipeClientStream(PipeDirection.InOut, true, true, handle);
        }
        catch (ArgumentException exception)
        {
            handle.SetHandleAsInvalid();
            throw new InvalidOperationException(role + " pipe: " + exception.Message, exception);
        }
    }

    internal static ulong Require(ContentSandboxLaunchFrame frame, ContentSandboxHandleRole role) =>
        frame.TryGetHandle(role, out var value) ? value : throw new InvalidOperationException("The launch inventory lacks a resource.");
}
