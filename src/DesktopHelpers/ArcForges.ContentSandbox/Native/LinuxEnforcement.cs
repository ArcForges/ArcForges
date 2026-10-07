// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;

namespace ArcForges.ContentSandbox.Native;

/// <summary>
/// The Linux profile of annex 24, applied by the helper to itself before it serves anything: no_new_privs, resource limits, a Landlock
/// ruleset that handles every file-system right and allows only a short read-only list, and a seccomp filter synchronised to every thread (Landlock too, with its own TSYNC flag; a kernel that refuses it ends the profile). It is
/// then verified by attempting what it must deny. A kernel without Landlock, a processor without a table, or any attempt that is not denied makes
/// the helper refuse to run a parser (exit code 70). It has not been run on Linux by the task that wrote it: only its pure parts are tested offline.
/// </summary>
[SupportedOSPlatform("linux")]
internal static class LinuxEnforcement
{
    private const int SeccompSetModeFilter = 1;
    private const uint SeccompFilterTsync = 1;
    private const int LandlockCreateRuleset = 444;
    private const int LandlockAddRule = 445;
    private const int LandlockRestrictSelf = 446;
    private const int LandlockRulePathBeneath = 1;
    private const int LandlockRestrictSelfTsync = 1 << 3;
    private const int OpenPath = 0x200000;
    private const int OpenCloseOnExec = 0x80000;
    private const int AtFdCwd = -100;
    private const ulong DataSlackBytes = 128UL * 1024 * 1024;

    /// <summary>Puts the profile in force and checks it; false means the helper must not run a parser.</summary>
    internal static bool ApplyAndVerify(ContentSandboxLaunchFrame frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        if (!OperatingSystem.IsLinux())
        {
            return false;
        }

        var architecture = SeccompProgram.Current;
        if (architecture == LinuxArchitecture.Unsupported)
        {
            return false;
        }

        if (LinuxNative.Prctl(LinuxNative.PrSetNoNewPrivs, 1, 0, 0, 0) != 0)
        {
            return false;
        }

        SetLimits(frame);
        var abi = (int)LinuxNative.Syscall(LandlockCreateRuleset, 0, 0, (nint)LandlockPlan.CreateRulesetVersion, 0, 0);
        if (abi < 1 || !ApplyLandlock(architecture, abi) || !ApplySeccomp(architecture))
        {
            return false;
        }

        return Verify(architecture);
    }

    private static void SetLimits(ContentSandboxLaunchFrame frame)
    {
        var data = frame.Limits.MaxMemoryBytes + frame.InputLength + frame.SlotCapacities.Aggregate(0UL, (sum, slot) => sum + slot) + DataSlackBytes;
        Limit(LinuxNative.RlimitCore, 0);
        Limit(LinuxNative.RlimitNofile, 256);
        Limit(LinuxNative.RlimitData, data);
    }

    private static void Limit(int resource, ulong value)
    {
        var limit = new LinuxNative.RlimitValue { Current = value, Maximum = value };
        _ = LinuxNative.SetRlimit(resource, ref limit);
    }

    private static unsafe bool ApplyLandlock(LinuxArchitecture architecture, int abi)
    {
        var handledFileSystem = LandlockPlan.HandledFileSystem(abi);
        var handledNetwork = LandlockPlan.HandledNetwork(abi);
        var attribute = stackalloc ulong[2];
        attribute[0] = handledFileSystem;
        attribute[1] = handledNetwork;
        var size = abi >= 4 ? 16 : 8;
        var ruleset = (int)LinuxNative.Syscall(LandlockCreateRuleset, (nint)attribute, size, 0, 0, 0);
        if (ruleset < 0)
        {
            return false;
        }

        try
        {
            var rule = stackalloc byte[12];
            foreach (var (path, directory) in LandlockPlan.ReadOnlyPlaces(AppContext.BaseDirectory.TrimEnd('/')))
            {
                var descriptor = OpenForRule(architecture, path);
                if (descriptor < 0)
                {
                    continue;
                }

                try
                {
                    var allowed = (directory ? LandlockPlan.Execute | LandlockPlan.ReadFile | LandlockPlan.ReadDirectory : LandlockPlan.ReadFile)
                        | (path == "/dev/null" ? LandlockPlan.WriteFile : 0);
                    allowed &= handledFileSystem;
                    *(ulong*)rule = allowed;
                    *(int*)(rule + 8) = descriptor;
                    if (LinuxNative.Syscall(LandlockAddRule, ruleset, LandlockRulePathBeneath, (nint)rule, 0, 0) != 0)
                    {
                        return false;
                    }
                }
                finally
                {
                    _ = CloseDescriptor(descriptor);
                }
            }

            // landlock_restrict_self restricts only the calling thread (and the threads it creates later) unless the TSYNC flag is given. The runtime
            // and thread pool already own threads that serve calls, so without it a parser on such a thread would be unrestricted. A kernel that
            // refuses the flag (EINVAL: no multithread Landlock) makes this fail, and the helper then refuses to run a parser.
            return LinuxNative.Syscall(LandlockRestrictSelf, ruleset, LandlockRestrictSelfTsync, 0, 0, 0) == 0;
        }
        finally
        {
            _ = CloseDescriptor(ruleset);
        }
    }

    private static int OpenForRule(LinuxArchitecture architecture, string path)
    {
        var text = Marshal.StringToCoTaskMemUTF8(path);
        try
        {
            return (int)LinuxNative.Syscall(OpenatNumber(architecture), AtFdCwd, text, OpenPath | OpenCloseOnExec, 0, 0);
        }
        finally
        {
            Marshal.FreeCoTaskMem(text);
        }
    }

    private static int CloseDescriptor(int descriptor) => (int)LinuxNative.Syscall(3, descriptor, 0, 0, 0, 0);

    private static unsafe bool ApplySeccomp(LinuxArchitecture architecture)
    {
        var bytes = SeccompProgram.Serialize(SeccompProgram.Build(architecture, Environment.ProcessId));
        var filter = (byte*)NativeMemory.Alloc((nuint)bytes.Length);
        try
        {
            bytes.CopyTo(new Span<byte>(filter, bytes.Length));
            var program = stackalloc byte[16];
            *(ushort*)program = (ushort)(bytes.Length / 8);
            *(nint*)(program + 8) = (nint)filter;
            return LinuxNative.Syscall(SeccompProgram.SeccompCall(architecture), SeccompSetModeFilter, (nint)SeccompFilterTsync, (nint)program, 0, 0) == 0;
        }
        finally
        {
            NativeMemory.Free(filter);
        }
    }

    /// <summary>Attempts a socket, a program execution, a trace and a read outside the allowlist: every one must be denied.</summary>
    [SuppressMessage("Maintainability", "CA1508", Justification = "The results are read after native calls.")]
    private static bool Verify(LinuxArchitecture architecture)
    {
        if (LinuxNative.Prctl(LinuxNative.PrGetNoNewPrivs, 0, 0, 0, 0) != 1)
        {
            return false;
        }

        var x64 = architecture == LinuxArchitecture.X64;
        var socket = LinuxNative.Syscall(x64 ? 41 : 198, 2, 1, 0, 0, 0);
        var socketError = Marshal.GetLastPInvokeError();
        var ptrace = LinuxNative.Syscall(x64 ? 101 : 117, 0, 0, 0, 0, 0);
        var ptraceError = Marshal.GetLastPInvokeError();
        var program = Marshal.StringToCoTaskMemUTF8("/proc/self/exe");
        nint execute;
        int executeError;
        try
        {
            execute = LinuxNative.Syscall(x64 ? 59 : 221, program, 0, 0, 0, 0);
            executeError = Marshal.GetLastPInvokeError();
        }
        finally
        {
            Marshal.FreeCoTaskMem(program);
        }

        return socket == -1 && socketError == LinuxNative.Eperm
            && ptrace == -1 && ptraceError == LinuxNative.Eperm
            && execute == -1 && executeError == LinuxNative.Eperm
            && OpenOutsideIsDeniedOnEveryKindOfThread(architecture);
    }

    /// <summary>
    /// Landlock is per thread unless synchronised, so the denial is observed from the applying thread, from a thread the runtime created before
    /// the restriction (thread-pool workers, several at once) and from a thread created afterwards.
    /// </summary>
    private static bool OpenOutsideIsDeniedOnEveryKindOfThread(LinuxArchitecture architecture)
    {
        if (!OpenOutsideIsDenied(architecture))
        {
            return false;
        }

        var pool = new Task<bool>[8];
        for (var i = 0; i < pool.Length; i++)
        {
            pool[i] = Task.Run(() => OpenOutsideIsDenied(architecture));
        }

        var fresh = false;
        var thread = new Thread(() => fresh = OpenOutsideIsDenied(architecture)) { IsBackground = true };
        thread.Start();
        var finished = thread.Join(5000);
        var allPool = true;
        foreach (var task in pool)
        {
            allPool &= task.Wait(5000) && task.Result;
        }

        return finished && fresh && allPool;
    }

    private static bool OpenOutsideIsDenied(LinuxArchitecture architecture)
    {
        var outside = Marshal.StringToCoTaskMemUTF8("/etc/passwd");
        try
        {
            var opened = LinuxNative.Syscall(OpenatNumber(architecture), AtFdCwd, outside, 0, 0, 0);
            var error = Marshal.GetLastPInvokeError();
            if (opened >= 0)
            {
                _ = CloseDescriptor((int)opened);
            }

            return opened == -1 && error == LinuxNative.Eacces;
        }
        finally
        {
            Marshal.FreeCoTaskMem(outside);
        }
    }

    private static int OpenatNumber(LinuxArchitecture architecture) => architecture == LinuxArchitecture.X64 ? 257 : 56;
}
