// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace ArcForges.ContentSandbox.Host;

/// <summary>The processor families the Linux profile has system call tables for. Any other processor refuses to run a parser.</summary>
internal enum LinuxArchitecture
{
    /// <summary>No table: the profile is unavailable.</summary>
    Unsupported = 0,

    /// <summary>x86-64.</summary>
    X64 = 1,

    /// <summary>64-bit Arm.</summary>
    Arm64 = 2,
}

/// <summary>One classic BPF instruction of a seccomp filter.</summary>
/// <param name="Code">The opcode.</param>
/// <param name="JumpTrue">The forward jump when the test holds.</param>
/// <param name="JumpFalse">The forward jump when it does not.</param>
/// <param name="Argument">The immediate operand.</param>
internal readonly record struct BpfInstruction(ushort Code, byte JumpTrue, byte JumpFalse, uint Argument);

/// <summary>
/// The seccomp filter of the Linux content profile. It is a deny list over the call classes a hostile parser has no business using: creating
/// network sockets or connecting them (transfers on the two inherited sockets stay possible), creating processes, executing programs, tracing, signalling (kill, tkill, pidfd) and reading other processes, changing mounts and namespaces,
/// loading kernel code, and the asynchronous and keyring interfaces that widen the kernel surface. Thread creation stays possible (a
/// <c>clone</c> with <c>CLONE_THREAD</c>), and <c>clone3</c>, whose flags the filter cannot read, answers "not implemented" so the C library
/// falls back to <c>clone</c>. A denied call fails with <c>EPERM</c> rather than killing the process, so the helper's own self-check can observe it.
/// The filter checks the architecture first and kills the process on a foreign one, and on x86-64 denies every call number with the x32 bit set. Not covered: tgkill (the runtime needs it to suspend its own threads) can still signal another process of the same user, and there is no PID, user or mount namespace. The numbers are the kernel's own, per processor family.
/// </summary>
internal static class SeccompProgram
{
    internal const uint AuditArchX64 = 0xC000003E;
    internal const uint AuditArchArm64 = 0xC00000B7;
    internal const uint RetAllow = 0x7FFF0000;
    internal const uint RetKillProcess = 0x80000000;
    internal const uint RetErrnoEperm = 0x00050001;
    internal const uint RetErrnoEnosys = 0x00050026;
    internal const uint CloneThread = 0x00010000;
    internal const uint X32Bit = 0x40000000;

    private const ushort LoadAbsolute = 0x20;
    private const ushort JumpEqual = 0x15;
    private const ushort JumpSet = 0x45;
    private const ushort Return = 0x06;
    private const uint OffsetNumber = 0;
    private const uint OffsetArchitecture = 4;
    private const uint OffsetArgument0 = 16;

    /// <summary>The processor family of this process, or <see cref="LinuxArchitecture.Unsupported"/>.</summary>
    internal static LinuxArchitecture Current => RuntimeInformation.ProcessArchitecture switch
    {
        Architecture.X64 => LinuxArchitecture.X64,
        Architecture.Arm64 => LinuxArchitecture.Arm64,
        _ => LinuxArchitecture.Unsupported,
    };

    /// <summary>The system call numbers the filter denies on a processor family (without <c>clone</c> and <c>clone3</c>, which are special).</summary>
    internal static IReadOnlyList<uint> Denied(LinuxArchitecture architecture) => architecture switch
    {
        LinuxArchitecture.X64 =>
        [
            41, 42, 43, 49, 50, 53, // socket connect accept bind listen socketpair
            62, 200, 424, 434, 438, // kill tkill pidfd_send_signal pidfd_open pidfd_getfd (signalling or taking descriptors from another process)
            57, 58, 59, 322, // fork vfork execve execveat
            101, 310, 311, // ptrace process_vm_readv process_vm_writev
            155, 161, 165, 166, // pivot_root chroot mount umount2
            175, 176, 313, 246, // init_module delete_module finit_module kexec_load
            248, 249, 250, // add_key request_key keyctl
            272, 308, // unshare setns
            288, // accept4
            298, 321, 323, 304, // perf_event_open bpf userfaultfd open_by_handle_at
            425, 426, 427, // io_uring_setup io_uring_enter io_uring_register
        ],
        LinuxArchitecture.Arm64 =>
        [
            198, 199, 200, 201, 202, 203, // socket socketpair bind listen accept connect
            129, 130, 424, 434, 438, // kill tkill pidfd_send_signal pidfd_open pidfd_getfd
            221, 281, // execve execveat
            117, 270, 271, // ptrace process_vm_readv process_vm_writev
            41, 51, 40, 39, // pivot_root chroot mount umount2
            105, 106, 273, 104, // init_module delete_module finit_module kexec_load
            217, 218, 219, // add_key request_key keyctl
            97, 268, // unshare setns
            242, // accept4
            241, 280, 282, 265, // perf_event_open bpf userfaultfd open_by_handle_at
            425, 426, 427, // io_uring_setup io_uring_enter io_uring_register
        ],
        _ => throw new PlatformNotSupportedException("No seccomp table exists for this processor."),
    };

    /// <summary>The number of <c>clone</c> on a processor family.</summary>
    internal static uint Clone(LinuxArchitecture architecture) => architecture == LinuxArchitecture.X64 ? 56u : 220u;

    /// <summary>The <c>seccomp</c> system call number on a processor family.</summary>
    internal static int SeccompCall(LinuxArchitecture architecture) => architecture == LinuxArchitecture.X64 ? 317 : 277;

    /// <summary>Builds the filter program for a processor family; every jump is computed from instruction positions.</summary>
    internal static IReadOnlyList<BpfInstruction> Build(LinuxArchitecture architecture)
    {
        var denied = Denied(architecture);
        var audit = architecture == LinuxArchitecture.X64 ? AuditArchX64 : AuditArchArm64;
        var list = new List<BpfInstruction>
        {
            new(LoadAbsolute, 0, 0, OffsetArchitecture),
            new(JumpEqual, 1, 0, audit),
            new(Return, 0, 0, RetKillProcess),
            new(LoadAbsolute, 0, 0, OffsetNumber),
        };
        var x32Test = -1;
        if (architecture == LinuxArchitecture.X64)
        {
            // The x32 ABI shares the architecture value but numbers its calls from 0x40000000: those would bypass every number below.
            x32Test = list.Count;
            list.Add(new BpfInstruction(JumpSet, 0, 0, X32Bit));
        }

        var firstTest = list.Count;
        var cloneTest = firstTest + denied.Count;
        var clone3Test = cloneTest + 1;
        var threadLoad = clone3Test + 1;
        var threadTest = threadLoad + 1;
        var allow = threadTest + 1;
        var deny = allow + 1;
        var enosys = deny + 1;
        if (x32Test >= 0)
        {
            list[x32Test] = new BpfInstruction(JumpSet, Jump(x32Test, deny), 0, X32Bit);
        }

        for (var index = 0; index < denied.Count; index++)
        {
            list.Add(new BpfInstruction(JumpEqual, Jump(firstTest + index, deny), 0, denied[index]));
        }

        // clone: inspect the flags. A call that creates a thread passes; anything else is a process and is denied. clone3 cannot be inspected.
        list.Add(new BpfInstruction(JumpEqual, Jump(cloneTest, threadLoad), 0, Clone(architecture)));
        list.Add(new BpfInstruction(JumpEqual, Jump(clone3Test, enosys), Jump(clone3Test, allow), 435));
        list.Add(new BpfInstruction(LoadAbsolute, 0, 0, OffsetArgument0));
        list.Add(new BpfInstruction(JumpSet, Jump(threadTest, allow), Jump(threadTest, deny), CloneThread));
        list.Add(new BpfInstruction(Return, 0, 0, RetAllow));
        list.Add(new BpfInstruction(Return, 0, 0, RetErrnoEperm));
        list.Add(new BpfInstruction(Return, 0, 0, RetErrnoEnosys));
        return list;
    }

    private static byte Jump(int from, int to) => checked((byte)(to - from - 1));

    /// <summary>The program as the kernel reads it: eight bytes per instruction in native (little-endian) order.</summary>
    internal static byte[] Serialize(IReadOnlyList<BpfInstruction> program)
    {
        ArgumentNullException.ThrowIfNull(program);
        var bytes = new byte[program.Count * 8];
        for (var index = 0; index < program.Count; index++)
        {
            var span = bytes.AsSpan(index * 8, 8);
            BinaryPrimitives.WriteUInt16LittleEndian(span, program[index].Code);
            span[2] = program[index].JumpTrue;
            span[3] = program[index].JumpFalse;
            BinaryPrimitives.WriteUInt32LittleEndian(span[4..], program[index].Argument);
        }

        return bytes;
    }
}

/// <summary>The Landlock ruleset of the Linux content profile: every file-system right the kernel supports is handled, so nothing outside the allowlist is reachable.</summary>
internal static class LandlockPlan
{
    internal const uint CreateRulesetVersion = 1;
    internal const ulong Execute = 1UL << 0;
    internal const ulong WriteFile = 1UL << 1;
    internal const ulong ReadFile = 1UL << 2;
    internal const ulong ReadDirectory = 1UL << 3;
    internal const ulong BindTcp = 1UL << 0;
    internal const ulong ConnectTcp = 1UL << 1;

    /// <summary>The file-system rights an ABI version can handle: 13 from the first, refer from 2, truncate from 3, device ioctl from 5.</summary>
    internal static ulong HandledFileSystem(int abi) =>
        abi < 1 ? 0
        : (1UL << 13) - 1
            | (abi >= 2 ? 1UL << 13 : 0)
            | (abi >= 3 ? 1UL << 14 : 0)
            | (abi >= 5 ? 1UL << 15 : 0);

    /// <summary>The network rights an ABI version can handle: TCP bind and connect from the fourth.</summary>
    internal static ulong HandledNetwork(int abi) => abi >= 4 ? BindTcp | ConnectTcp : 0;

    /// <summary>
    /// The read-only places a helper may open: its own directory, the system libraries a loader needs, and the few virtual files the runtime
    /// reads at start. Nothing here is writable and nothing is a product, user or credential location.
    /// </summary>
    internal static IReadOnlyList<(string Path, bool Directory)> ReadOnlyPlaces(string helperDirectory) =>
    [
        (helperDirectory, true),
        ("/lib", true),
        ("/lib64", true),
        ("/usr/lib", true),
        ("/usr/lib64", true),
        ("/proc/self", true),
        ("/proc/sys/kernel/random", true),
        ("/sys/devices/system/cpu", true),
        ("/sys/fs/cgroup", true),
        ("/dev/urandom", false),
        ("/dev/null", false),
    ];
}
