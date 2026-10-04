// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.ContentSandbox.Broker.Linux;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.ContentSandbox.Host;
using Xunit;

namespace ArcForges.ContentSandbox.Tests;

/// <summary>
/// The pure parts of the Linux profile, checked offline on any host: the seccomp program is run by a small classic-BPF interpreter against the
/// call numbers it must deny and the ones it must allow, the Landlock plan and the spawn plan are checked as data. None of this applies a
/// restriction to a process, and nothing here shows that a Linux kernel enforces the profile: that needs the profile run on Linux, which this
/// task did not do.
/// </summary>
public sealed class LinuxProfileTests
{
    private const uint Eperm = SeccompProgram.RetErrnoEperm;

    private static uint Run(IReadOnlyList<BpfInstruction> program, uint architecture, uint number, ulong argument0 = 0)
    {
        uint accumulator = 0;
        var counter = 0;
        for (var steps = 0; steps < 10_000; steps++)
        {
            var instruction = program[counter];
            switch (instruction.Code)
            {
                case 0x20:
                    accumulator = instruction.Argument switch
                    {
                        0 => number,
                        4 => architecture,
                        16 => (uint)argument0,
                        _ => throw new InvalidOperationException("The filter reads only the number, the architecture and the first argument."),
                    };
                    counter++;
                    break;
                case 0x15:
                    counter += 1 + (accumulator == instruction.Argument ? instruction.JumpTrue : instruction.JumpFalse);
                    break;
                case 0x45:
                    counter += 1 + ((accumulator & instruction.Argument) != 0 ? instruction.JumpTrue : instruction.JumpFalse);
                    break;
                case 0x06:
                    return instruction.Argument;
                default:
                    throw new InvalidOperationException("Unknown opcode " + instruction.Code);
            }
        }

        throw new InvalidOperationException("The filter did not terminate.");
    }

    public static TheoryData<string> Architectures => new() { "X64", "Arm64" };

    private static (LinuxArchitecture Architecture, uint Audit) Resolve(string name) =>
        name == "X64" ? (LinuxArchitecture.X64, SeccompProgram.AuditArchX64) : (LinuxArchitecture.Arm64, SeccompProgram.AuditArchArm64);

    [Theory]
    [MemberData(nameof(Architectures))]
    public void EveryDeniedCallFailsWithPermissionDeniedAndEveryOtherCallPasses(string name)
    {
        var (architecture, audit) = Resolve(name);
        var program = SeccompProgram.Build(architecture);
        var denied = SeccompProgram.Denied(architecture);
        Assert.Equal(denied.Count, denied.Distinct().Count());
        foreach (var number in denied)
        {
            Assert.Equal(Eperm, Run(program, audit, number));
        }

        foreach (var number in Enumerable.Range(0, 450).Select(value => (uint)value).Except(denied)
            .Where(value => value != SeccompProgram.Clone(architecture) && value != 435))
        {
            Assert.Equal(SeccompProgram.RetAllow, Run(program, audit, number));
        }
    }

    [Theory]
    [MemberData(nameof(Architectures))]
    public void AForeignArchitectureKillsTheProcess(string name)
    {
        var (architecture, audit) = Resolve(name);
        var program = SeccompProgram.Build(architecture);
        Assert.Equal(SeccompProgram.RetKillProcess, Run(program, audit ^ 0x1, 0));
        Assert.Equal(SeccompProgram.RetKillProcess, Run(program, name == "X64" ? SeccompProgram.AuditArchArm64 : SeccompProgram.AuditArchX64, 0));
    }

    [Theory]
    [MemberData(nameof(Architectures))]
    public void ThreadsMayBeCreatedButProcessesMayNot(string name)
    {
        var (architecture, audit) = Resolve(name);
        var program = SeccompProgram.Build(architecture);
        var clone = SeccompProgram.Clone(architecture);
        Assert.Equal(SeccompProgram.RetAllow, Run(program, audit, clone, SeccompProgram.CloneThread | 0x100));
        Assert.Equal(Eperm, Run(program, audit, clone, 0x11));
        Assert.Equal(Eperm, Run(program, audit, clone, 0));
        Assert.Equal(SeccompProgram.RetErrnoEnosys, Run(program, audit, 435));
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(9u)]
    [InlineData(202u)]
    [InlineData(232u)]
    [InlineData(257u)]
    [InlineData(318u)]
    [InlineData(231u)]
    public void TheCallsAManagedRuntimeNeedsOnX64StayAllowed(uint number) =>
        Assert.Equal(SeccompProgram.RetAllow, Run(SeccompProgram.Build(LinuxArchitecture.X64), SeccompProgram.AuditArchX64, number));

    [Fact]
    public void TheDeniedClassesAreTheNetworkProcessTraceMountKernelAndKeyringOnes()
    {
        var x64 = SeccompProgram.Denied(LinuxArchitecture.X64);
        foreach (var number in new uint[] { 41, 42, 49, 50, 59, 57, 101, 165, 175, 250, 308, 321, 425 })
        {
            Assert.Contains(number, x64);
        }

        // Data transfer on the two inherited sockets is not creation of a socket and must stay possible.
        foreach (var number in new uint[] { 44, 45, 46, 47 })
        {
            Assert.DoesNotContain(number, x64);
        }

        var arm = SeccompProgram.Denied(LinuxArchitecture.Arm64);
        foreach (var number in new uint[] { 198, 203, 221, 117, 40, 105, 219, 97, 280, 425 })
        {
            Assert.Contains(number, arm);
        }

        foreach (var number in new uint[] { 206, 207, 211, 212 })
        {
            Assert.DoesNotContain(number, arm);
        }
    }

    [Fact]
    public void AProgramIsSerializedAsEightByteLittleEndianInstructions()
    {
        var program = SeccompProgram.Build(LinuxArchitecture.X64);
        var bytes = SeccompProgram.Serialize(program);
        Assert.Equal(program.Count * 8, bytes.Length);
        Assert.Equal([0x20, 0x00, 0, 0, 4, 0, 0, 0], bytes[..8]);
        Assert.True(program.Count < 4096);
        Assert.Equal(1, SeccompProgram.SeccompCall(LinuxArchitecture.X64) == 317 && SeccompProgram.SeccompCall(LinuxArchitecture.Arm64) == 277 ? 1 : 0);
    }

    [Fact]
    public void LandlockHandlesEveryRightTheKernelOffersAndAllowsOnlyAShortReadOnlyList()
    {
        Assert.Equal(0UL, LandlockPlan.HandledFileSystem(0));
        Assert.Equal((1UL << 13) - 1, LandlockPlan.HandledFileSystem(1));
        Assert.Equal((1UL << 14) - 1, LandlockPlan.HandledFileSystem(2));
        Assert.Equal((1UL << 15) - 1, LandlockPlan.HandledFileSystem(3));
        Assert.Equal((1UL << 15) - 1, LandlockPlan.HandledFileSystem(4));
        Assert.Equal((1UL << 16) - 1, LandlockPlan.HandledFileSystem(5));
        Assert.Equal(0UL, LandlockPlan.HandledNetwork(3));
        Assert.Equal(LandlockPlan.BindTcp | LandlockPlan.ConnectTcp, LandlockPlan.HandledNetwork(4));

        var places = LandlockPlan.ReadOnlyPlaces("/opt/arcforges/helper");
        Assert.Contains(places, place => place.Path == "/opt/arcforges/helper" && place.Directory);
        Assert.DoesNotContain(places, place => place.Path is "/" or "/home" or "/etc" or "/tmp" or "/root" or "/var" or "/usr");
        Assert.All(places, place => Assert.StartsWith("/", place.Path, StringComparison.Ordinal));
        Assert.True(places.Count < 20);
    }

    [Fact]
    public void TheSpawnPlanGivesTheChildTheClosedInventoryAtFixedNumbersAndNothingElse()
    {
        var plan = LinuxLaunchPlan.TargetPlan(3);
        Assert.Equal(
            [
                (ContentSandboxHandleRole.Control, 3),
                (ContentSandboxHandleRole.Service, 4),
                (ContentSandboxHandleRole.Input, 5),
                (ContentSandboxHandleRole.Slot0, 6),
                (ContentSandboxHandleRole.Slot1, 7),
                (ContentSandboxHandleRole.Slot2, 8),
            ],
            plan);
        Assert.Equal(plan.Count, plan.Select(item => item.Target).Distinct().Count());
        Assert.Equal(4, LinuxLaunchPlan.TargetPlan(1).Count);
        var environment = LinuxLaunchPlan.Environment(new ContentSandboxLimits { MaxMemoryBytes = 512UL * 1024 * 1024 });
        Assert.Equal(["DOTNET_gcServer=0", "DOTNET_GCHeapHardLimit=20000000"], environment);
    }
}
