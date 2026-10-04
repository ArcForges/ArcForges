// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using ArcForges.Contracts.LocalRpc.Sandbox.V1;

namespace ArcForges.ContentSandbox.Contracts;

/// <summary>
/// The fixed facts of the private parent-to-helper contract. This project is a thin facade: every message and service is the
/// generated <c>ArcForges.Contracts.LocalRpc.Sandbox</c> (and bootstrap <c>.Platform</c>) binding, and nothing here is a second
/// wire type or a second schema owner.
/// </summary>
public static class ContentSandboxContract
{
    /// <summary>The private protocol version of the parent-to-helper launch (annex 09).</summary>
    public const uint ProtocolVersion = 1;

    /// <summary>The most output slots one invocation provisions.</summary>
    public const int MaxSlots = 3;

    /// <summary>The largest output slot (64 MiB).</summary>
    public const long MaxSlotBytes = 64L * 1024 * 1024;

    /// <summary>The generated method that renews the session lease; it is declared a reserved lease-renewal control method.</summary>
    public const string RenewSessionMethod = "RenewSession";

    /// <summary>The generated method that cancels a session; it is declared a reserved cancellation control method.</summary>
    public const string CancelSessionMethod = "CancelSession";

    /// <summary>The longest parser-profile identifier the launch carries.</summary>
    public const int MaxParserProfileLength = 64;

    /// <summary>The helper ended normally after its session was closed.</summary>
    public const int ExitClean = 0;

    /// <summary>The launch frame was malformed or for another profile family.</summary>
    public const int ExitLaunchFrameInvalid = 64;

    /// <summary>An inherited resource was missing, unusable or not of the closed inventory.</summary>
    public const int ExitInventoryInvalid = 65;

    /// <summary>The helper could not enforce or verify its operating-system profile and refused to run a parser.</summary>
    public const int ExitIsolationUnavailable = 70;

    /// <summary>The helper failed in a way that is not one of the other codes.</summary>
    public const int ExitInternalFailure = 71;

    /// <summary>The parent was lost: its stream closed or its registration lease could not be kept.</summary>
    public const int ExitParentLost = 75;

    /// <summary>The session lease passed without a renewal.</summary>
    public const int ExitSessionExpired = 76;

    /// <summary>A parser call ignored its cancellation and its deadline, so the helper left the process.</summary>
    public const int ExitParserHung = 77;

    private static readonly byte[] SetDigest = ComputeContractSetDigest();

    /// <summary>The full protobuf name of the generated service the helper serves.</summary>
    public static string ServiceName => ContentSandboxService.Descriptor.FullName;

    /// <summary>
    /// The SHA-256 digest of the generated contract set both sides were built against: the serialized descriptors of the sandbox
    /// and bootstrap contracts, each length-prefixed. A parent and a helper built from different generated sets cannot register.
    /// </summary>
    public static ReadOnlyMemory<byte> ContractSetDigest => SetDigest;

    private static byte[] ComputeContractSetDigest()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("arcforges.contentsandbox.contractset.v1\n"u8);
        Span<byte> length = stackalloc byte[4];
        foreach (var serialized in new[]
        {
            ContentSandboxService.Descriptor.File.SerializedData,
            LocalBootstrapService.Descriptor.File.SerializedData,
        })
        {
            BinaryPrimitives.WriteUInt32BigEndian(length, (uint)serialized.Length);
            hash.AppendData(length);
            hash.AppendData(serialized.Span);
        }

        return hash.GetHashAndReset();
    }

    internal static byte[] Utf8(string value) => Encoding.UTF8.GetBytes(value);
}
