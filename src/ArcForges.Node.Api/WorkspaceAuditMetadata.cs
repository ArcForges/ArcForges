// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;

namespace ArcForges.Node.Api;

/// <summary>The 06a section 6 workspace metadata transcript; this never hashes or records workspace file contents.</summary>
internal static class WorkspaceAuditMetadata
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static FileAuditMetadata ForRecords(IReadOnlyList<Workspace> records)
    {
        ArgumentNullException.ThrowIfNull(records);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long size = 0;
        void Add(ReadOnlySpan<byte> bytes)
        {
            hash.AppendData(bytes);
            size = checked(size + bytes.Length);
        }

        void AddUInt32(uint value)
        {
            Span<byte> bytes = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
            Add(bytes);
        }

        void AddText(string value)
        {
            var bytes = StrictUtf8.GetBytes(value);
            AddUInt32(checked((uint)bytes.Length));
            Add(bytes);
        }

        Add("ArcForges workspace-metadata v1\0"u8);
        foreach (var workspace in records)
        {
            if (workspace.WorkspaceId is not { Value.Length: 16 } || !workspace.HasRootPath || !workspace.HasKind ||
                !workspace.HasState || !workspace.HasName)
            {
                throw new ArgumentException("A workspace audit record must contain its ID, path, kind, state and name.", nameof(records));
            }

            Add(workspace.WorkspaceId.Value.Span);
            AddText(workspace.RootPath);
            AddUInt32((uint)workspace.Kind);
            AddUInt32((uint)workspace.State);
            AddText(workspace.Name);
        }

        return new FileAuditMetadata
        {
            Observations =
            {
                new FileAuditObservation
                {
                    Kind = FileAuditKind.WorkspaceMetadata,
                    SizeBytes = (ulong)size,
                    DigestInputBytes = (ulong)size,
                    ItemCount = checked((uint)records.Count),
                    Sha256 = ByteString.CopyFrom(hash.GetHashAndReset()),
                },
            },
        };
    }
}
