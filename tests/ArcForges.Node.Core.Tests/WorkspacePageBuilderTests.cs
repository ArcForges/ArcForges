// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Api;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed class WorkspacePageBuilderTests
{
    [Fact]
    public void ActualSerializedBoundaryHasLosslessNodeAndFilterBoundContinuations()
    {
        var node = Enumerable.Repeat((byte)7, 16).ToArray();
        var key = Enumerable.Repeat((byte)11, 32).ToArray();
        var records = Enumerable.Range(0, 130).Select(i =>
        {
            var id = new byte[16];
            id[14] = (byte)(i >> 8);
            id[15] = (byte)i;
            return new Workspace
            {
                WorkspaceId = new Id { Value = ByteString.CopyFrom(id) },
                RootPath = "/" + new string('x', 4040) + "/" + i.ToString(System.Globalization.CultureInfo.InvariantCulture),
                Kind = WorkspaceKind.Registered,
                State = WorkspaceState.Active,
                Name = "test",
            };
        }).ToArray();

        var seen = new List<Workspace>();
        var start = 0;
        do
        {
            var response = WorkspacePageBuilder.Build(new ResponseMeta(), records[start..], more: false, node, kinds: 1, revision: 19, key);
            Assert.True(response.CalculateSize() <= 131_072);
            Assert.NotEmpty(response.Value.Workspaces);
            Assert.Equal(WorkspaceAuditMetadata.ForRecords(response.Value.Workspaces), response.Audit);
            seen.AddRange(response.Value.Workspaces);
            start = seen.Count;
            if (!response.Value.Page.HasMore)
            {
                Assert.False(response.Value.Page.HasNextCursor);
                break;
            }

            Assert.True(WorkspacePageBuilder.TryCursor(response.Value.Page.NextCursor, node, 1, key, out var after, out var revision));
            Assert.Equal(seen[^1].WorkspaceId.Value.ToByteArray(), after);
            Assert.Equal(19, revision);
            Assert.False(WorkspacePageBuilder.TryCursor(response.Value.Page.NextCursor, node, 3, key, out _, out _));
            Assert.False(WorkspacePageBuilder.TryCursor(response.Value.Page.NextCursor, new byte[16], 1, key, out _, out _));
            Assert.False(WorkspacePageBuilder.TryCursor(response.Value.Page.NextCursor + "A", node, 1, key, out _, out _));
        }
        while (true);

        Assert.Equal(records.Select(item => item.WorkspaceId), seen.Select(item => item.WorkspaceId));
        Assert.True(start > 0 && start == records.Length);
    }

    [Fact]
    public void EmptyAndExplicitlyContinuedPagesCarryExactMetadata()
    {
        var node = Enumerable.Repeat((byte)9, 16).ToArray();
        var key = Enumerable.Repeat((byte)12, 32).ToArray();
        var empty = WorkspacePageBuilder.Build(new ResponseMeta(), [], false, node, 7, 0, key);
        Assert.False(empty.Value.Page.HasMore);
        Assert.Equal(WorkspaceAuditMetadata.ForRecords([]), empty.Audit);
        Assert.Equal("1de557e721f721d6eac4ba416d41ffac5139c3fcf98833301a375c39b5df0757",
            Convert.ToHexStringLower(empty.Audit.Observations[0].Sha256.Span));
        Assert.Throws<ArgumentException>(() => WorkspacePageBuilder.Build(new ResponseMeta(), [], true, node, 7, 0, key));
    }
}
