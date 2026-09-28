// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using Xunit;

namespace ArcForges.Persistence.Resources.Tests;

public sealed class ManagedResourceStoreTests
{
    [Fact]
    public void ContentIsAddressedByHashButResolvedOnlyThroughBlobId()
    {
        using var fixture = new StoreDirectory();
        using var store = ManagedResourceStore.Open(fixture.Root);

        byte[] content = [4, 8, 15, 16, 23, 42];
        BlobId first = store.Store(content);
        BlobId second = store.Store(content);

        Assert.NotEqual(first, second);
        Assert.Equal(content, store.Read(first));
        Assert.Equal(content, store.Read(second));
        Assert.Single(Directory.EnumerateFiles(Path.Combine(fixture.Root, "objects"), "*.blob", SearchOption.AllDirectories));
        Assert.Throws<KeyNotFoundException>(() => store.Read(new BlobId(Guid.NewGuid())));
    }

    [Fact]
    public void EveryReadChecksLengthAndContentDigest()
    {
        using var fixture = new StoreDirectory();
        using var store = ManagedResourceStore.Open(fixture.Root);
        BlobId id = store.Store([1, 2, 3, 4]);
        string objectPath = Directory.EnumerateFiles(Path.Combine(fixture.Root, "objects"), "*.blob", SearchOption.AllDirectories).Single();

        File.WriteAllBytes(objectPath, [1, 2, 3, 5]);

        Assert.Throws<InvalidDataException>(() => store.Read(id));
    }

    [Fact]
    public void ReferenceCountComesFromReferrerRowsAndGcPreservesSharedLiveObjects()
    {
        using var fixture = new StoreDirectory();
        using var store = ManagedResourceStore.Open(fixture.Root);
        byte[] content = [10, 20, 30];
        BlobId live = store.Store(content);
        BlobId unreferencedAlias = store.Store(content);

        store.AddReference("session/one", live);
        store.AddReference("session/one", live);
        store.AddReference("capture/two", live);
        Assert.Equal(2, store.ReferenceCount(live));
        Assert.Equal(0, store.ReferenceCount(unreferencedAlias));
        Assert.Throws<KeyNotFoundException>(() => store.AddReference("future/ref", new BlobId(Guid.NewGuid())));

        Assert.True(store.RemoveReference("session/one", live));
        Assert.False(store.RemoveReference("session/one", live));
        Assert.Equal(1, store.ReferenceCount(live));

        var firstCollection = store.CollectGarbage();
        Assert.Equal(1, firstCollection.RemovedIdentities);
        Assert.Equal(0, firstCollection.RemovedObjects);
        Assert.Equal(content, store.Read(live));
        Assert.Single(Directory.EnumerateFiles(Path.Combine(fixture.Root, "objects"), "*.blob", SearchOption.AllDirectories));

        Assert.True(store.RemoveReference("capture/two", live));
        Assert.Equal(0, store.ReferenceCount(live));
        var finalCollection = store.CollectGarbage();
        Assert.Equal(1, finalCollection.RemovedIdentities);
        Assert.Equal(1, finalCollection.RemovedObjects);
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(fixture.Root, "objects"), "*.blob", SearchOption.AllDirectories));
        Assert.Throws<KeyNotFoundException>(() => store.Read(live));
    }

    [Fact]
    public void InterruptionBeforeIdentityPublicationLeavesOnlyAReclaimableOrphan()
    {
        using var fixture = new StoreDirectory();
        BlobId interruptedId = default;
        using (var interrupted = ManagedResourceStore.OpenForTesting(fixture.Root, (point, id) =>
        {
            if (point != ResourceStoreFaultPoint.ObjectCommitted) return;
            interruptedId = id;
            throw new InvalidOperationException("simulated interruption");
        }))
        {
            Assert.Throws<InvalidOperationException>(() => interrupted.Store([5, 4, 3], "unpublished/ref"));
        }

        using var recovered = ManagedResourceStore.Open(fixture.Root);
        Assert.Throws<KeyNotFoundException>(() => recovered.Read(interruptedId));
        var collected = recovered.CollectGarbage();
        Assert.Equal(0, collected.RemovedIdentities);
        Assert.Equal(1, collected.RemovedObjects);
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(fixture.Root, "objects"), "*.blob", SearchOption.AllDirectories));
    }

    [Fact]
    public void InterruptionAfterReferencePublicationKeepsTheObjectAndReferenceTogether()
    {
        using var fixture = new StoreDirectory();
        BlobId committedId = default;
        byte[] content = [9, 7, 5, 3, 1];
        using (var interrupted = ManagedResourceStore.OpenForTesting(fixture.Root, (point, id) =>
        {
            if (point != ResourceStoreFaultPoint.ReferenceCommitted) return;
            committedId = id;
            throw new InvalidOperationException("simulated interruption");
        }))
        {
            Assert.Throws<InvalidOperationException>(() => interrupted.Store(content, "project/current"));
        }

        using var recovered = ManagedResourceStore.Open(fixture.Root);
        Assert.Equal(content, recovered.Read(committedId));
        Assert.Equal(1, recovered.ReferenceCount(committedId));
        var collected = recovered.CollectGarbage();
        Assert.Equal(0, collected.RemovedIdentities);
        Assert.Equal(0, collected.RemovedObjects);
    }

    [Fact]
    public void InterruptionDuringCollectionCanOnlyLeaveOrphanObjects()
    {
        using var fixture = new StoreDirectory();
        byte[] liveContent = [1, 1, 1];
        byte[] deadContent = [2, 2, 2];
        BlobId live;
        BlobId dead;
        using (var store = ManagedResourceStore.Open(fixture.Root))
        {
            live = store.Store(liveContent, "owner/live");
            dead = store.Store(deadContent);
        }

        using (var interrupted = ManagedResourceStore.OpenForTesting(fixture.Root, (point, _) =>
        {
            if (point == ResourceStoreFaultPoint.GarbageCollectionMappingsRemoved)
                throw new InvalidOperationException("simulated interruption");
        }))
        {
            Assert.Throws<InvalidOperationException>(() => interrupted.CollectGarbage());
        }

        using var recovered = ManagedResourceStore.Open(fixture.Root);
        Assert.Equal(liveContent, recovered.Read(live));
        Assert.Equal(1, recovered.ReferenceCount(live));
        Assert.Throws<KeyNotFoundException>(() => recovered.Read(dead));
        var completed = recovered.CollectGarbage();
        Assert.Equal(0, completed.RemovedIdentities);
        Assert.Equal(1, completed.RemovedObjects);
        Assert.Equal(liveContent, recovered.Read(live));
    }

    [Fact]
    public void DisposeFencesOperationsAndReleasesRootOwnership()
    {
        using var fixture = new StoreDirectory();
        var store = ManagedResourceStore.Open(fixture.Root);
        byte[] content = [31, 41, 59];
        BlobId id = store.Store(content);

        store.Dispose();
        store.Dispose();

        Assert.Throws<ObjectDisposedException>(() => store.Read(id));
        using var reopened = ManagedResourceStore.Open(fixture.Root);
        Assert.Equal(content, reopened.Read(id));
    }

    private sealed class StoreDirectory : IDisposable
    {
        public StoreDirectory()
        {
            Root = Path.Combine(Path.GetTempPath(), "arcf-store-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public void Dispose()
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }
}
