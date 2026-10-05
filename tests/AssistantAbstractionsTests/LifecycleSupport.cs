// SPDX-License-Identifier: AGPL-3.0-only
#pragma warning disable CA2007 // Test code has no synchronization context to preserve.
#pragma warning disable xUnit1051 // These tests deliberately exercise the default (no token) and explicit-cancellation paths.
#pragma warning disable CA1849 // The test store and log use synchronous durable writes like a simple real store.
#pragma warning disable CA2000 // Test doubles here own no unmanaged resources.
#pragma warning disable CA1859 // Tests deliberately use the port interfaces to exercise their contracts.
using System.Globalization;
using System.Text;
using ArcForges.Assistant.Abstractions;
using ArcForges.Foundation.Errors;

namespace AssistantAbstractionsTests;

/// <summary>A unique scratch directory removed after the test; the stand-in for a profile's local data directory.</summary>
internal sealed class ScratchDirectory : IDisposable
{
    public ScratchDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ArcForgesAssistantLifecycle", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup of a temp directory.
        }
    }
}

/// <summary>
/// Test-only durable draft store. It follows the port's contract with a real file system: a revision is written to a
/// temporary file and moved over the previous one, so a crash between the two steps leaves the previous revision
/// intact. It is a stand-in for the product's real local store (WP15 / Persistence.Sqlite), not a release store.
/// </summary>
internal sealed class FileDraftStore(AssistantHostIdentity owner, AssistantStorePartition partition, string directory)
    : IAssistantDraftStore
{
    private readonly object _gate = new();

    public AssistantHostIdentity Owner { get; } = owner;
    public AssistantStorePartition Partition { get; } = partition;
    public string Directory { get; } = System.IO.Path.GetFullPath(directory);
    public int SaveCalls { get; private set; }
    public int SkippedFiles { get; private set; }

    /// <summary>Runs after the temporary file is complete and before it replaces the stored revision.</summary>
    public Func<CancellationToken, Task>? AfterTemporaryWritten { get; set; }
    public Func<CancellationToken, Task>? BeforeRecover { get; set; }
    public Exception? RecoverFault { get; set; }
    public Exception? SaveFault { get; set; }
    public Func<AssistantDraft, AssistantDraft>? Tamper { get; set; }

    /// <summary>Acknowledges a save without storing anything (a store that lies about durability).</summary>
    public bool AcknowledgeWithoutWriting { get; set; }

    public async ValueTask<Outcome<AssistantDraft>> SaveAsync(AssistantDraft draft, long expectedRevision,
        CancellationToken cancellationToken = default)
    {
        SaveCalls++;
        if (SaveFault is not null)
        {
            throw SaveFault;
        }

        if (draft.Revision != expectedRevision + 1)
        {
            return Outcome.Failure<AssistantDraft>(TypedFailure.Create("validation.invalid_request"));
        }

        System.IO.Directory.CreateDirectory(Directory);
        string final = FileFor(draft.Id);
        string temporary = final + "." + Guid.NewGuid().ToString("N") + ".tmp";
        lock (_gate)
        {
            if ((Read(final)?.Revision ?? 0) != expectedRevision)
            {
                return Outcome.Failure<AssistantDraft>(TypedFailure.Create("conflict.revision_mismatch"));
            }

            using var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            stream.Write(Encode(draft));
            stream.Flush(flushToDisk: true);
        }

        if (AfterTemporaryWritten is { } hook)
        {
            await hook(cancellationToken);
        }

        lock (_gate)
        {
            if (AcknowledgeWithoutWriting)
            {
                File.Delete(temporary);
            }
            else
            {
                File.Move(temporary, final, overwrite: true);
            }
        }

        return Outcome.Success(Tamper is null ? draft : Tamper(draft));
    }

    public async ValueTask<Outcome<IReadOnlyList<AssistantDraft>>> RecoverAsync(CancellationToken cancellationToken = default)
    {
        if (BeforeRecover is { } hook)
        {
            await hook(cancellationToken);
        }

        if (RecoverFault is not null)
        {
            throw RecoverFault;
        }

        List<AssistantDraft> drafts = [];
        if (System.IO.Directory.Exists(Directory))
        {
            foreach (string path in System.IO.Directory.EnumerateFiles(Directory, "*.draft"))
            {
                var draft = Read(path);
                if (draft is null)
                {
                    SkippedFiles++;
                    continue;
                }

                drafts.Add(draft);
            }
        }

        return Outcome.Success<IReadOnlyList<AssistantDraft>>(drafts);
    }

    public ValueTask<Outcome<bool>> DiscardAsync(AssistantDraftId id, long expectedRevision,
        CancellationToken cancellationToken = default)
    {
        string path = FileFor(id);
        lock (_gate)
        {
            var stored = Read(path);
            if (stored is null)
            {
                return ValueTask.FromResult(Outcome.Success(false));
            }

            if (stored.Revision != expectedRevision)
            {
                return ValueTask.FromResult(Outcome.Failure<bool>(TypedFailure.Create("conflict.revision_mismatch")));
            }

            File.Delete(path);
            return ValueTask.FromResult(Outcome.Success(true));
        }
    }

    public string[] TemporaryFiles()
        => System.IO.Directory.Exists(Directory)
            ? System.IO.Directory.GetFiles(Directory, "*.tmp") : [];

    public void Corrupt(AssistantDraftId id) => File.WriteAllText(FileFor(id), "not a draft");

    public AssistantDraft? Stored(AssistantDraftId id) => Read(FileFor(id));

    private string FileFor(AssistantDraftId id) => System.IO.Path.Combine(Directory, id.Value.ToString("N") + ".draft");

    private static byte[] Encode(AssistantDraft draft) => Encoding.UTF8.GetBytes(string.Join('\n',
        "v1", draft.Id.Value.ToString("N"), draft.Window.Value.ToString("N"),
        draft.Conversation?.Value.ToString("N") ?? "-",
        draft.Revision.ToString(CultureInfo.InvariantCulture),
        Convert.ToBase64String(Encoding.UTF8.GetBytes(draft.Text)), "end"));

    private static AssistantDraft? Read(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            string[] lines = File.ReadAllText(path, Encoding.UTF8).Split('\n');
            if (lines.Length != 7 || lines[0] != "v1" || lines[6] != "end")
            {
                return null;
            }

            return new AssistantDraft(new AssistantDraftId(Guid.ParseExact(lines[1], "N")),
                new AssistantWindowId(Guid.ParseExact(lines[2], "N")),
                lines[3] == "-" ? null : new AssistantConversationId(Guid.ParseExact(lines[3], "N")),
                long.Parse(lines[4], CultureInfo.InvariantCulture),
                Encoding.UTF8.GetString(Convert.FromBase64String(lines[5])));
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or IOException)
        {
            return null;
        }
    }
}

internal sealed class FakeRemoteLink(AssistantHostIdentity owner) : IAssistantRemoteLink
{
    public AssistantHostIdentity Owner { get; } = owner;
    public AssistantRemoteState Observed { get; set; } = AssistantRemoteState.Available;
    public bool Throws { get; set; }
    public int Reads { get; private set; }

    public AssistantRemoteState State
    {
        get
        {
            Reads++;
            return Throws ? throw new InvalidOperationException("Cloud unreachable.") : Observed;
        }
    }
}

/// <summary>Session that records the order of its disposal relative to the view lifecycle.</summary>
internal sealed class RecordingSession(AssistantHostOptions options, AssistantHostServices services, List<string> events)
    : FakeSession(options, services)
{
    public bool ThrowOnDispose { get; set; }
    public int DisposeCalls { get; private set; }

    public override ValueTask DisposeAsync()
    {
        DisposeCalls++;
        events.Add("session.disposed");
        return ThrowOnDispose ? throw new InvalidOperationException("dispose failed") : base.DisposeAsync();
    }
}

/// <summary>One composed application over a scratch directory, with the real lifecycle and test-only ports.</summary>
internal sealed class LifecycleApp
{
    public LifecycleApp(string root, AssistantProductIdentity? product = null, int instance = 1, ulong epoch = 7,
        bool remote = true, TimeSpan? timeout = null)
    {
        Identity = TestData.Host(TestData.Installed(product, 1), instance, epoch);
        Host = FakeHost.For(Identity);
        Directory = System.IO.Path.Combine(root, Identity.Product.ProductId);
        Store = new FileDraftStore(Identity, Host.Partition, System.IO.Path.Combine(Directory, "drafts"));
        Remote = remote ? new FakeRemoteLink(Identity) : null;
        Lifecycle = new AssistantLifecycle(Identity, Store, Remote, timeout);
        Options = TestData.Options(Identity);
        Factory = new FakeSessionFactory(Identity, (o, s) =>
        {
            Session = new RecordingSession(o, s, Events);
            return Session;
        });
        Services = new AssistantHostServices(Identity, Host, TestData.Registry(Identity), Host, Host, Lifecycle, Host, Host, Factory);
    }

    public AssistantHostIdentity Identity { get; }
    public FakeHost Host { get; }
    public string Directory { get; }
    public FileDraftStore Store { get; }
    public FakeRemoteLink? Remote { get; }
    public AssistantLifecycle Lifecycle { get; }
    public AssistantHostOptions Options { get; }
    public FakeSessionFactory Factory { get; }
    public AssistantHostServices Services { get; }
    public RecordingSession? Session { get; private set; }
    public List<string> Events { get; } = [];

    public async Task<AssistantLaunchReport> LaunchAsync()
    {
        var launched = await Lifecycle.LaunchAsync(Options, Services);
        Xunit.Assert.True(launched.TryGetValue(out var report));
        return report;
    }

    /// <summary>A second process start over the same data directory: a new instance identity and epoch.</summary>
    public LifecycleApp Restart(string root, TimeSpan? timeout = null, bool remote = true)
        => new(root, Identity.Product, instance: 2, epoch: Identity.Epoch + 1, remote: remote, timeout: timeout);
}
