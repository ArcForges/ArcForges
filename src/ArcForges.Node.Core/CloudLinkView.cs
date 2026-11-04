// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Node.Core;

/// <summary>Where the node's link to its center stands (AF-CTR-04 CTR4-NODE-08).</summary>
public enum CloudLinkPhase
{
    /// <summary>No usable credential for the configured center (also after a revocation, with its reason).</summary>
    SignedOut,

    /// <summary>A sign-in flow is active (part N2).</summary>
    SigningIn,

    /// <summary>The node holds a credential of the configured center.</summary>
    SignedIn,
}

/// <summary>
/// The core's view of the cloud link (AF-CTR-04 N1, node-12 item 4): <c>Node.Core</c> cannot reference the CloudLink project, so the host
/// sets this seam at startup step 8. <see cref="NodeRuntime.Info"/> reads <see cref="AccountLinked"/>; the <c>center_url</c> refusal of
/// <c>UpdateNodeSettings</c> reads <see cref="Phase"/> under <see cref="EnterAsync"/>, the link's own gate, so no sign-in completes while a
/// center change is decided; <see cref="CenterChangedAsync"/> clears what belonged to the old center; <see cref="NodeInfoChanged"/>
/// schedules <c>ReportNodeInfo</c> after a rename.
/// </summary>
public interface ICloudLinkView
{
    /// <summary>The link's phase now.</summary>
    CloudLinkPhase Phase { get; }

    /// <summary><c>NodeInfo.account_linked</c>: the node holds a credential of its configured center.</summary>
    bool AccountLinked { get; }

    /// <summary>Takes the link's gate (the one async gate of refresh, sign-out and sign-in completion); dispose to release it.</summary>
    Task<IDisposable> EnterAsync(CancellationToken cancellationToken);

    /// <summary>Called after a successful <c>center_url</c> change (outside the single writer): deletes the old center's key cache and key.</summary>
    Task CenterChangedAsync();

    /// <summary>Called after the node's name changed: <c>ReportNodeInfo</c> follows (debounced).</summary>
    void NodeInfoChanged();
}

/// <summary>The view of a node without a cloud link (before step 8, and in hosts that build none).</summary>
public sealed class NoCloudLink : ICloudLinkView
{
    /// <summary>The shared instance.</summary>
    public static readonly NoCloudLink Instance = new();

    private NoCloudLink()
    {
    }

    /// <inheritdoc />
    public CloudLinkPhase Phase => CloudLinkPhase.SignedOut;

    /// <inheritdoc />
    public bool AccountLinked => false;

    /// <inheritdoc />
    public Task<IDisposable> EnterAsync(CancellationToken cancellationToken) => Task.FromResult<IDisposable>(Released.Instance);

    /// <inheritdoc />
    public Task CenterChangedAsync() => Task.CompletedTask;

    /// <inheritdoc />
    public void NodeInfoChanged()
    {
    }

    private sealed class Released : IDisposable
    {
        public static readonly Released Instance = new();

        public void Dispose()
        {
        }
    }
}
