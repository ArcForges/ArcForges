// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.ContentSandbox.Contracts;
using ArcForges.LocalRpc;

namespace ArcForges.ContentSandbox.Broker;

/// <summary>
/// What a platform launcher is asked to start: the verified helper, the immutable input, the slot sizes and the hooks that tie the new
/// process to its launch. A launcher provisions the OS resources itself, because only it knows the child-side numbers the frame lists.
/// </summary>
internal sealed record HelperStartRequest(
    string HelperPath,
    ReadOnlyMemory<byte> HelperSha256,
    ReadOnlyMemory<byte> Input,
    IReadOnlyList<long> SlotCapacities,
    ContentSandboxLimits Limits,
    Action<LocalRpcProcessIdentity> OnProcessCreated,
    Func<IReadOnlyList<ContentSandboxHandleEntry>, byte[]> EncodeFrame);

/// <summary>
/// A helper process that was started in its restricted profile with its closed resource inventory, together with the parent's ends of
/// those resources. Disposing it ends the process tree, waits for it, and releases every resource once.
/// </summary>
internal interface IProvisionedHelper : IAsyncDisposable
{
    /// <summary>The verified child process (id and start value).</summary>
    LocalRpcProcessIdentity Identity { get; }

    /// <summary>The parent's end of the stream on which the helper calls the bootstrap service (the parent is the server).</summary>
    Stream ControlStream { get; }

    /// <summary>The parent's end of the stream on which the parent calls the sandbox service (the parent is the client).</summary>
    Stream ServiceStream { get; }

    /// <summary>The parent's read mappings of the output slots. The session that receives them disposes them; disposal is idempotent.</summary>
    IReadOnlyList<ILocalRpcBufferMapping> SlotMappings { get; }

    /// <summary>Completes with the exit code when the helper process has ended, however it ended.</summary>
    Task<int> Exited { get; }

    /// <summary>The last output the helper wrote to its standard output and error, for diagnostics only. Never a parser result.</summary>
    string DiagnosticTail { get; }

    /// <summary>Ends the whole process tree at once. Idempotent.</summary>
    void Terminate();
}

/// <summary>A launch could not be completed; the reason code is one of the registered producer codes.</summary>
public sealed class ContentSandboxLaunchException : Exception
{
    /// <summary>Creates an exception with the generic launch-failure code.</summary>
    public ContentSandboxLaunchException()
        : this("resource.unavailable", "The restricted helper could not be launched.")
    {
    }

    /// <summary>Creates an exception with the generic launch-failure code.</summary>
    /// <param name="message">What failed.</param>
    public ContentSandboxLaunchException(string message)
        : this("resource.unavailable", message)
    {
    }

    /// <summary>Creates an exception with the generic launch-failure code.</summary>
    /// <param name="message">What failed.</param>
    /// <param name="innerException">The cause.</param>
    public ContentSandboxLaunchException(string message, Exception innerException)
        : this("resource.unavailable", message, innerException)
    {
    }

    internal ContentSandboxLaunchException(string reasonCode, string message)
        : base(message)
    {
        ReasonCode = reasonCode;
    }

    internal ContentSandboxLaunchException(string reasonCode, string message, Exception inner)
        : base(message, inner)
    {
        ReasonCode = reasonCode;
    }

    /// <summary>The registered reason code (for example <c>security.isolation_unavailable</c>).</summary>
    public string ReasonCode { get; } = "resource.unavailable";
}

/// <summary>Starts a helper in one restricted profile. A platform without a verified profile has no launcher and never starts a process.</summary>
internal interface IContentSandboxProcessLauncher
{
    /// <summary>The profile family this launcher enforces.</summary>
    ContentSandboxProfileKind Profile { get; }

    /// <summary>Starts the helper, or throws <see cref="ContentSandboxLaunchException"/> having started nothing.</summary>
    ValueTask<IProvisionedHelper> StartAsync(HelperStartRequest request, CancellationToken cancellationToken);
}
