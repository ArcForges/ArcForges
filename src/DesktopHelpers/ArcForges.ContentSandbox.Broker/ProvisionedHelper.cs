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
    Func<IReadOnlyList<ContentSandboxHandleEntry>, byte[]> EncodeFrame,
    bool RequirePlatformSignature = true);

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

/// <summary>
/// Owns the right to signal one child process id. Once the child has been reaped the id may be recycled by an unrelated process, so the id is
/// invalidated under the same lock that reaps it, and a signal is only ever sent under that lock while the id is still valid.
/// </summary>
internal sealed class ChildProcessGuard
{
    private readonly object _gate = new();
    private readonly Func<int, int?> _tryReap;
    private readonly Action<int> _kill;
    private int _processId;

    internal ChildProcessGuard(int processId, Func<int, int?> tryReap, Action<int> kill)
    {
        _processId = processId;
        _tryReap = tryReap;
        _kill = kill;
    }

    /// <summary>True while the child has not been reaped.</summary>
    internal bool IsLive
    {
        get
        {
            lock (_gate)
            {
                return _processId > 0;
            }
        }
    }

    /// <summary>Signals the child unless it was already reaped. Never signals a recycled id.</summary>
    internal void Kill()
    {
        lock (_gate)
        {
            if (_processId > 0)
            {
                _kill(_processId);
            }
        }
    }

    /// <summary>Reaps the child if it has ended and invalidates the id in the same step; returns the exit code when it did.</summary>
    internal int? TryReap()
    {
        lock (_gate)
        {
            if (_processId <= 0)
            {
                return null;
            }

            var code = _tryReap(_processId);
            if (code is not null)
            {
                _processId = 0;
            }

            return code;
        }
    }
}

/// <summary>Bounds untrusted helper output before it is placed in a parent-side diagnostic note.</summary>
internal static class HelperText
{
    internal const int MaxChars = 200;

    /// <summary>Keeps at most <see cref="MaxChars"/> printable ASCII characters of the tail; everything else becomes a space.</summary>
    internal static string Sanitise(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var tail = text.Length > MaxChars ? text[^MaxChars..] : text;
        return string.Create(tail.Length, tail, static (span, source) =>
        {
            for (var index = 0; index < span.Length; index++)
            {
                span[index] = source[index] is >= ' ' and <= '~' ? source[index] : ' ';
            }
        });
    }
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
