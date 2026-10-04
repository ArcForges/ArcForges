// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.Foundation.Errors;

namespace ArcForges.ContentSandbox.Broker;

/// <summary>The restricted launch profile family of this operating system.</summary>
public enum ContentSandboxProfile
{
    /// <summary>No verified profile exists for this platform; nothing is launched and there is no unsafe fallback.</summary>
    Unsupported = 0,

    /// <summary>Windows AppContainer with a Job Object.</summary>
    WindowsAppContainerJob = 1,

    /// <summary>Linux Landlock, seccomp and no_new_privs.</summary>
    LinuxLandlockSeccomp = 2,

    /// <summary>macOS App Sandbox with an XPC descriptor handoff. It is not implemented: a launch for it is refused.</summary>
    MacOsAppSandboxXpc = 3,
}

/// <summary>Whether this platform has a restricted launch profile that can run now, and why not when it cannot.</summary>
/// <param name="Profile">The profile family of the platform.</param>
/// <param name="IsAvailable">True when a helper can be launched in the profile.</param>
/// <param name="Reason">A short factual reason when it cannot; empty otherwise.</param>
public sealed record ContentSandboxProfileStatus(ContentSandboxProfile Profile, bool IsAvailable, string Reason);

/// <summary>
/// The outcome of a sandbox operation: a value, or a typed failure carrying a registered producer reason code. A failure never carries parser
/// output, an exception text from the helper or a path.
/// </summary>
/// <typeparam name="T">The value type.</typeparam>
public sealed class ContentSandboxResult<T>
{
    private ContentSandboxResult(T? value, TypedFailure? failure, string? detail)
    {
        Value = value;
        Failure = failure;
        Detail = detail;
    }

    /// <summary>True when the operation succeeded and <see cref="Value"/> is set.</summary>
    [MemberNotNullWhen(true, nameof(Value))]
    [MemberNotNullWhen(false, nameof(Failure))]
    public bool IsSuccess => Failure is null;

    /// <summary>The value on success.</summary>
    public T? Value { get; }

    /// <summary>The typed failure otherwise.</summary>
    public TypedFailure? Failure { get; }

    /// <summary>
    /// A short factual note of the parent's own about where a launch or call failed (a step name and an operating-system error number). It is
    /// for diagnostics only and must not be shown to a user or acted on. It may end with a short excerpt (at most 200 printable ASCII
    /// characters) of what the hostile helper wrote to its output: untrusted text, kept out of any log that is parsed and out of any UI.
    /// </summary>
    public string? Detail { get; }

    internal static ContentSandboxResult<T> Ok(T value) => new(value, null, null);

    internal static ContentSandboxResult<T> Fail(string code, string? detail = null) => new(default, TypedFailure.Create(code), detail);

    internal static ContentSandboxResult<T> Fail(TypedFailure failure, string? detail = null) => new(default, failure, detail);
}

/// <summary>What a product configures to launch the restricted content helper of its installation.</summary>
public sealed record ContentSandboxLaunchOptions
{
    /// <summary>The installed helper executable.</summary>
    public required string HelperPath { get; init; }

    /// <summary>
    /// The SHA-256 of the helper executable as recorded in the installed signed inventory. The launcher opens the file with writers
    /// refused, compares its digest before the process is created and runs the bytes it checked. A mismatch launches nothing.
    /// </summary>
    public required ReadOnlyMemory<byte> HelperSha256 { get; init; }

    /// <summary>The build identifier the helper presents at registration (1 to 64 characters of letters, digits, dot, underscore and hyphen).</summary>
    public string BuildId { get; init; } = "arcforges.contentsandbox";

    /// <summary>The parser profile the helper is asked to serve (the signed helper chooses its libraries from it, never from a path).</summary>
    public string ParserProfile { get; init; } = "none";

    /// <summary>An absolute path of an owner-only directory for the per-launch records of the launch authority; it is created when missing.</summary>
    public required string RuntimeRoot { get; init; }

    /// <summary>The parser budget of the invocation. Every value is positive and within the profile maximum.</summary>
    public ContentSandboxLimits Limits { get; init; } = new();

    /// <summary>The capacity of each output slot in bytes, 1 byte through 64 MiB (default 64 MiB).</summary>
    public long SlotCapacityBytes { get; init; } = ContentSandboxContract.MaxSlotBytes;

    /// <summary>The number of output slots, 1 through 3 (default 3).</summary>
    public int SlotCount { get; init; } = ContentSandboxContract.MaxSlots;

    /// <summary>How long registration and the first session may take before the launch is abandoned and the helper terminated (default 30 s).</summary>
    public TimeSpan LaunchTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>The AppContainer name prefix on Windows; at most eight identities are leased under it.</summary>
    public string AppContainerName { get; init; } = "ArcForges.ContentSandbox";

    /// <summary>The directory of the AppContainer identity locks on Windows; the per-user default when null.</summary>
    public string? SlotLockDirectory { get; init; }
}

/// <summary>The geometry and bytes of one verified tile. The bytes are the parent's private copy, verified against the sealed digest.</summary>
public sealed class ContentSandboxTile : IDisposable
{
    private readonly ArcForges.LocalRpc.LocalRpcVerifiedBuffer _buffer;

    internal ContentSandboxTile(ArcForges.LocalRpc.LocalRpcVerifiedBuffer buffer, uint format, uint fullWidth, uint fullHeight, uint x, uint y, uint width, uint height, ulong rowStride)
    {
        _buffer = buffer;
        Format = format;
        FullWidth = fullWidth;
        FullHeight = fullHeight;
        X = x;
        Y = y;
        Width = width;
        Height = height;
        RowStride = rowStride;
    }

    /// <summary>1 for 8-bit RGBA, 2 for 32-bit float RGBA.</summary>
    public uint Format { get; }

    /// <summary>The full image or page width in pixels.</summary>
    public uint FullWidth { get; }

    /// <summary>The full image or page height in pixels.</summary>
    public uint FullHeight { get; }

    /// <summary>The tile origin.</summary>
    public uint X { get; }

    /// <summary>The tile origin.</summary>
    public uint Y { get; }

    /// <summary>The tile width in pixels.</summary>
    public uint Width { get; }

    /// <summary>The tile height in pixels.</summary>
    public uint Height { get; }

    /// <summary>The distance in bytes between row starts.</summary>
    public ulong RowStride { get; }

    /// <summary>The verified bytes. Reading them after <see cref="Dispose"/> throws.</summary>
    public ReadOnlyMemory<byte> Bytes => _buffer.Bytes;

    /// <summary>The verified SHA-256 of the bytes as lowercase hexadecimal.</summary>
    public string Sha256 => _buffer.Digest.ToHex();

    /// <summary>Zeroes the private copy and releases the copy budget of the session. Safe to repeat.</summary>
    public void Dispose() => _buffer.Dispose();
}
