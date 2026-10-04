// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ArcForges.ContentSandbox.Broker.Windows;
using ArcForges.ContentSandbox.Contracts;
using ArcForges.Foundation.Errors;
using ArcForges.LocalRpc;

namespace ArcForges.ContentSandbox.Broker;

/// <summary>
/// Launches the signed ContentSandbox helper of one installation in the restricted profile of the operating system and returns an
/// invocation that talks to it over the generated sandbox contract. A platform without a verified profile launches nothing: there is no
/// same-user full-trust fallback and no in-process parsing.
/// </summary>
public sealed class ContentSandboxLauncher : IAsyncDisposable
{
    private readonly ContentSandboxLaunchOptions _options;
    private readonly IContentSandboxProcessLauncher? _launcher;
    private readonly ContentSandboxProfileStatus _status;
    private readonly LocalRpcLaunchAuthority? _authority;
    private int _disposed;

    /// <summary>Creates a launcher for the helper of this installation. It validates the options and prepares the private runtime root; it starts nothing.</summary>
    /// <param name="options">The helper, its pinned digest, the runtime root and the budget.</param>
    public ContentSandboxLauncher(ContentSandboxLaunchOptions options)
        : this(options, profileOverride: null, launcherOverride: null)
    {
    }

    internal ContentSandboxLauncher(ContentSandboxLaunchOptions options, ContentSandboxProfile? profileOverride, IContentSandboxProcessLauncher? launcherOverride)
    {
        ArgumentNullException.ThrowIfNull(options);
        Validate(options);
        _options = options;
        _status = profileOverride is { } forced
            ? new ContentSandboxProfileStatus(forced, launcherOverride is not null, launcherOverride is null ? "The profile was forced unavailable." : string.Empty)
            : launcherOverride is not null
                ? new ContentSandboxProfileStatus(ContentSandboxProfile.WindowsAppContainerJob, true, string.Empty)
                : ProbeProfile();
        _launcher = launcherOverride ?? (profileOverride is null ? CreateLauncher(options) : null);
        _authority = _launcher is null ? null : LocalRpcLaunchAuthority.Create(options.RuntimeRoot);
    }

    /// <summary>What the profile of this platform can do now. It starts no process and touches no resource.</summary>
    public static ContentSandboxProfileStatus ProbeProfile()
    {
        if (OperatingSystem.IsWindows())
        {
            return new ContentSandboxProfileStatus(ContentSandboxProfile.WindowsAppContainerJob, true, string.Empty);
        }

        if (OperatingSystem.IsLinux())
        {
            return new ContentSandboxProfileStatus(
                ContentSandboxProfile.LinuxLandlockSeccomp,
                true,
                string.Empty);
        }

        if (OperatingSystem.IsMacOS())
        {
            return new ContentSandboxProfileStatus(
                ContentSandboxProfile.MacOsAppSandboxXpc,
                false,
                "The macOS App Sandbox profile needs a signed sandboxed bundle and an XPC descriptor handoff that this build does not contain.");
        }

        return new ContentSandboxProfileStatus(ContentSandboxProfile.Unsupported, false, "No restricted launch profile exists for this operating system.");
    }

    /// <summary>
    /// Starts the helper in its restricted profile, waits for it to register, opens the one session of the invocation and returns the
    /// invocation. A refusal (profile unavailable, helper not the pinned build, helper failed its own isolation check, registration or
    /// session not completed in time) is a typed failure and leaves no helper running.
    /// </summary>
    /// <param name="input">The immutable bytes the helper may read; at most the input budget.</param>
    /// <param name="cancellationToken">Abandons the launch and ends the helper.</param>
    public async ValueTask<ContentSandboxResult<ContentSandboxInvocation>> LaunchAsync(ReadOnlyMemory<byte> input, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (_launcher is null || _authority is null || !_status.IsAvailable)
        {
            return ContentSandboxResult<ContentSandboxInvocation>.Fail("security.isolation_unavailable");
        }

        if (input.Length == 0 || (ulong)input.Length > _options.Limits.MaxInputBytes)
        {
            return ContentSandboxResult<ContentSandboxInvocation>.Fail("validation.invalid_request");
        }

        return await ContentSandboxInvocation.StartAsync(_options, _launcher, _authority, input, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Disposes the launch authority. Invocations that are still open keep running until they are disposed.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0 && _authority is not null)
        {
            await _authority.DisposeAsync().ConfigureAwait(false);
        }
    }

    internal static LocalRpcLaunchIdentity IdentityFor(ContentSandboxLaunchOptions options) =>
        new(
            LocalRpcChildKind.ContentSandbox,
            options.BuildId,
            options.HelperSha256.Span,
            ContentSandboxContract.ProtocolVersion,
            ContentSandboxContract.ContractSetDigest.Span);

    [SuppressMessage("Performance", "CA1859", Justification = "Each platform returns its own launcher type behind the one interface.")]
    private static IContentSandboxProcessLauncher? CreateLauncher(ContentSandboxLaunchOptions options)
    {
        if (OperatingSystem.IsWindows())
        {
            return new WindowsHelperLauncher(options.AppContainerName, options.SlotLockDirectory);
        }

        return null;
    }

    private static void Validate(ContentSandboxLaunchOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.HelperPath) || !Path.IsPathFullyQualified(options.HelperPath))
        {
            throw new ArgumentException("The helper path is an absolute path.", nameof(options));
        }

        if (options.HelperSha256.Length != SHA256.HashSizeInBytes)
        {
            throw new ArgumentException("The helper digest is a SHA-256 value.", nameof(options));
        }

        if (!ContentSandboxLaunchFrame.IsParserProfile(options.ParserProfile))
        {
            throw new ArgumentException("The parser profile is not a valid identifier.", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(options.RuntimeRoot) || !Path.IsPathFullyQualified(options.RuntimeRoot))
        {
            throw new ArgumentException("The runtime root is an absolute path.", nameof(options));
        }

        if (!options.Limits.IsWithinProfile())
        {
            throw new ArgumentException("The limits are not within the profile.", nameof(options));
        }

        if (options.SlotCount is < 1 or > ContentSandboxContract.MaxSlots
            || options.SlotCapacityBytes is < 1 or > ContentSandboxContract.MaxSlotBytes)
        {
            throw new ArgumentException("The slot count or capacity is outside the profile.", nameof(options));
        }

        if (options.LaunchTimeout <= TimeSpan.Zero || options.LaunchTimeout > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentException("The launch timeout is positive and at most five minutes.", nameof(options));
        }

        _ = new LocalRpcLaunchIdentity(
            LocalRpcChildKind.ContentSandbox,
            options.BuildId,
            options.HelperSha256.Span,
            ContentSandboxContract.ProtocolVersion,
            ContentSandboxContract.ContractSetDigest.Span);
    }
}
