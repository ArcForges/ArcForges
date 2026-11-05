// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;

namespace ArcForges.Node.CloudLink;

/// <summary>Opens the browser sign-in's URL (the seam a test browser replaces; the URL check runs before it, in <see cref="SignInUrls"/>).</summary>
internal interface IBrowserOpener
{
    /// <summary>Opens <paramref name="url"/>; false when nothing was opened (the flow stays BROWSER with <c>browser_not_opened</c>).</summary>
    Task<bool> OpenAsync(DerivedUrl url, TimeSpan wait, CancellationToken cancellationToken);
}

/// <summary>
/// The system browser (AF-CTR-04 CTR4-NODE-12/17; the plan review's protocol-2 corrected fix item (d)). It receives only a URL the node
/// derived itself. Windows: <c>ProcessStartInfo { FileName = &lt;url&gt;, UseShellExecute = true }</c>, never <c>cmd</c>, <c>start</c>,
/// PowerShell or a batch file. Linux: <c>xdg-open</c> with an argument vector (<c>UseShellExecute = false</c>), waited for at most the given
/// time. Under <c>--test-mode</c> no OS handler is ever started: with <c>ARCFORGES_TEST_BROWSER_FILE</c> the URL is written to that file,
/// otherwise nothing is opened. This is the only source file of <c>src/</c> that starts an OS handler (a repository test pins it).
/// </summary>
internal sealed class BrowserOpener : IBrowserOpener
{
    private readonly bool _testMode;
    private readonly string? _file;

    /// <summary>Creates the opener; <paramref name="browserFile"/> is the checked test-mode hook (or <see langword="null"/>).</summary>
    public BrowserOpener(bool testMode, string? browserFile)
    {
        _testMode = testMode;
        _file = testMode ? browserFile : null;
    }

    /// <summary>How the system browser is started for <paramref name="url"/> on Windows (<paramref name="windows"/>) or Linux.</summary>
    public static ProcessStartInfo StartInfo(DerivedUrl url, bool windows)
    {
        ArgumentNullException.ThrowIfNull(url);
        if (windows)
        {
            return new ProcessStartInfo { FileName = url.Value, UseShellExecute = true };
        }

        // Redirected and discarded (N2 confirmation C1-3): xdg-open and the browser it starts name the URL in their messages, which would
        // otherwise reach the node's own output (the user journal under the systemd unit). The pipes are drained to their end, for the
        // browser's lifetime too, so a writer never blocks on a full pipe or meets a closed one (sec N-9).
        var start = new ProcessStartInfo("xdg-open") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = false };
        start.ArgumentList.Add(url.Value);
        return start;
    }

    /// <inheritdoc />
    public async Task<bool> OpenAsync(DerivedUrl url, TimeSpan wait, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(url);
        if (_testMode)
        {
            if (_file is null)
            {
                return false;
            }

            PrivateFiles.WriteAtomic(_file, System.Text.Encoding.UTF8.GetBytes(url.Value + "\n"));
            return true;
        }

        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
        {
            return false;
        }

        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var shell = Process.Start(StartInfo(url, windows: true));
                return true;
            }

            // Still running after the wait (a browser that stays attached): opened.
            return await RunAsync(StartInfo(url, windows: false), wait, cancellationToken).ConfigureAwait(false) is null or 0;
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException or PlatformNotSupportedException)
        {
            return false;
        }
    }

    /// <summary>
    /// Starts <paramref name="start"/> (its output redirected) and discards its output: both pipes are read to their end in the background,
    /// also after the process exits while a child it started still holds them; the process object is released only then. The exit code, or
    /// <see langword="null"/> when the process still runs after <paramref name="wait"/>.
    /// </summary>
    internal static async Task<int?> RunAsync(ProcessStartInfo start, TimeSpan wait, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(start);
        var process = Process.Start(start) ?? throw new InvalidOperationException("The process did not start.");
        var drained = Task.WhenAll(Discard(process.StandardOutput.BaseStream), Discard(process.StandardError.BaseStream));
        try
        {
            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            bounded.CancelAfter(wait > TimeSpan.Zero ? wait : TimeSpan.FromMilliseconds(1));
            await process.WaitForExitAsync(bounded.Token).ConfigureAwait(false);
            return process.ExitCode;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        finally
        {
            // Released once its output has ended (a browser it started may hold the pipes much longer than it runs).
            _ = drained.ContinueWith(_ => process.Dispose(), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    private static async Task Discard(Stream stream)
    {
        try
        {
            await stream.CopyToAsync(Stream.Null).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException)
        {
        }
    }
}
