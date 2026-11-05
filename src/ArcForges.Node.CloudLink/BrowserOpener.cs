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

        // Not redirected (N2 review sec N-9): a browser that inherits a pipe nobody reads would block on a full one, or meet a closed one.
        var start = new ProcessStartInfo("xdg-open") { UseShellExecute = false, RedirectStandardOutput = false, RedirectStandardError = false, RedirectStandardInput = false };
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
            using var process = Process.Start(StartInfo(url, OperatingSystem.IsWindows()));
            if (process is null)
            {
                return OperatingSystem.IsWindows();
            }

            if (OperatingSystem.IsWindows())
            {
                return true;
            }

            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            bounded.CancelAfter(wait > TimeSpan.Zero ? wait : TimeSpan.FromMilliseconds(1));
            try
            {
                await process.WaitForExitAsync(bounded.Token).ConfigureAwait(false);
                return process.ExitCode == 0;
            }
            catch (OperationCanceledException)
            {
                // Still running after the wait (a browser that stays attached): opened.
                return true;
            }
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException or PlatformNotSupportedException)
        {
            return false;
        }
    }
}
