// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Globalization;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.TestLoad;

/// <summary>Records only fixed observations from an isolated native security test payload.</summary>
internal static partial class SecurityScenario
{
    private static readonly SearchValues<char> LowerHex = SearchValues.Create("0123456789abcdef");
    internal const string SecretEnvironmentName = "CORESEC01_NATIVE_SECRET";

    public static async Task<int> RunAsync(string[] arguments)
    {
        if (arguments is not [var marker, var endpoint, var guarded, var value, var argumentDigest, var secretDigest]
            || marker is not ("security-verified.log" or "security-refused.log")
            || !IsFixtureEndpoint(endpoint) || !Path.IsPathFullyQualified(guarded)
            || Path.GetFileName(guarded) != "sec01-host-probe"
            || Path.GetFileName(Path.GetDirectoryName(guarded)) != "control"
            || !IsDigest(argumentDigest) || !IsDigest(secretDigest))
        {
            throw new UsageException("The security probe needs the isolated fixture marker, IPC endpoint, guarded sentinel and two digests.");
        }

        var secret = Environment.GetEnvironmentVariable(SecretEnvironmentName);
        var argvMatched = MatchesDigest(value, argumentDigest);
        var secretMatched = secret is not null && MatchesDigest(secret, secretDigest);
        string ipc;
        if (OperatingSystem.IsWindows())
        {
            ipc = CheckWindowsPipe(endpoint);
        }
        else
        {
            var (observation, errno) = CheckUnixSocket(endpoint);
            ipc = observation;
            await File.WriteAllTextAsync("security-ipc-native.log", errno.ToString(CultureInfo.InvariantCulture)).ConfigureAwait(false);
        }
        var metadata = CheckGuardedPath(guarded);
        await File.WriteAllLinesAsync(marker,
            [argvMatched ? "argument-verified" : "argument-mismatch", secretMatched ? "secret-verified" : "secret-mismatch", ipc, metadata])
            .ConfigureAwait(false);
        if (!argvMatched || !secretMatched || ipc is not ("ipc-access-denied" or "ipc-not-visible")
            || metadata is not ("metadata-access-denied" or "metadata-not-visible"))
        {
            return ExitCodes.Failure;
        }

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        if (OperatingSystem.IsWindows())
        {
            const string handoff = "security-mxc-run-id";
            await WaitForFileAsync(handoff, deadline.Token).ConfigureAwait(false);
            var runId = await File.ReadAllTextAsync(handoff, deadline.Token).ConfigureAwait(false);
            if (runId.Length != 32 || runId.AsSpan().IndexOfAnyExcept(LowerHex) >= 0)
            {
                return ExitCodes.Failure;
            }

            var control = Path.GetDirectoryName(guarded)!;
            var config = CheckGuardedPath(Path.Combine(control, "run-" + runId, "mxc-request.json"));
            await File.WriteAllTextAsync("security-mxc-config.log", config, deadline.Token).ConfigureAwait(false);
            if (config is not ("metadata-access-denied" or "metadata-not-visible"))
            {
                return ExitCodes.Failure;
            }
        }

        await WaitForFileAsync("security-finish", deadline.Token).ConfigureAwait(false);
        return ExitCodes.Success;
    }

    private static async Task WaitForFileAsync(string path, CancellationToken cancellationToken)
    {
        while (!File.Exists(path))
        {
            await Task.Delay(25, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool IsFixtureEndpoint(string endpoint)
    {
        var name = endpoint;
        if (!OperatingSystem.IsWindows())
        {
            if (!OperatingSystem.IsLinux() || Path.GetFileName(endpoint) != "node.sock")
            {
                return false;
            }

            name = Path.GetFileName(Path.GetDirectoryName(endpoint)) ?? string.Empty;
            if (endpoint != Path.Combine("/tmp", name, "node.sock"))
            {
                return false;
            }
        }

        return name.Length == 18 && name.StartsWith("af-cl-", StringComparison.Ordinal)
            && name.AsSpan(6).IndexOfAnyExcept(LowerHex) < 0;
    }

    private static bool IsDigest(string value) => value.Length == 64 && value.AsSpan().IndexOfAnyExcept(LowerHex) < 0;

    private static bool MatchesDigest(string value, string expected)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        try
        {
            return Convert.ToHexStringLower(SHA256.HashData(bytes)) == expected;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string CheckGuardedPath(string path)
    {
        try
        {
            using var opened = File.OpenRead(path);
            return "metadata-unexpected-open";
        }
        catch (UnauthorizedAccessException)
        {
            return "metadata-access-denied";
        }
        catch (IOException error) when (error is FileNotFoundException or DirectoryNotFoundException)
        {
            return "metadata-not-visible";
        }
    }

    private static unsafe (string Observation, int Errno) CheckUnixSocket(string endpoint)
    {
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified) { Blocking = false };
        var nativeAddress = new UnixDomainSocketEndPoint(endpoint).Serialize();
        fixed (byte* address = nativeAddress.Buffer.Span)
        {
            if (ConnectUnixSocket(socket.SafeHandle, address, (uint)nativeAddress.Size) == 0)
            {
                return ("ipc-unexpected-open", 0);
            }

            var errno = Marshal.GetLastPInvokeError();
            return (errno switch
            {
                1 or 13 => "ipc-access-denied",
                2 => "ipc-not-visible",
                _ => "ipc-inconclusive",
            }, errno);
        }
    }

    [SupportedOSPlatform("windows")]
    private static string CheckWindowsPipe(string name)
    {
        using var pipe = OpenPipe(@"\\.\pipe\" + name, 0xc0000000, FileShare.ReadWrite, 0, 3, 0, 0);
        return !pipe.IsInvalid ? "ipc-unexpected-open" : Marshal.GetLastPInvokeError() switch
        {
            5 => "ipc-access-denied",
            2 or 3 => "ipc-not-visible",
            _ => "ipc-inconclusive",
        };
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle OpenPipe(string path, uint access, FileShare share, nint security, uint mode, uint flags, nint template);

    [LibraryImport("libc", EntryPoint = "connect", SetLastError = true)]
    private static unsafe partial int ConnectUnixSocket(SafeSocketHandle socket, byte* address, uint addressLength);
}
