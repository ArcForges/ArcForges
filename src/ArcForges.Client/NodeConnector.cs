// SPDX-License-Identifier: AGPL-3.0-only
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using ArcForges.LocalRpc;

namespace ArcForges.Client;

/// <summary>Why the operating-system connection to the node's endpoint failed.</summary>
public enum EndpointFailure
{
    /// <summary>Nothing listens: the pipe does not exist, or the socket is missing or refuses connections (02 section 3 auto-start).</summary>
    NotRunning = 1,

    /// <summary>
    /// The node listens but cannot accept now: every pipe instance is busy (Windows), or the socket backlog is full and the
    /// connect returned <c>EAGAIN</c> (Linux). Retried with bounded backoff, never read as "not running".
    /// </summary>
    Busy = 2,

    /// <summary>The endpoint is not this user's: the pipe has another owner, or the socket directory is not owner-only or not accessible.</summary>
    AccessDenied = 3,
}

/// <summary>The connection to the endpoint failed with a classified reason; nothing was sent.</summary>
public sealed class EndpointConnectException : IOException
{
    /// <summary>Creates the exception.</summary>
    public EndpointConnectException(EndpointFailure failure, string message, Exception? innerException = null)
        : base(message, innerException) => Failure = failure;

    /// <summary>Creates the exception.</summary>
    public EndpointConnectException()
    {
    }

    /// <summary>Creates the exception.</summary>
    public EndpointConnectException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public EndpointConnectException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>The classified reason.</summary>
    public EndpointFailure Failure { get; }
}

/// <summary>
/// Opens the operating-system stream to the node's endpoint with the same-user checks of the LocalRpc client (the pipe must be
/// owned by this user; the socket directory must be owner-only and not a link) and classifies failures, so that a client can
/// tell a node that is not running from one that is busy or not this user's.
/// </summary>
public static partial class NodeConnector
{
    private const int ErrorFileNotFound = 2;
    private const int ErrorSemTimeout = 121;

    /// <summary>How long a connect waits for a free pipe instance before it reports <see cref="EndpointFailure.Busy"/>.</summary>
    public static readonly TimeSpan BusyWait = TimeSpan.FromSeconds(2);

    /// <summary>Opens a stream to <paramref name="endpoint"/>; throws <see cref="EndpointConnectException"/> with the reason on failure.</summary>
    public static ValueTask<Stream> OpenAsync(LocalRpcEndpoint endpoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        return endpoint.Transport switch
        {
            LocalRpcTransport.NamedPipe => OpenPipeAsync(endpoint.Address, cancellationToken),
            LocalRpcTransport.UnixDomainSocket => OpenSocketAsync(endpoint.Address, cancellationToken),
            _ => throw new ArgumentException("The node endpoint is a named pipe or a Unix socket.", nameof(endpoint)),
        };
    }

    private static async ValueTask<Stream> OpenPipeAsync(string name, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Named pipes are the Windows transport.");
        }

        // WaitNamedPipe tells "no such pipe" apart from "all instances busy" without taking an instance.
        if (!WaitNamedPipeW(@"\\.\pipe\" + name, 1))
        {
            var error = Marshal.GetLastPInvokeError();
            if (error == ErrorFileNotFound)
            {
                throw new EndpointConnectException(EndpointFailure.NotRunning, $"No node listens on the pipe {name}.");
            }

            if (error != ErrorSemTimeout)
            {
                throw new EndpointConnectException(EndpointFailure.NotRunning, $"The pipe {name} is not available (error {error}).");
            }
        }

        // CurrentUserOnly makes the runtime verify that the server end is owned by this user.
        var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
            TokenImpersonationLevel.Anonymous);
        try
        {
            await pipe.ConnectAsync((int)BusyWait.TotalMilliseconds, cancellationToken).ConfigureAwait(false);
            return pipe;
        }
        catch (TimeoutException exception)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw new EndpointConnectException(EndpointFailure.Busy, $"Every instance of the pipe {name} stayed busy for {BusyWait.TotalSeconds:0} s.", exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw new EndpointConnectException(EndpointFailure.AccessDenied, $"The pipe {name} is not owned by this user.", exception);
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async ValueTask<Stream> OpenSocketAsync(string path, CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Unix sockets are the Linux transport.");
        }

        var directory = Path.GetDirectoryName(path)!;
        UnixFileMode mode;
        try
        {
            if (new DirectoryInfo(directory).LinkTarget is not null)
            {
                throw new EndpointConnectException(EndpointFailure.AccessDenied, $"The socket directory {directory} is a link.");
            }

            mode = File.GetUnixFileMode(directory);
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            throw new EndpointConnectException(EndpointFailure.NotRunning, $"No node socket directory exists at {directory}.", exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new EndpointConnectException(EndpointFailure.AccessDenied, $"The socket directory {directory} is not accessible to this user.", exception);
        }

        const UnixFileMode GroupOrOther = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        if ((mode & GroupOrOther) != 0)
        {
            throw new EndpointConnectException(EndpointFailure.AccessDenied, $"The socket directory {directory} is not owner-only (0700).");
        }

        var entry = new FileInfo(path);
        if (!entry.Exists)
        {
            throw new EndpointConnectException(EndpointFailure.NotRunning, $"No node socket exists at {path}.");
        }

        if (entry.LinkTarget is not null)
        {
            throw new EndpointConnectException(EndpointFailure.AccessDenied, $"The node socket {path} is a link.");
        }

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch (SocketException exception)
        {
            socket.Dispose();
            throw exception.SocketErrorCode switch
            {
                // EAGAIN: the backlog (16) is full; the node is running (DesktopPlatform LocalRpc README, service mode).
                SocketError.TryAgain or SocketError.WouldBlock or SocketError.NoBufferSpaceAvailable =>
                    new EndpointConnectException(EndpointFailure.Busy, $"The node socket {path} has a full backlog (EAGAIN).", exception),
                SocketError.AccessDenied =>
                    new EndpointConnectException(EndpointFailure.AccessDenied, $"Connecting to {path} was denied.", exception),
                _ => new EndpointConnectException(EndpointFailure.NotRunning, $"No node accepts connections on {path} ({exception.SocketErrorCode}).", exception),
            };
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "WaitNamedPipeW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WaitNamedPipeW(string name, uint timeoutMilliseconds);
}
