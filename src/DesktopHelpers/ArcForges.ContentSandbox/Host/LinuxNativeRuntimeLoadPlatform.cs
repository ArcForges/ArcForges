// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using ArcForges.ContentSandbox.Native;
using ArcForges.Native.Abstractions;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.ContentSandbox.Host;

/// <summary>A canonical signed native-root locator remains pinned independently of /proc/self/exe or AppContext.BaseDirectory.</summary>
[SupportedOSPlatform("linux")]
internal sealed unsafe class LinuxNativeRuntimeLoadPlatform : INativeRuntimeLoadPlatform, IDisposable
{
    private readonly SafeFileHandle _directory;
    private readonly string _locator;
    private readonly object _gate = new();
    private readonly bool _arm;
    private bool _disposed;

    internal LinuxNativeRuntimeLoadPlatform(string canonicalDirectory)
    {
        if (!OperatingSystem.IsLinux() || !Path.IsPathFullyQualified(canonicalDirectory)
            || Path.GetFullPath(canonicalDirectory) != canonicalDirectory)
        {
            throw new InvalidDataException("Linux native loading requires an explicit canonical signed directory locator.");
        }

        _locator = canonicalDirectory;
        _arm = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.Arm64 => true,
            Architecture.X64 => false,
            _ => throw new PlatformNotSupportedException("Only the admitted Linux architectures are supported."),
        };
        var bytes = Utf8(canonicalDirectory);
        nint descriptor;
        fixed (byte* path = bytes)
        {
            descriptor = LinuxNative.Syscall(_arm ? 56 : 257, -100, (nint)path, 0x10000 | 0x20000 | 0x80000, 0, 0); // openat: O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC.
        }

        if (descriptor < 0 || descriptor > int.MaxValue)
        {
            throw new IOException("The signed native directory could not be pinned: " + Marshal.GetLastPInvokeError());
        }

        _directory = new SafeFileHandle(descriptor, ownsHandle: true);
        try
        {
            var resolved = Directory.ResolveLinkTarget("/proc/self/fd/" + (int)descriptor, returnFinalTarget: true)?.FullName;
            if (resolved != canonicalDirectory)
            {
                throw new InvalidDataException("The native directory locator resolves through an unexpected path.");
            }
        }
        catch
        {
            _directory.Dispose();
            throw;
        }
    }

    public string Rid => _arm ? "linux-arm64" : "linux-x64";

    INativeRuntimeFileLease INativeRuntimeLoadPlatform.Open(string directory, string name, CancellationToken cancellationToken) =>
        OpenSnapshot(directory, name, cancellationToken);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000", Justification = "The complete sealed-file owner transfers to the returned lease; finally disposes both partially constructed owners on every preparation failure.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1508", Justification = "Owners are null on the success transfer path, but remain non-null on constructor/read/write/seal/cancellation exception paths and must be cleaned in finally.")]
    internal SealedFile OpenSnapshot(string directory, string name, CancellationToken cancellationToken)
    {
        // The signed directory is pinned by the constructor; directory is never inferred from a sealed executable pathname.
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            cancellationToken.ThrowIfCancellationRequested();
            if (directory != _locator || string.IsNullOrEmpty(name) || name != Path.GetFileName(name) || name.Contains('\\', StringComparison.Ordinal) || name.Contains(':', StringComparison.Ordinal))
            {
                throw new InvalidDataException("The sealed native filename is invalid.");
            }

            var nameBytes = Utf8(name);
            nint sourceDescriptor;
            fixed (byte* source = nameBytes)
            {
                sourceDescriptor = LinuxNative.Syscall(_arm ? 56 : 257, _directory.DangerousGetHandle(), (nint)source, 0x20000 | 0x80000 | 0x800, 0, 0); // openat pinned dir, read-only, no symlink.
            }

            if (sourceDescriptor < 0) { throw new IOException("The pinned native member could not be opened: " + Marshal.GetLastPInvokeError()); }
            using var sourceHandle = new SafeFileHandle(sourceDescriptor, ownsHandle: true);
            using var input = new FileStream(sourceHandle, FileAccess.Read);
            if (input.Length is 0 or > 256L * 1024 * 1024) { throw new InvalidDataException("The native member exceeds its production bound."); }
            nint sealedDescriptor;
            fixed (byte* label = nameBytes)
            {
                sealedDescriptor = LinuxNative.Syscall(_arm ? 279 : 319, (nint)label, 1 | 2 | 0x10, 0, 0, 0); // memfd: CLOEXEC|ALLOW_SEALING|EXEC, never a mutable installed mapping.
            }

            if (sealedDescriptor < 0) { throw new IOException("Executable sealed native bytes are unavailable: " + Marshal.GetLastPInvokeError()); }
            SafeFileHandle? handle = null;
            FileStream? output = null;
            try
            {
                handle = new SafeFileHandle(sealedDescriptor, ownsHandle: true);
                output = new FileStream(handle, FileAccess.ReadWrite);
                handle = null; // FileStream now owns the descriptor, including failed preparation paths.
                var buffer = new byte[64 * 1024];
                long total = 0;
                int count;
                while ((count = input.Read(buffer)) != 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    total = checked(total + count);
                    if (total > 256L * 1024 * 1024) { throw new InvalidDataException("The native source grew beyond its production bound."); }
                    output.Write(buffer.AsSpan(0, count));
                }

                output.Flush();
                if (LinuxNative.Syscall(_arm ? 25 : 72, sealedDescriptor, 1033, 1 | 2 | 4 | 8, 0, 0) != 0) // F_ADD_SEALS: SEAL|SHRINK|GROW|WRITE.
                {
                    throw new IOException("The immutable native memfd seals could not be established: " + Marshal.GetLastPInvokeError());
                }

                cancellationToken.ThrowIfCancellationRequested();
                output.Position = 0;
                var lease = new SealedFile(output, "/proc/self/fd/" + (int)sealedDescriptor);
                output = null; // Complete immutable-file lifetime transfers to the returned lease.
                return lease;
            }
            finally
            {
                try { output?.Dispose(); }
                finally { handle?.Dispose(); }
            }
        }
    }

    public nint Load(string loaderPath) => NativeLibrary.Load(loaderPath);
    public bool HasExport(nint handle, string name) => NativeLibrary.TryGetExport(handle, name, out _);
    public void Free(nint handle) => NativeLibrary.Free(handle);
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) { return; }
            _disposed = true;
            _directory.Dispose();
        }
    }

    private static byte[] Utf8(string value) => new UTF8Encoding(false, true).GetBytes(value + "\0");
    internal sealed class SealedFile(FileStream bytes, string loaderPath) : INativeRuntimeFileLease
    {
        public Stream Bytes => bytes;
        public string LoaderPath => loaderPath;
        public void Dispose() => bytes.Dispose();
    }
}
