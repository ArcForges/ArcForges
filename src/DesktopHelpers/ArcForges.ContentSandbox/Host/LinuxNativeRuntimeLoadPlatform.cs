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
internal sealed unsafe partial class LinuxNativeRuntimeLoadPlatform : INativeRuntimeLoadPlatform, IDisposable
{
    private readonly SafeFileHandle _directory;
    private readonly string _locator;
    private readonly object _gate = new();
    private readonly Dictionary<nint, int> _loadedHandles = [];
    private readonly Dictionary<string, SealedFile> _sealedFiles = new(StringComparer.Ordinal);
    private long _sealedBytes;
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
            if (_sealedFiles.Count >= 128) { throw new InvalidDataException("The retained native file inventory exceeds its production bound."); }
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
            if (input.Length > 512L * 1024 * 1024 - _sealedBytes) { throw new InvalidDataException("The retained native closure exceeds its production byte bound."); }
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
                    if (total > 256L * 1024 * 1024 || total > 512L * 1024 * 1024 - _sealedBytes)
                    {
                        throw new InvalidDataException("The native source grew beyond its production bound.");
                    }
                    output.Write(buffer.AsSpan(0, count));
                }

                output.Flush();
                if (LinuxNative.Syscall(_arm ? 25 : 72, sealedDescriptor, 1033, 1 | 2 | 4 | 8, 0, 0) != 0) // F_ADD_SEALS: SEAL|SHRINK|GROW|WRITE.
                {
                    throw new IOException("The immutable native memfd seals could not be established: " + Marshal.GetLastPInvokeError());
                }

                cancellationToken.ThrowIfCancellationRequested();
                output.Position = 0;
                var lease = new SealedFile(this, output, "/proc/self/fd/" + (int)sealedDescriptor, total);
                _sealedFiles.Add(lease.LoaderPath, lease);
                _sealedBytes += total;
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

    public nint Load(string loaderPath)
    {
        const string prefix = "/proc/self/fd/";
        if (!loaderPath.StartsWith(prefix, StringComparison.Ordinal) || loaderPath.Length > 64
            || !int.TryParse(loaderPath.AsSpan(prefix.Length), System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var descriptor) || descriptor <= 0)
        {
            throw new InvalidDataException("Linux native loading requires its retained sealed-file locator.");
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_sealedFiles.ContainsKey(loaderPath)) { throw new InvalidDataException("Foreign or released native sealed-file locator."); }
            if (_loadedHandles.Values.Sum() >= 128) { throw new InvalidDataException("The retained native module inventory exceeds its production bound."); }
            _ = DlError();
            // NOW refuses unresolved symbols before an apparently successful handle
            // can escape. LOCAL avoids introducing symbols into the global namespace.
            var handle = DlOpen(loaderPath, 2);
            if (handle == 0) { throw new DllNotFoundException("Immediate native linkage refused the verified closure."); }
            _loadedHandles.TryGetValue(handle, out var references);
            _loadedHandles[handle] = checked(references + 1);
            return handle;
        }
    }

    public bool HasExport(nint handle, string name)
    {
        if (handle == 0 || string.IsNullOrEmpty(name) || name.Length > 128
            || name.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_'))
        {
            throw new ArgumentException("Invalid owned native export lookup.");
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_loadedHandles.ContainsKey(handle)) { throw new InvalidOperationException("Foreign or released native closure handle."); }
            _ = DlError();
            var address = DlSym(handle, name);
            return DlError() == 0 && address != 0;
        }
    }

    public void Free(nint handle)
    {
        if (handle == 0) { return; }
        lock (_gate)
        {
            if (!_loadedHandles.TryGetValue(handle, out var references)) { throw new InvalidOperationException("Foreign or released native closure handle."); }
            if (DlClose(handle) != 0) { throw new InvalidOperationException("Native closure handle release failed."); }
            if (references == 1) { _loadedHandles.Remove(handle); }
            else { _loadedHandles[handle] = references - 1; }
        }
    }

    [LibraryImport("libdl.so.2", EntryPoint = "dlopen", StringMarshalling = StringMarshalling.Utf8)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial nint DlOpen(string path, int flags);
    [LibraryImport("libdl.so.2", EntryPoint = "dlsym", StringMarshalling = StringMarshalling.Utf8)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial nint DlSym(nint handle, string name);
    [LibraryImport("libdl.so.2", EntryPoint = "dlclose")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int DlClose(nint handle);
    [LibraryImport("libdl.so.2", EntryPoint = "dlerror")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial nint DlError();
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) { return; }
            _disposed = true;
            var failures = new List<Exception>();
            foreach (var pair in _loadedHandles)
            {
                for (var index = 0; index < pair.Value; index++)
                {
                    if (DlClose(pair.Key) != 0) { failures.Add(new InvalidOperationException("Native module disposal failed.")); }
                }
            }

            _loadedHandles.Clear();
            foreach (var lease in _sealedFiles.Values.ToArray())
            {
                try { lease.Dispose(); }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException) { failures.Add(error); }
            }

            _directory.Dispose();
            if (failures.Count != 0) { throw new AggregateException("Native platform disposal failed.", failures); }
        }
    }

    private static byte[] Utf8(string value) => new UTF8Encoding(false, true).GetBytes(value + "\0");
    internal sealed class SealedFile(LinuxNativeRuntimeLoadPlatform owner, FileStream bytes, string loaderPath, long length) : INativeRuntimeFileLease
    {
        private bool _disposed;
        public Stream Bytes => bytes;
        public string LoaderPath => loaderPath;
        public void Dispose()
        {
            lock (owner._gate)
            {
                if (_disposed) { return; }
                _disposed = true;
                try { bytes.Dispose(); }
                finally
                {
                    owner._sealedFiles.Remove(loaderPath);
                    owner._sealedBytes -= length;
                }
            }
        }
    }
}
