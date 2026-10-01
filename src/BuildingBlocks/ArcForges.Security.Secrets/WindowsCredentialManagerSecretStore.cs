// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace ArcForges.Security.Secrets;

/// <summary>
/// Current-Windows-user Credential Manager adapter. Credential Manager is shared by every process of the same user,
/// so this store declares <see cref="SecretStoreIsolation.SameUserShared"/>: application isolation is the bound broker
/// namespace only, and a hostile same-user sibling that bypasses the broker is not stopped by the OS.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsCredentialManagerSecretStore : ISecretBackingStore
{
    private const uint GenericCredential = 1;
    private const uint PersistLocalMachine = 2;
    private const int CredentialNotFound = 1168;
    private const int MaximumCredentialBytes = 2560;
    private const string TargetPrefix = "ArcForges.Secrets.v1.";

    public SecretStoreIsolation Isolation => SecretStoreIsolation.SameUserShared;

    public void Write(string opaqueTarget, ReadOnlySpan<byte> secret)
    {
        ValidateTarget(opaqueTarget);
        if (secret.IsEmpty || secret.Length > MaximumCredentialBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(secret), "Credential Manager values must be between 1 and 2560 bytes.");
        }

        IntPtr target = IntPtr.Zero;
        IntPtr username = IntPtr.Zero;
        IntPtr blob = IntPtr.Zero;
        byte[] temporary = secret.ToArray();
        try
        {
            target = Marshal.StringToHGlobalUni(opaqueTarget);
            username = Marshal.StringToHGlobalUni("ArcForges");
            blob = Marshal.AllocHGlobal(temporary.Length);
            Marshal.Copy(temporary, 0, blob, temporary.Length);
            var credential = new NativeCredential
            {
                Type = GenericCredential,
                TargetName = target,
                CredentialBlobSize = (uint)temporary.Length,
                CredentialBlob = blob,
                Persist = PersistLocalMachine,
                UserName = username,
            };

            if (!CredWriteW(ref credential, 0)) throw LastError("Windows Credential Manager could not store the secret.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(temporary);
            ZeroAndFree(blob, secret.Length);
            if (target != IntPtr.Zero) Marshal.FreeHGlobal(target);
            if (username != IntPtr.Zero) Marshal.FreeHGlobal(username);
        }
    }

    public byte[]? Read(string opaqueTarget)
    {
        ValidateTarget(opaqueTarget);
        if (!CredReadW(opaqueTarget, GenericCredential, 0, out IntPtr credentialPointer))
        {
            int error = Marshal.GetLastPInvokeError();
            if (error == CredentialNotFound) return null;
            throw new Win32Exception(error, "Windows Credential Manager could not read the secret.");
        }

        NativeCredential credential = default;
        try
        {
            credential = Marshal.PtrToStructure<NativeCredential>(credentialPointer);
            if (credential.CredentialBlobSize is 0 or > MaximumCredentialBytes || credential.CredentialBlob == IntPtr.Zero)
            {
                throw new InvalidDataException("Windows Credential Manager returned an invalid secret length.");
            }

            var secret = new byte[checked((int)credential.CredentialBlobSize)];
            Marshal.Copy(credential.CredentialBlob, secret, 0, secret.Length);
            return secret;
        }
        finally
        {
            if (credential.CredentialBlob != IntPtr.Zero
                && credential.CredentialBlobSize is > 0 and <= MaximumCredentialBytes)
            {
                ZeroMemory(credential.CredentialBlob, checked((int)credential.CredentialBlobSize));
            }

            CredFree(credentialPointer);
        }
    }

    public bool Delete(string opaqueTarget)
    {
        ValidateTarget(opaqueTarget);
        if (CredDeleteW(opaqueTarget, GenericCredential, 0)) return true;
        int error = Marshal.GetLastPInvokeError();
        if (error == CredentialNotFound) return false;
        throw new Win32Exception(error, "Windows Credential Manager could not delete the secret.");
    }

    private static void ValidateTarget(string opaqueTarget)
    {
        ArgumentNullException.ThrowIfNull(opaqueTarget);
        if (opaqueTarget.Length != TargetPrefix.Length + 64 || !opaqueTarget.StartsWith(TargetPrefix, StringComparison.Ordinal))
        {
            throw new ArgumentException("Only canonical opaque ArcForges targets are accepted.", nameof(opaqueTarget));
        }

        foreach (char character in opaqueTarget.AsSpan(TargetPrefix.Length))
        {
            if (character is not (>= '0' and <= '9' or >= 'A' and <= 'F'))
            {
                throw new ArgumentException("Only canonical opaque ArcForges targets are accepted.", nameof(opaqueTarget));
            }
        }
    }

    private static Win32Exception LastError(string message) => new(Marshal.GetLastPInvokeError(), message);

    private static void ZeroAndFree(IntPtr address, int length)
    {
        if (address == IntPtr.Zero) return;
        for (int index = 0; index < length; index++) Marshal.WriteByte(address, index, 0);
        Marshal.FreeHGlobal(address);
    }

    private static void ZeroMemory(IntPtr address, int length)
    {
        for (int index = 0; index < length; index++) Marshal.WriteByte(address, index, 0);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCredential
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public long LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [LibraryImport("Advapi32.dll", EntryPoint = "CredWriteW", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredWriteW(ref NativeCredential credential, uint flags);

    [LibraryImport("Advapi32.dll", EntryPoint = "CredReadW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredReadW(string target, uint type, uint flags, out IntPtr credential);

    [LibraryImport("Advapi32.dll", EntryPoint = "CredDeleteW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredDeleteW(string target, uint type, uint flags);

    [LibraryImport("Advapi32.dll", EntryPoint = "CredFree")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial void CredFree(IntPtr buffer);
}

/// <summary>Fail-closed selection of the platform secret store (secure storage is the one fatal slot, DG-04).</summary>
public static class OsSecretStore
{
    /// <summary>
    /// Returns the OS secret-store adapter of the current platform, or throws <see cref="PlatformNotSupportedException"/>.
    /// It never falls back to files, preferences, environment variables or memory.
    /// </summary>
    public static ISecretBackingStore CreateForCurrentPlatform() => Create(OperatingSystem.IsWindows());

    internal static ISecretBackingStore Create(bool isWindows)
    {
        if (isWindows && OperatingSystem.IsWindows()) return new WindowsCredentialManagerSecretStore();
        throw new PlatformNotSupportedException(
            "No validated OS secret-store adapter exists for this platform; the application must not start without protected storage.");
    }
}
