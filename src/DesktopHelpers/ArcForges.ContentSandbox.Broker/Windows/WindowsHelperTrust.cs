// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.ContentSandbox.Broker.Native;

namespace ArcForges.ContentSandbox.Broker.Windows;

/// <summary>Standard Windows Authenticode chain/revocation verification over the executable handle the launcher actually retains.</summary>
[SupportedOSPlatform("windows")]
internal static unsafe class WindowsHelperTrust
{
    internal static void Verify(FileStream executable, string path, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(executable);
        cancellationToken.ThrowIfCancellationRequested();
        var action = new Guid("00aac56b-cd44-11d0-8cc2-00c04fc295ee");
        var name = Marshal.StringToCoTaskMemUni(path);
        var retained = false;
        try
        {
            executable.SafeFileHandle.DangerousAddRef(ref retained);
            var file = new WindowsNative.WinTrustFileInfo
            {
                StructSize = (uint)sizeof(WindowsNative.WinTrustFileInfo),
                FilePath = name,
                FileHandle = executable.SafeFileHandle.DangerousGetHandle(),
            };
            var data = new WindowsNative.WinTrustData
            {
                StructSize = (uint)sizeof(WindowsNative.WinTrustData),
                UiChoice = 2, // WTD_UI_NONE: no interactive certificate prompt is permitted.
                RevocationChecks = 1, // WTD_REVOKE_WHOLECHAIN.
                UnionChoice = 1, // WTD_CHOICE_FILE, with the actual held hFile.
                FileInfo = (nint)(&file),
                StateAction = 1, // WTD_STATEACTION_VERIFY.
                ProviderFlags = 0x80, // WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT.
            };
            try
            {
                var status = WindowsNative.WinVerifyTrust(0, &action, &data);
                if (status != 0)
                {
                    throw new CryptographicException($"The held helper executable failed standard Authenticode trust (0x{unchecked((uint)status):x8}).");
                }
            }
            finally
            {
                data.StateAction = 2; // Always release provider state, including rejected signatures.
                _ = WindowsNative.WinVerifyTrust(0, &action, &data);
            }

            // WinVerifyTrust is synchronous and has no cancellation API. Cancellation never reports
            // success during that native call; it is checked again immediately after state cleanup.
            cancellationToken.ThrowIfCancellationRequested();
        }
        finally
        {
            if (retained) { executable.SafeFileHandle.DangerousRelease(); }
            Marshal.FreeCoTaskMem(name);
        }
    }
}
