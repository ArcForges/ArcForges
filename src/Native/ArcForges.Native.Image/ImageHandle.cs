// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.InteropServices;
using ArcForges.Native.Abstractions;

namespace ArcForges.Native.Image;

// Owns one arc_handle_t generation token and the GCHandle that keeps the managed byte source reachable for
// the native callbacks. The token is released through arc_image_close; the callback context is freed only
// after that close succeeds, so native code never calls into a freed source.
internal sealed class ImageHandle : NativeSafeHandle
{
    private GCHandle _context;

    internal ImageHandle(ulong token, GCHandle context)
        : base(token)
    {
        _context = context;
    }

    protected override NativeStatus ReleaseNativeToken(ulong token)
    {
        NativeStatus status = ImageAbi.CloseNative(token);
        if ((status is NativeStatus.Ok or NativeStatus.Closed) && _context.IsAllocated)
        {
            _context.Free();
        }

        return status;
    }
}
