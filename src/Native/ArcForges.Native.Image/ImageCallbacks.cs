// SPDX-License-Identifier: AGPL-3.0-only

using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ArcForges.Native.Abstractions;

namespace ArcForges.Native.Image;

// Entry points that native code calls back into. They run on the thread that is executing the native
// call, never throw across the ABI, and hold no managed monitor while they run.
internal static unsafe class ImageCallbacks
{
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types",
        Justification = "A managed source failure must become an IO status at the native boundary, never an exception across it.")]
    internal static int ReadAt(nint context, ulong offset, nint destination, ulong count, ulong* done)
    {
        try
        {
            if (done == null)
            {
                return (int)NativeStatus.InvalidArgument;
            }

            *done = 0;
            if (count == 0)
            {
                return (int)NativeStatus.Ok;
            }

            if (context == 0 || destination == 0 || count > int.MaxValue || offset > long.MaxValue)
            {
                return (int)NativeStatus.InvalidArgument;
            }

            if (GCHandle.FromIntPtr(context).Target is not ImageByteSource source)
            {
                return (int)NativeStatus.Internal;
            }

            int read = source.ReadAt((long)offset, new Span<byte>((void*)destination, (int)count));
            if (read < 0 || read > (int)count)
            {
                return (int)NativeStatus.Io;
            }

            *done = (ulong)read;
            return (int)NativeStatus.Ok;
        }
        catch (Exception)
        {
            if (done != null)
            {
                *done = 0;
            }

            return (int)NativeStatus.Io;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types",
        Justification = "A cancellation probe that cannot read its state must report cancelled, so native code stops.")]
    internal static byte IsCancelled(nint userData)
    {
        try
        {
            return GCHandle.FromIntPtr(userData).Target is CancellationState state && !state.Token.IsCancellationRequested
                ? (byte)0
                : (byte)1;
        }
        catch (Exception)
        {
            return 1;
        }
    }
}

// Carries one caller's CancellationToken into a native call. The GCHandle lives only for that call.
internal sealed class CancellationState(CancellationToken token)
{
    internal CancellationToken Token { get; } = token;
}

// Owns the pinned cancellation state for one native call. Dispose after the call returns.
internal sealed unsafe class CancellationBridge : IDisposable
{
    private readonly GCHandle _state;

    internal CancellationBridge(CancellationToken token)
    {
        Enabled = token.CanBeCanceled;
        _state = GCHandle.Alloc(new CancellationState(token));
    }

    internal bool Enabled { get; }

    internal NativeCancelToken Token => new()
    {
        StructSize = (uint)sizeof(NativeCancelToken),
        StructVersion = NativeAbiConstants.RecordVersion1,
        IsCancelled = &ImageCallbacks.IsCancelled,
        UserData = GCHandle.ToIntPtr(_state),
    };

    public void Dispose()
    {
        _state.Free();
    }
}
