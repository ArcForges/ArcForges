// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.LocalRpc;

namespace ArcForges.ContentSandbox.Host;

/// <summary>One output slot mapped writable into the helper. Disposing it unmaps it and closes what it owns.</summary>
internal interface IHelperSlot : IParserSlot, IDisposable
{
}

/// <summary>
/// The closed OS inventory the helper received, already wrapped: the two private streams, the read-only input and the output slots. It is
/// everything the helper may touch outside its own memory; nothing is looked up by name or path.
/// </summary>
internal sealed class HelperResources(
    Stream control,
    Stream service,
    ILocalRpcBufferMapping input,
    IReadOnlyList<IHelperSlot> slots) : IAsyncDisposable
{
    /// <summary>The stream on which the helper calls the parent's bootstrap service.</summary>
    internal Stream Control { get; } = control;

    /// <summary>The stream on which the helper serves the sandbox service to its parent.</summary>
    internal Stream Service { get; } = service;

    /// <summary>The read-only input.</summary>
    internal ILocalRpcBufferMapping Input { get; } = input;

    /// <summary>The output slots, in slot order.</summary>
    internal IReadOnlyList<IHelperSlot> Slots { get; } = slots;

    /// <summary>Releases the mappings and the streams.</summary>
    public async ValueTask DisposeAsync()
    {
        foreach (var slot in Slots)
        {
            slot.Dispose();
        }

        Input.Dispose();
        await Control.DisposeAsync().ConfigureAwait(false);
        await Service.DisposeAsync().ConfigureAwait(false);
    }
}
