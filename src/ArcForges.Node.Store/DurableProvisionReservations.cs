// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Text;
using System.Text.Json;

namespace ArcForges.Node.Store;

internal sealed partial class DurableCommandStore
{
    private const string GrantReservationField = "_reservedRemoteGrantSlots";
    private const string GrantReservationPath = "$." + GrantReservationField;
    private const string ProvisionBindingField = "_provisionBinding";

    private static bool ValidProvisionBinding(DurableProvisionBinding binding) =>
        IsGrantIdentity(binding.ParentGrantId) && IsGrantIdentity(binding.DerivedGrantId)
        && binding.ParentGrantId != binding.DerivedGrantId && binding.ParentGrantRevision > 0;

    private static DurableProvisionBinding? ReadProvisionReservation(string json)
    {
        using var document = JsonDocument.Parse(json);
        var body = document.RootElement;
        if (body.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        bool hasSlot = body.TryGetProperty(GrantReservationField, out var slot);
        bool hasBinding = body.TryGetProperty(ProvisionBindingField, out var record);
        if (!hasSlot && !hasBinding)
        {
            return null;
        }

        if (slot.ValueKind == JsonValueKind.Number && slot.TryGetInt32(out int slots) && slots == 1
            && record.ValueKind == JsonValueKind.Object
            && record.TryGetProperty("parentGrantId", out var parent) && parent.ValueKind == JsonValueKind.String
            && record.TryGetProperty("parentGrantRevision", out var revision) && revision.ValueKind == JsonValueKind.Number
            && revision.TryGetInt64(out long parentRevision)
            && record.TryGetProperty("derivedGrantId", out var derived) && derived.ValueKind == JsonValueKind.String)
        {
            var binding = new DurableProvisionBinding(parent.GetString()!, parentRevision, derived.GetString()!);
            if (ValidProvisionBinding(binding))
            {
                return binding;
            }
        }

        throw new DurableStoreMaintenanceException();
    }

    private static string WriteProvisionReservation(string? summary, DurableProvisionBinding binding)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer);
        writer.WriteStartObject();
        if (summary is not null)
        {
            using var document = JsonDocument.Parse(summary);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new ArgumentException("Provisioning uncertainty requires a bounded result object.", nameof(summary));
            }

            foreach (var field in document.RootElement.EnumerateObject())
            {
                if (!field.NameEquals(GrantReservationField) && !field.NameEquals(ProvisionBindingField))
                {
                    field.WriteTo(writer);
                }
            }
        }

        writer.WriteNumber(GrantReservationField, 1);
        writer.WriteStartObject(ProvisionBindingField);
        writer.WriteString("parentGrantId", binding.ParentGrantId);
        writer.WriteNumber("parentGrantRevision", binding.ParentGrantRevision);
        writer.WriteString("derivedGrantId", binding.DerivedGrantId);
        writer.WriteEndObject();
        writer.WriteEndObject();
        writer.Flush();
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }
}
