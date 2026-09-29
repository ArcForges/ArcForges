// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.Desktop.Shell;

public enum LayoutLoadStatus
{
    Missing,
    Loaded,
    Recovered,
    Corrupt,
    Unavailable
}
public sealed record LayoutLoadResult(LayoutLoadStatus Status, LayoutSnapshot? Snapshot, int DiscardedDuplicateCount = 0);

/// <summary>
/// Persists a single application/layout pair under the caller-selected LocalApplicationData root.
/// Validated identifiers are hashed before use in the path; their raw values never become path segments.
/// </summary>
public sealed class DeviceLocalLayoutStore
{
    private const int MaximumDocumentBytes = 256 * 1024;
    private readonly ApplicationKey _application;
    private readonly LayoutKey _layout;
    private readonly string _filePath;
    private readonly AtomicLayoutFileWriter _writer;

    public DeviceLocalLayoutStore(ApplicationKey application, LayoutKey layout)
        : this(application, layout, GetLocalApplicationDataRoot(), new AtomicLayoutFileWriter())
    {
    }

    internal DeviceLocalLayoutStore(ApplicationKey application, LayoutKey layout, string localApplicationDataRoot)
        : this(application, layout, localApplicationDataRoot, new AtomicLayoutFileWriter())
    {
    }

    internal DeviceLocalLayoutStore(
        ApplicationKey application,
        LayoutKey layout,
        string localApplicationDataRoot,
        AtomicLayoutFileWriter writer)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentException.ThrowIfNullOrWhiteSpace(localApplicationDataRoot);
        ArgumentNullException.ThrowIfNull(writer);

        _application = application;
        _layout = layout;
        _writer = writer;
        var root = Path.GetFullPath(localApplicationDataRoot);
        _filePath = Path.Combine(root, "ArcForges", "DesktopLayouts", Hash("application\0" + application.Value), Hash("layout\0" + layout.Value) + ".json");
    }

    public static DeviceLocalLayoutStore ForCurrentUser(ApplicationKey application, LayoutKey layout)
        => new(application, layout);

    public LayoutLoadResult Load()
    {
        byte[] content;
        try
        {
            using var stream = new FileStream(_filePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 4096, FileOptions.SequentialScan);
            if (stream.Length > MaximumDocumentBytes)
            {
                return new LayoutLoadResult(LayoutLoadStatus.Corrupt, null);
            }

            content = new byte[checked((int)stream.Length)];
            stream.ReadExactly(content);
        }
        catch (FileNotFoundException)
        {
            return new LayoutLoadResult(LayoutLoadStatus.Missing, null);
        }
        catch (DirectoryNotFoundException)
        {
            return new LayoutLoadResult(LayoutLoadStatus.Missing, null);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new LayoutLoadResult(LayoutLoadStatus.Unavailable, null);
        }

        try
        {
            using var document = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 16 });
            if (!TryReadFields(document.RootElement, out var fields, "schemaVersion", "applicationKey", "layoutKey", "windows", "panels")
                || !TryGetInt32(fields, "schemaVersion", out var schemaVersion)
                || schemaVersion != 1
                || !TryGetString(fields, "applicationKey", out var applicationKey)
                || !string.Equals(applicationKey, _application.Value, StringComparison.Ordinal)
                || !TryGetString(fields, "layoutKey", out var layoutKey)
                || !string.Equals(layoutKey, _layout.Value, StringComparison.Ordinal)
                || fields["windows"].ValueKind != JsonValueKind.Array
                || fields["panels"].ValueKind != JsonValueKind.Array
                || fields["windows"].GetArrayLength() > 64
                || fields["panels"].GetArrayLength() > 256)
            {
                return new LayoutLoadResult(LayoutLoadStatus.Corrupt, null);
            }

            var windowsElement = fields["windows"];
            var panelsElement = fields["panels"];
            var windows = new List<WindowPlacement>(windowsElement.GetArrayLength());
            var windowIds = new HashSet<WindowId>();
            var panels = new List<PanelPlacement>(panelsElement.GetArrayLength());
            var panelIds = new HashSet<PanelKey>();
            var discardedDuplicates = 0;
            foreach (var stored in windowsElement.EnumerateArray())
            {
                if (!TryReadFields(stored, out var storedFields, "id", "display", "x", "y", "width", "height")
                    || !TryGetString(storedFields, "id", out var storedId)
                    || !TryGetString(storedFields, "display", out var storedDisplay)
                    || !TryGetDouble(storedFields, "x", out var x)
                    || !TryGetDouble(storedFields, "y", out var y)
                    || !TryGetDouble(storedFields, "width", out var width)
                    || !TryGetDouble(storedFields, "height", out var height))
                {
                    return new LayoutLoadResult(LayoutLoadStatus.Corrupt, null);
                }

                var id = WindowId.TryParse(storedId);
                var display = DisplayId.TryParse(storedDisplay);
                var bounds = new WindowBounds(x, y, width, height);
                if (id is null || display is null || !bounds.IsValid)
                {
                    return new LayoutLoadResult(LayoutLoadStatus.Corrupt, null);
                }

                if (!windowIds.Add(id))
                {
                    discardedDuplicates++;
                    continue;
                }

                windows.Add(new WindowPlacement(id, display, bounds));
            }

            foreach (var stored in panelsElement.EnumerateArray())
            {
                if (!TryReadFields(stored, out var storedFields, "key", "region", "isCollapsed", "order")
                    || !TryGetString(storedFields, "key", out var storedKey)
                    || !TryGetString(storedFields, "region", out var storedRegion)
                    || !TryGetBoolean(storedFields, "isCollapsed", out var isCollapsed)
                    || !TryGetInt32(storedFields, "order", out var order))
                {
                    return new LayoutLoadResult(LayoutLoadStatus.Corrupt, null);
                }

                var key = PanelKey.TryParse(storedKey);
                if (key is null || !Enum.TryParse<DockRegion>(storedRegion, ignoreCase: false, out var region)
                    || !Enum.IsDefined(region) || !string.Equals(storedRegion, region.ToString(), StringComparison.Ordinal)
                    || order is < 0 or > 100_000)
                {
                    return new LayoutLoadResult(LayoutLoadStatus.Corrupt, null);
                }

                if (!panelIds.Add(key))
                {
                    discardedDuplicates++;
                    continue;
                }

                panels.Add(new PanelPlacement(key, region, isCollapsed, order));
            }

            var snapshot = LayoutSnapshot.Create(_application, _layout, windows, panels);
            return new LayoutLoadResult(
                discardedDuplicates == 0 ? LayoutLoadStatus.Loaded : LayoutLoadStatus.Recovered,
                snapshot,
                discardedDuplicates);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or ArgumentException)
        {
            return new LayoutLoadResult(LayoutLoadStatus.Corrupt, null);
        }
    }

    public void Save(LayoutSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (snapshot.Application != _application || snapshot.Layout != _layout)
        {
            throw new ArgumentException("A layout snapshot must match this store's application and layout keys.", nameof(snapshot));
        }

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("applicationKey", _application.Value);
            writer.WriteString("layoutKey", _layout.Value);
            writer.WriteStartArray("windows");
            foreach (var item in snapshot.Windows)
            {
                writer.WriteStartObject();
                writer.WriteString("id", item.Id.Value);
                writer.WriteString("display", item.Display.Value);
                writer.WriteNumber("x", item.Bounds.X);
                writer.WriteNumber("y", item.Bounds.Y);
                writer.WriteNumber("width", item.Bounds.Width);
                writer.WriteNumber("height", item.Bounds.Height);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteStartArray("panels");
            foreach (var item in snapshot.Panels)
            {
                writer.WriteStartObject();
                writer.WriteString("key", item.Key.Value);
                writer.WriteString("region", item.Region.ToString());
                writer.WriteBoolean("isCollapsed", item.IsCollapsed);
                writer.WriteNumber("order", item.Order);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        var content = buffer.WrittenSpan.ToArray();
        if (content.Length > MaximumDocumentBytes)
        {
            throw new InvalidOperationException("The layout document exceeds its size limit.");
        }

        _writer.WriteAtomically(_filePath, content);
    }

    internal string StoragePath => _filePath;

    private static bool TryReadFields(JsonElement element, out Dictionary<string, JsonElement> fields, params string[] requiredFields)
    {
        fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        foreach (var property in element.EnumerateObject())
        {
            if (!requiredFields.Contains(property.Name, StringComparer.Ordinal) || !fields.TryAdd(property.Name, property.Value))
            {
                return false;
            }
        }

        return requiredFields.All(fields.ContainsKey);
    }

    private static bool TryGetString(Dictionary<string, JsonElement> fields, string name, out string value)
    {
        var element = fields[name];
        if (element.ValueKind != JsonValueKind.String)
        {
            value = string.Empty;
            return false;
        }

        value = element.GetString()!;
        return true;
    }

    private static bool TryGetInt32(Dictionary<string, JsonElement> fields, string name, out int value)
    {
        var element = fields[name];
        if (element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out value))
        {
            return true;
        }

        value = default;
        return false;
    }

    private static bool TryGetDouble(Dictionary<string, JsonElement> fields, string name, out double value)
    {
        var element = fields[name];
        if (element.ValueKind == JsonValueKind.Number && element.TryGetDouble(out value))
        {
            return true;
        }

        value = default;
        return false;
    }

    private static bool TryGetBoolean(Dictionary<string, JsonElement> fields, string name, out bool value)
    {
        var element = fields[name];
        if (element.ValueKind == JsonValueKind.True)
        {
            value = true;
            return true;
        }

        if (element.ValueKind == JsonValueKind.False)
        {
            value = false;
            return true;
        }

        value = false;
        return false;
    }

    private static string GetLocalApplicationDataRoot()
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return string.IsNullOrWhiteSpace(root)
            ? throw new InvalidOperationException("The platform did not provide a LocalApplicationData directory.")
            : root;
    }

    private static string Hash(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

internal sealed class AtomicLayoutFileWriter(Action? beforeReplace = null)
{
    internal void WriteAtomically(string targetPath, ReadOnlySpan<byte> content)
    {
        var directory = Path.GetDirectoryName(targetPath)
            ?? throw new InvalidOperationException("The layout file must have a parent directory.");
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(directory, $".{Path.GetFileName(targetPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }

            beforeReplace?.Invoke();
            File.Move(temporaryPath, targetPath, overwrite: true);
        }
        finally
        {
            try
            {
                File.Delete(temporaryPath);
            }
            catch (IOException)
            {
                // Preserve the original write/replace exception. A later save may clean this orphaned temp file.
            }
            catch (UnauthorizedAccessException)
            {
                // Preserve the original write/replace exception. The target remains either the old or new document.
            }
        }
    }
}
