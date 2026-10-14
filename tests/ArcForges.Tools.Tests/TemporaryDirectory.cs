// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Tools.Tests;

internal sealed class TemporaryDirectory : IDisposable
{
    public TemporaryDirectory() => Directory.CreateDirectory(Path);

    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "arcforges-tools-tests-" + Guid.NewGuid().ToString("N"));

    public string File(string relative, int bytes)
    {
        var path = System.IO.Path.Combine(Path, relative);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        System.IO.File.WriteAllBytes(path, new byte[bytes]);
        return path;
    }

    public void Dispose() => Directory.Delete(Path, recursive: true);
}
