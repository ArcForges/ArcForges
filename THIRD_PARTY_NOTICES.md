# Third-party components

ArcForges source is AGPL-3.0-only. Dependencies retain their own licenses.
The exact versions and content hashes are recorded in `Directory.Packages.props`
and the committed `packages.lock.json` files.

| Component | Upstream / license |
| --- | --- |
| Avalonia and its desktop backends | [Avalonia](https://github.com/AvaloniaUI/Avalonia), MIT |
| SkiaSharp / HarfBuzzSharp | [SkiaSharp](https://github.com/mono/SkiaSharp), MIT plus native third-party notices |
| MicroCom.Runtime | [MicroCom](https://github.com/kekekeks/MicroCom), MIT |
| Tmds.DBus.Protocol | [Tmds.DBus](https://github.com/tmds/Tmds.DBus), MIT |
| .NET runtime | [dotnet/runtime](https://github.com/dotnet/runtime), MIT plus third-party notices |
| xUnit and Microsoft.Testing.Platform | Test-only dependencies; see their NuGet license metadata |

System libraries and fonts come from the host OS. No font or proprietary asset is bundled.
Portable CI archives include the project license, this notice, the resolved application
dependency lock and bundled third-party license texts.
