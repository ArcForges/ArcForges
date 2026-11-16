# Third-party components

ArcForges source is AGPL-3.0-only. Dependencies retain their own licenses.
The exact versions and content hashes are recorded in `Directory.Packages.props`
and the committed `packages.lock.json` files.

| Component | Upstream / license |
| --- | --- |
| Microsoft.Mxc.Sdk and official MXC executor (isolated admission probe only) | [microsoft/mxc](https://github.com/microsoft/mxc) 1.0.1, MIT; exact native unit, bundled SPDX and license limitations in `eng/mxc/README.md` |
| Tmds.DBus.Protocol | [Tmds.DBus](https://github.com/tmds/Tmds.DBus), MIT |
| Microsoft.Data.Sqlite | [dotnet/efcore](https://github.com/dotnet/efcore) (built in [dotnet/dotnet](https://github.com/dotnet/dotnet)), MIT |
| SQLitePCLRaw and the bundled SQLite (`e_sqlite3`) | [SQLitePCL.raw](https://github.com/ericsink/SQLitePCL.raw), Apache-2.0; [SQLite](https://sqlite.org/copyright.html), public domain |
| Google.Protobuf | [protobuf](https://github.com/protocolbuffers/protobuf), BSD-3-Clause |
| Grpc.Core.Api, Grpc.Net.Client, Grpc.Net.Client.Web, Grpc.Net.Common, Grpc.AspNetCore.Server | [grpc-dotnet](https://github.com/grpc/grpc-dotnet), Apache-2.0 |
| ASP.NET Core (Kestrel, the `Microsoft.AspNetCore.App` shared framework) and Microsoft.Extensions.* abstractions | [dotnet/aspnetcore](https://github.com/dotnet/aspnetcore) and [dotnet/runtime](https://github.com/dotnet/runtime), MIT |
| Azure.Core, Azure.Monitor.OpenTelemetry.Exporter and System.ClientModel | [Azure SDK for .NET](https://github.com/Azure/azure-sdk-for-net), MIT; transitive telemetry implementation dependencies |
| Microsoft.ApplicationInsights and Microsoft.Identity.* | [Application Insights](https://github.com/microsoft/ApplicationInsights-dotnet) and [MSAL](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet), MIT |
| OpenTelemetry and its hosting/persistent-storage components | [OpenTelemetry .NET](https://github.com/open-telemetry/opentelemetry-dotnet) and [contrib](https://github.com/open-telemetry/opentelemetry-dotnet-contrib), Apache-2.0 |
| System.CommandLine | [dotnet/command-line-api](https://github.com/dotnet/command-line-api), MIT |
| ArcForges.Contracts.* (the internal ArcForges.Contracts.Relay included), ArcForges.Sdk.Contracts | [ArcForges Contracts](https://github.com/ArcForges/Contracts), Apache-2.0 |
| ArcForges.LocalRpc, ArcForges.Observability, ArcForges.Capabilities, ArcForges.Security.Secrets, ArcForges.Security, ArcForges.Foundation | [ArcForges DesktopPlatform](https://github.com/ArcForges/DesktopPlatform), AGPL-3.0-only |
| .NET runtime | [dotnet/runtime](https://github.com/dotnet/runtime), MIT plus third-party notices |
| xUnit and Microsoft.Testing.Platform | Test-only dependencies; see their NuGet license metadata |
| CsCheck | Test-only dependency ([CsCheck](https://github.com/AnthonyLloyd/CsCheck)), Apache-2.0 |
| Grpc.Tools | Build-only code generator (protoc); see its NuGet license metadata |

System libraries and fonts come from the host OS. No font or proprietary asset is bundled.
The private native build-tool selector is adapted from Apache-2.0 Contracts
tooling; its retained terms are `third-party/Contracts.NativeTooling.LICENSE.txt`
and its exact source/reuse record is `eng/policy/native-tooling-reuse.json`.
External LLVM/GNU compiler source, tools and source-context patches are not
included in runtime packages.
Portable CI archives include the project license, this notice, the resolved application
dependency lock and bundled third-party license texts.
