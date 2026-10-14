# ArcForges

**Your machine. Your rules.**

The native desktop foundation for ArcForges: putting AI-driven work under your control.
C# · Avalonia · Native AOT. No browser shell. No cloud required to say hello.

This first slice is deliberately small: a working, offline **Hello World** window.
Enter a name, press **Say hello**, and make it yours. Resource control, agent orchestration
and cloud integration are future work—not features of this bootstrap.

## Run

Use .NET SDK **10.0.401** on Windows 11 or desktop Linux.

```sh
dotnet restore ArcForges.slnx --locked-mode
dotnet run --project src/ArcForges.Desktop
```

## Build with confidence

```sh
dotnet build ArcForges.slnx -c Release --no-restore
dotnet test --project tests/ArcForges.Desktop.Tests -c Release --no-build
dotnet format ArcForges.slnx --verify-no-changes --no-restore
dotnet publish src/ArcForges.Desktop -c Release -r win-x64 --no-restore -o artifacts/publish/win-x64
```

CI compiles Native AOT for **Windows x64 / ARM64** and **Linux x64**, tests the real view
in memory, and checks formatting, dependencies, secrets and CodeQL. Portable build
artifacts are unsigned development previews, not stable releases or native desktop E2E evidence.

[Development & native prerequisites](CONTRIBUTING.md) · [Security](SECURITY.md) ·
[AGPL-3.0-only](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md)
