# AOT and Runtime Baseline

The foundation PR records only actually executed cells. Missing OS/RID hardware remains `NotExecuted`, never
`Passed` by inference.

| Host | RID | Mode | Command/artifact | Result | Size/startup | IL2026/IL3050 |
|---|---|---|---|---|---|---|
| ArcChat Desktop | win-x64 | Native AOT | `dotnet publish` + `ArcChat.Desktop.exe --smoke` | Passed locally | 214,381,104 bytes; startup not benchmarked | 0 observed |
| ArcNotes Desktop | win-x64 | Native AOT | `dotnet publish` + `ArcNotes.Desktop.exe --smoke` | Passed locally | 214,381,132 bytes; startup not benchmarked | 0 observed |
| ArcScope Desktop | win-x64 | Native AOT | `dotnet publish` + `ArcScope.Desktop.exe --smoke` | Passed locally | 214,396,128 bytes; startup not benchmarked | 0 observed |
| ArcSlate Desktop | win-x64 | Native AOT | `dotnet publish` + `ArcSlate.Desktop.exe --smoke` | Passed locally | 214,396,128 bytes; startup not benchmarked | 0 observed |
| ArcForges Cloud | win-x64 | framework-dependent JIT | publish, `/health`, root JSON, SignalR negotiate | Passed locally | startup not benchmarked | n/a |
