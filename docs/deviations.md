# Architecture Deviations

| Item | Reason | Impact | Decision | Authority/writeback |
|---|---|---|---|---|
| SDK pin is `10.0.400` | This is the installed stable .NET 10 feature band used by Visual Studio and CI bootstrap | Replaces the older planning example `10.0.1xx`; exact pin prevents SDK-driven lock-file drift | Accept exact stable SDK only | Step 01 evidence |
| `ArcForges.Foundation` contains runtime primitives only | Stable serialized IDs belong to Contracts | Avoids duplicate nominal identities | `ArcForges.Contracts.Foundation` is the single serialized-ID owner | Step 02 confirms contracts |
| MAUI uses one conditional multi-target head | One app owns Android and deferred iOS platform folders | No duplicate platform heads | Keep `ArcChat.Mobile.csproj` as the only MAUI executable | Steps 18–20 |
| Stable MAUI 10.0.90 resolves `Xamarin.AndroidX.Security.SecurityCrypto/1.1.0.4-alpha07` | This exact AndroidX binding is a transitive dependency selected by the frozen stable MAUI package and has no stable 1.1.0.4 replacement on nuget.org | Android head alone carries one audited prerelease-labeled transitive; ArcForges never references it directly | Keep an exact one-entry policy allowlist; any other prerelease still fails CI | Step 01 dependency evidence; revisit with each MAUI upgrade |
