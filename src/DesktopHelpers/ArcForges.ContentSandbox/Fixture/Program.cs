// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.ContentSandbox.Host;
using ArcForges.ContentSandbox.HostileFixture;

// TEST ONLY. The same helper host as production with the one hostile test composition added. Never packaged, never signed as a product helper.
return await HelperEntry.RunAsync(new ParserProfiles([new HostileProfile(), new ProductionContainmentProfile()])).ConfigureAwait(false);
