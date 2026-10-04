// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.ContentSandbox.Host;

// The production helper composes no parser: the approved parser compositions are added to this same host by their own task, and a launch
// that names one this build does not contain is refused.
return await HelperEntry.RunAsync(ParserProfiles.Production).ConfigureAwait(false);
