// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.ContentSandbox.Host;

// The production helper composes the approved production parsers; the PDF parser path is retired (P2-022) and the still-image composition
// is not yet delivered. A launch that names a composition this build does not contain, including the hostile test composition, is refused.
return await HelperEntry.RunAsync(ParserProfiles.Production).ConfigureAwait(false);
