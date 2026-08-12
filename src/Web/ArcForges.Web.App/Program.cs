// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
await builder.Build().RunAsync().ConfigureAwait(false);
