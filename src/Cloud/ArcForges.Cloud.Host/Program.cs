// SPDX-License-Identifier: AGPL-3.0-only

using ArcForges.Cloud.Host;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSignalR();
builder.Services.AddTransient(static _ => new ArcForgesEventHub());

var app = builder.Build();
app.MapGet("/", () => Results.Json(new { app = "arcforges-cloud", ok = true }));
app.MapGet("/health", () => Results.Json(new { status = "ok" }));
app.MapHub<ArcForgesEventHub>("/hubs/v1/events");
app.Run();

internal partial class Program;
