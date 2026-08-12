// SPDX-License-Identifier: AGPL-3.0-only

var builder = DistributedApplication.CreateBuilder(args);
builder.AddProject<Projects.ArcForges_Cloud_Host>("arcforges-cloud");
builder.Build().Run();
