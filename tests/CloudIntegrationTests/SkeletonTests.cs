// SPDX-License-Identifier: AGPL-3.0-only

using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace ArcForges.Tests.CloudIntegrationTests;

public sealed class SkeletonTests
{
    [Xunit.Fact]
    [Xunit.Trait("Category", "Integration")]
    public async Task PublishedHttpAndSignalRContractsRespond()
    {
        using WebApplicationFactory<Program> factory = new();
        using HttpClient client = factory.CreateClient();
        CancellationToken cancellationToken = Xunit.TestContext.Current.CancellationToken;

        Dictionary<string, object>? health = await client
            .GetFromJsonAsync<Dictionary<string, object>>("/health", cancellationToken)
            .ConfigureAwait(true);
        Xunit.Assert.NotNull(health);
        Xunit.Assert.Contains("ok", health["status"].ToString(), StringComparison.Ordinal);

        Dictionary<string, object>? root = await client
            .GetFromJsonAsync<Dictionary<string, object>>("/", cancellationToken)
            .ConfigureAwait(true);
        Xunit.Assert.NotNull(root);
        Xunit.Assert.Contains("arcforges-cloud", root["app"].ToString(), StringComparison.Ordinal);

        using HttpResponseMessage negotiate = await client
            .PostAsync(new Uri("/hubs/v1/events/negotiate?negotiateVersion=1", UriKind.Relative), null, cancellationToken)
            .ConfigureAwait(true);
        Xunit.Assert.Equal(HttpStatusCode.OK, negotiate.StatusCode);
        string body = await negotiate.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(true);
        Xunit.Assert.Contains("connectionToken", body, StringComparison.Ordinal);
    }
}
