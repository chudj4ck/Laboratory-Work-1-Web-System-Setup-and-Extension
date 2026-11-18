using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

// ЛР 6: REG-RATE-01 — per-user limiter search: квота, 429, незалежний partition, відновлення.
public sealed class Lab06RateLimitTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task RegRate01_Search_QuotaPerUser_429_OtherUserUnaffected_ThenRecovers()
    {
        using var limitedHost = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("SearchRateLimit:PermitLimit", "2");
            builder.UseSetting("SearchRateLimit:WindowSeconds", "3");
        });
        using var alice = await limitedHost.LoginAsync("alice", StudyPassword);
        using var bob = await limitedHost.LoginAsync("bob", StudyPassword);
        const string url = "/api/incidents/search?q=лист";

        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var allowed = await alice.GetAsync(url);
            Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        }

        using var limited = await alice.GetAsync(url);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("application/problem+json", limited.Content.Headers.ContentType?.MediaType);

        // Інший partition (Bob) має власний лічильник.
        using var otherUser = await bob.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, otherUser.StatusCode);

        await Task.Delay(TimeSpan.FromSeconds(3.7));
        using var recovered = await alice.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
    }
}
