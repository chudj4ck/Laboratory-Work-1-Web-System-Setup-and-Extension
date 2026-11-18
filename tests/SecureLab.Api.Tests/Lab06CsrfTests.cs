using System.Net;
using System.Net.Http.Json;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

// ЛР 6: REG-CSRF-01 — cookie-сеанс без request token не змінює стан; з валідною парою — зміна відбувається.
public sealed class Lab06CsrfTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static object NewIncident(string title) => new
    {
        title,
        description = "Регресійна перевірка antiforgery для створення інциденту.",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
    };

    [Fact]
    public async Task RegCsrf01_CreateWithoutToken_IsRejectedAndNothingCreated_ThenValidPairSucceeds()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var title = $"REG-CSRF-01 {Guid.NewGuid():N}";

        // Негативна частина: auth-cookie є, request token немає.
        using var rejected = await alice.PostAsJsonAsync("/api/incidents", NewIncident(title));
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        Assert.Contains("Antiforgery", await rejected.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.DoesNotContain(await ListAsync(alice), item => item.Title == title);

        // Позитивна частина: той самий клієнт одержує токен і повторює операцію.
        await alice.WithCsrfTokenAsync();
        using var created = await alice.PostAsJsonAsync("/api/incidents", NewIncident(title));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Single(await ListAsync(alice), item => item.Title == title);
    }

    [Fact]
    public async Task RegCsrf01_UpdateWithoutToken_IsRejectedAndTitleUnchanged()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var before = await alice.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{DbSeeder.AliceIncidentId}");

        using var rejected = await alice.PutAsJsonAsync($"/api/incidents/{DbSeeder.AliceIncidentId}", new
        {
            title = "Змінено без CSRF-токена",
            description = "Ця зміна не повинна застосуватися без дійсного request token."
        });

        var after = await alice.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        Assert.Equal(before!.Title, after!.Title);
        Assert.Equal(before.Description, after.Description);
    }

    [Fact]
    public async Task RegCsrf01_LogoutWithoutToken_KeepsSession()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var rejected = await alice.PostAsync("/api/auth/logout", content: null);
        using var stillSignedIn = await alice.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        Assert.Equal(HttpStatusCode.OK, stillSignedIn.StatusCode);
    }

    private static async Task<List<IncidentListItemResponse>> ListAsync(HttpClient client) =>
        await client.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents") ?? [];
}
