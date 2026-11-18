using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class IncidentEndpointTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();
    private readonly SecureLabApiFactory _factory = factory;

    // Створення інциденту захищене, тому перевірки контракту ЛР 2 виконуються клієнтом із cookie.
    private Task<HttpClient> LoginAsAliceAsync()
    {
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");
        return LoginWithCsrfAsync(password);
    }

    private async Task<HttpClient> LoginWithCsrfAsync(string password)
    {
        var client = await _factory.LoginAsync("alice", password);
        return await client.WithCsrfTokenAsync();
    }

    // ЛР 4: список обмежено дозволеною множиною (матриця), тому Alice бачить лише власні інциденти.
    [Fact]
    public async Task GetList_AsAlice_ReturnsOnlyOwnIncidents()
    {
        using var alice = await LoginAsAliceAsync();

        var incidents = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>(
            "/api/incidents");

        Assert.NotNull(incidents);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(incidents, incident => incident.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task GetDetails_ForUnknownId_ReturnsProblemDetails404()
    {
        using var alice = await LoginAsAliceAsync();
        using var response = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task GetDetails_DoesNotExposeInternalOwnerFields()
    {
        using var alice = await LoginAsAliceAsync();
        using var response = await alice.GetAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(document.RootElement.TryGetProperty("ownerUserId", out _));
        Assert.False(document.RootElement.TryGetProperty("email", out _));
        Assert.Equal("Аліса Коваль", document.RootElement.GetProperty("ownerDisplayName").GetString());
    }

    [Fact]
    public async Task ClientScript_DoesNotUseDangerousInnerHtmlSink()
    {
        var script = await _client.GetStringAsync("/app.js");

        Assert.DoesNotContain("innerHTML", script, StringComparison.Ordinal);
        Assert.Contains("textContent", script, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Post_InvalidDto_ReturnsValidationProblem()
    {
        var body = new
        {
            title = " ",
            description = "",
            severity = "7",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(10)
        };

        using var client = await LoginAsAliceAsync();
        using var response = await client.PostAsJsonAsync("/api/incidents", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var json = await response.Content.ReadAsStringAsync();

        Assert.Contains("\"title\"", json, StringComparison.Ordinal);
        Assert.Contains("\"description\"", json, StringComparison.Ordinal);
        Assert.Contains("\"severity\"", json, StringComparison.Ordinal);
        Assert.Contains("\"occurredAtUtc\"", json, StringComparison.Ordinal);

        Assert.DoesNotContain("stack trace", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SELECT", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Post_DuplicateActiveTitle_ReturnsConflict()
    {
        var body = new
        {
            title = "Підозрілий лист із вкладенням",
            description = "Опис для перевірки конфлікту предметного правила.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        using var client = await LoginAsAliceAsync();
        using var response = await client.PostAsJsonAsync("/api/incidents", body);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);

        Assert.Equal(409, document.RootElement.GetProperty("status").GetInt32());
        Assert.DoesNotContain("SELECT", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection", json, StringComparison.OrdinalIgnoreCase);
    }
}
