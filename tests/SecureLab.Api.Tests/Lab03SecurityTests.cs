using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class Lab03SecurityTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string IdentityCookiePrefix = ".AspNetCore.Identity.Application=";

    private static readonly WebApplicationFactoryClientOptions HttpsClientOptions = new()
    {
        BaseAddress = new Uri("https://localhost"),
        AllowAutoRedirect = false,
        HandleCookies = true
    };

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private HttpClient CreateAnonymousClient() => factory.CreateClient(HttpsClientOptions);

    private static object NewIncident(string label) => new
    {
        title = $"{label} {Guid.NewGuid():N}",
        description = "Регресійна перевірка захищеного створення інциденту.",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
    };

    [Fact]
    public async Task A01_AnonymousCreate_Returns401WithoutRedirect()
    {
        using var anonymous = CreateAnonymousClient();

        using var response = await anonymous.PostAsJsonAsync("/api/incidents", NewIncident("A01"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task A02_LoginThenMe_ReturnsCurrentUserWithSafeFields()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync("/api/me");
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(DbSeeder.AliceId, root.GetProperty("id").GetGuid());
        Assert.Equal("alice", root.GetProperty("userName").GetString());

        var propertyNames = root.EnumerateObject().Select(property => property.Name).Order().ToArray();
        Assert.Equal(new[] { "id", "roles", "userName" }, propertyNames);
    }

    [Fact]
    public async Task A03_ForeignDemoHeader_DoesNotChangeCurrentUser()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        using var response = await alice.SendAsync(request);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(DbSeeder.AliceId, document.RootElement.GetProperty("id").GetGuid());
    }

    [Fact]
    public async Task A04_CreateWithoutOwner_UsesPrincipalAsOwner()
    {
        using var bob = await factory.LoginAsync("bob", StudyPassword);

        using var response = await bob.PostAsJsonAsync("/api/incidents", NewIncident("A04"));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(DbSeeder.BobId, await ReadOwnerOfCreatedIncidentAsync(response));
    }

    [Fact]
    public async Task A05_ForgedOwnerInJson_IsIgnored_OwnerStaysPrincipal()
    {
        using var bob = await factory.LoginAsync("bob", StudyPassword);
        var body = new
        {
            title = $"A05 {Guid.NewGuid():N}",
            description = "Спроба підмінити власника нового інциденту через тіло запиту.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
            ownerUserId = DbSeeder.AliceId
        };

        using var response = await bob.PostAsJsonAsync("/api/incidents", body);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var owner = await ReadOwnerOfCreatedIncidentAsync(response);
        Assert.Equal(DbSeeder.BobId, owner);
        Assert.NotEqual(DbSeeder.AliceId, owner);
    }

    [Fact]
    public async Task A06_Logout_ThenProtectedRequestReturns401()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var before = await alice.GetAsync("/api/me");
        using var logout = await alice.PostAsync("/api/auth/logout", content: null);
        using var after = await alice.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact]
    public async Task A07_UnknownUserAndWrongPassword_LookTheSame()
    {
        using var client = CreateAnonymousClient();
        var wrongPassword = "Wrong-" + Guid.NewGuid().ToString("N");
        var unknownUser = "nouser" + Guid.NewGuid().ToString("N")[..8];

        using var wrongPasswordResponse = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = wrongPassword });
        using var unknownUserResponse = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = unknownUser, password = wrongPassword });

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPasswordResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownUserResponse.StatusCode);
        Assert.False(wrongPasswordResponse.Headers.Contains("Set-Cookie"));
        Assert.False(unknownUserResponse.Headers.Contains("Set-Cookie"));

        Assert.Equal(
            await DescribeFailureAsync(wrongPasswordResponse),
            await DescribeFailureAsync(unknownUserResponse));
    }

    [Fact]
    public async Task Register_Duplicate_Returns409_AndFirstResponseIsSafe()
    {
        using var client = CreateAnonymousClient();
        var userName = "reg" + Guid.NewGuid().ToString("N")[..8];
        var registration = new
        {
            userName,
            email = userName + "@example.test",
            displayName = "Студент регресії",
            password = StudyPassword
        };

        using var first = await client.PostAsJsonAsync("/api/auth/register", registration);
        using var sameAgain = await client.PostAsJsonAsync("/api/auth/register", registration);
        using var sameEmail = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName = userName + "x",
            registration.email,
            registration.displayName,
            registration.password
        });

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, sameAgain.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, sameEmail.StatusCode);
        Assert.Equal("application/problem+json", sameAgain.Content.Headers.ContentType?.MediaType);

        using var document = JsonDocument.Parse(await first.Content.ReadAsStringAsync());
        var propertyNames = document.RootElement.EnumerateObject()
            .Select(property => property.Name).Order().ToArray();
        Assert.Equal(new[] { "displayName", "id", "userName" }, propertyNames);
        Assert.False(first.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task Login_OverHttps_SetsCookieWithExpectedFlags()
    {
        using var client = CreateAnonymousClient();

        using var response = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        var matching = response.Headers.GetValues("Set-Cookie")
            .Where(value => value.StartsWith(IdentityCookiePrefix, StringComparison.Ordinal))
            .ToArray();

        Assert.True(matching.Length == 1);

        var attributes = matching[0].Split(';').Skip(1)
            .Select(part => part.Trim().ToLowerInvariant())
            .ToArray();

        Assert.Contains("httponly", attributes);
        Assert.Contains("secure", attributes);
        Assert.Contains("samesite=lax", attributes);
        Assert.Contains("path=/", attributes);
    }

    [Fact]
    public async Task Login_RateLimit_Returns429_ThenRecoversAfterWindow()
    {
        const int permitLimit = 3;
        const string permitLimitSetting = "3";
        const string windowSecondsSetting = "3";
        var window = TimeSpan.FromSeconds(3);

        using var limitedHost = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("LoginRateLimit:PermitLimit", permitLimitSetting);
            builder.UseSetting("LoginRateLimit:WindowSeconds", windowSecondsSetting);
        });
        using var client = limitedHost.CreateClient(HttpsClientOptions);
        var wrongPassword = "Wrong-" + Guid.NewGuid().ToString("N");

        for (var attempt = 0; attempt < permitLimit; attempt++)
        {
            using var rejected = await client.PostAsJsonAsync(
                "/api/auth/login", new { userName = "alice", password = wrongPassword });
            Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        }

        using var limitedKnown = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });
        using var limitedUnknown = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "nouser" + Guid.NewGuid().ToString("N")[..8], password = wrongPassword });

        Assert.Equal(HttpStatusCode.TooManyRequests, limitedKnown.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedUnknown.StatusCode);
        Assert.False(limitedKnown.Headers.Contains("Set-Cookie"));

        await Task.Delay(window + TimeSpan.FromMilliseconds(700));

        using var recovered = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, recovered.StatusCode);
    }

    private async Task<Guid> ReadOwnerOfCreatedIncidentAsync(HttpResponseMessage response)
    {
        var created = await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>();
        Assert.NotNull(created);
        var createdId = created!.Id;

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.AsNoTracking().SingleAsync(item => item.Id == createdId);
        return incident.OwnerUserId;
    }

    private static async Task<string> DescribeFailureAsync(HttpResponseMessage response)
    {
        var mediaType = response.Content.Headers.ContentType?.MediaType ?? "<none>";
        var body = await response.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(body))
        {
            return $"{(int)response.StatusCode}|{mediaType}|<empty>";
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        return string.Join('|',
            (int)response.StatusCode,
            mediaType,
            ReadField(root, "type"),
            ReadField(root, "title"),
            ReadField(root, "status"),
            ReadField(root, "detail"));
    }

    private static string ReadField(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) ? value.ToString() : "<absent>";
}
