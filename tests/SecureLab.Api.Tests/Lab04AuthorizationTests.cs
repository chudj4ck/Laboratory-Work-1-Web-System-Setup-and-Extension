using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class Lab04AuthorizationTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // ЛР 6: автентифіковані клієнти цих тестів перевіряють авторизацію, тому мають дійсний CSRF-токен.
    private async Task<HttpClient> LoginAsync(string userName) =>
        await (await factory.LoginAsync(userName, StudyPassword)).WithCsrfTokenAsync();

    private HttpClient CreateAnonymousClient() => factory.CreateClient(new()
    {
        BaseAddress = new Uri("https://localhost"),
        AllowAutoRedirect = false,
        HandleCookies = true
    });

    [Fact]
    public async Task A01_AnonymousRequests_Return401WithoutRedirect()
    {
        using var anonymous = CreateAnonymousClient();
        var id = DbSeeder.AliceIncidentId;

        using var details = await anonymous.GetAsync($"/api/incidents/{id}");
        using var update = await anonymous.PutAsJsonAsync($"/api/incidents/{id}", new { title = "x", description = "y" });
        using var delete = await anonymous.DeleteAsync($"/api/incidents/{id}");
        using var triage = await anonymous.PostAsync($"/api/incidents/{id}/triage", null);

        foreach (var response in new[] { details, update, delete, triage })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Null(response.Headers.Location);
        }
        Assert.True(await IncidentExistsAsync(id));
    }

    [Fact]
    public async Task A02_AliceReadsOwnIncident_Returns200()
    {
        using var alice = await LoginAsync("alice");

        var details = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.NotNull(details);
        Assert.Equal(DbSeeder.AliceIncidentId, details.Id);
    }

    [Fact]
    public async Task A03_AliceReadsBobIncident_Returns404()
    {
        using var alice = await LoginAsync("alice");

        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.DoesNotContain("Боб", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A03R_AnalystReadsAliceIncident_Returns200ButCannotUpdate()
    {
        using var morgan = await LoginAsync("morgan");
        var before = await LoadIncidentAsync(DbSeeder.AliceIncidentId);

        using var details = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        using var update = await morgan.PutAsJsonAsync($"/api/incidents/{DbSeeder.AliceIncidentId}", new
        {
            title = "Спроба аналітика",
            description = "Аналітик намагається змінити зміст чужого інциденту."
        });

        Assert.Equal(HttpStatusCode.OK, details.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, update.StatusCode);
        Assert.Equal(before.Title, (await LoadIncidentAsync(DbSeeder.AliceIncidentId)).Title);
    }

    [Fact]
    public async Task A03b_AdministratorWithoutPublishedRights_Returns404ForForeignIncident()
    {
        using var admin = await LoginAsync("admin");

        using var details = await admin.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var triage = await admin.PostAsync($"/api/incidents/{DbSeeder.BobIncidentId}/triage", null);

        Assert.Equal(HttpStatusCode.NotFound, details.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, triage.StatusCode);
    }

    [Fact]
    public async Task A04_AliceUpdatesOrDeletesBobIncident_Returns404AndStateUnchanged()
    {
        var before = await LoadIncidentAsync(DbSeeder.BobIncidentId);
        using var alice = await LoginAsync("alice");

        using var update = await alice.PutAsJsonAsync($"/api/incidents/{DbSeeder.BobIncidentId}", new
        {
            title = "Змінено чужим користувачем",
            description = "Спроба змінити інцидент, який належить іншому користувачу системи."
        });
        using var delete = await alice.DeleteAsync($"/api/incidents/{DbSeeder.BobIncidentId}");

        var after = await LoadIncidentAsync(DbSeeder.BobIncidentId);
        Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
        Assert.Equal(before.Title, after.Title);
        Assert.Equal(before.Description, after.Description);
        Assert.Equal(before.UpdatedAtUtc, after.UpdatedAtUtc);
    }

    [Fact]
    public async Task A05_ListIsScopedToOwnerForReporter_AndFullForAnalyst()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");

        var aliceList = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");
        var morganList = await morgan.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(aliceList);
        Assert.Contains(aliceList, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(aliceList, item => item.Id == DbSeeder.BobIncidentId);

        Assert.NotNull(morganList);
        Assert.Contains(morganList, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(morganList, item => item.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task A06_ReporterTriagesOwnIncident_Returns403AndStatusUnchanged()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice, "A06");
        var historyBefore = await CountHistoryAsync(id);

        using var response = await alice.PostAsync($"/api/incidents/{id}/triage", null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(IncidentStatus.New, (await LoadIncidentAsync(id)).Status);
        Assert.Equal(historyBefore, await CountHistoryAsync(id));
    }

    [Fact]
    public async Task A07_AnalystTriagesNewIncident_Returns204ThenRepeatReturns409()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");
        var id = await CreateIncidentAsync(alice, "A07");
        Assert.Equal(IncidentStatus.New, (await LoadIncidentAsync(id)).Status);

        using var first = await morgan.PostAsync($"/api/incidents/{id}/triage", null);
        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);
        Assert.Equal(IncidentStatus.Triaged, (await LoadIncidentAsync(id)).Status);
        Assert.Equal(1, await CountHistoryAsync(id));

        using var second = await morgan.PostAsync($"/api/incidents/{id}/triage", null);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        Assert.Equal(IncidentStatus.Triaged, (await LoadIncidentAsync(id)).Status);
        Assert.Equal(1, await CountHistoryAsync(id));
    }

    [Fact]
    public async Task A08a_OwnerUpdateWithForgedFields_ChangesOnlyTitleAndDescription()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice, "A08a");
        var before = await LoadIncidentAsync(id);

        using var response = await alice.PutAsJsonAsync($"/api/incidents/{id}", new
        {
            title = "Оновлено власником",
            description = "Нове безпечне формулювання опису інциденту для перевірки.",
            status = "Closed",
            ownerUserId = DbSeeder.BobId,
            role = "Analyst"
        });

        var after = await LoadIncidentAsync(id);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal("Оновлено власником", after.Title);
        Assert.Equal("Нове безпечне формулювання опису інциденту для перевірки.", after.Description);
        Assert.Equal(before.Status, after.Status);
        Assert.Equal(DbSeeder.AliceId, after.OwnerUserId);
        Assert.Equal(before.Severity, after.Severity);
    }

    [Fact]
    public async Task A10_ForeignAndUnknownIncident_ReturnIndistinguishable404()
    {
        using var alice = await LoginAsync("alice");

        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknown = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(unknown.StatusCode, foreign.StatusCode);
        Assert.Equal(unknown.Content.Headers.ContentType?.MediaType, foreign.Content.Headers.ContentType?.MediaType);
        Assert.Equal(await WithoutTraceIdAsync(unknown), await WithoutTraceIdAsync(foreign));
    }

    [Fact]
    public async Task A12_ChildCommentAndInternalComment_FollowParentAuthorization()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");
        var internalUrl = $"/api/incident-comments/{DbSeeder.InternalCommentId}";

        using var aliceForeignComment = await alice.GetAsync(
            "/api/incident-comments/30000000-0000-0000-0000-000000000002");
        using var aliceInternal = await alice.GetAsync(internalUrl);
        var aliceDetails = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        using var morganInternal = await morgan.GetAsync(internalUrl);
        var morganDetails = await morgan.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, aliceForeignComment.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, aliceInternal.StatusCode);
        Assert.NotNull(aliceDetails);
        Assert.DoesNotContain(aliceDetails.Comments, comment => comment.Id == DbSeeder.InternalCommentId);

        Assert.Equal(HttpStatusCode.OK, morganInternal.StatusCode);
        var body = await morganInternal.Content.ReadFromJsonAsync<IncidentCommentResponse>();
        Assert.Equal(DbSeeder.InternalCommentId, body!.Id);
        Assert.NotNull(morganDetails);
        Assert.Contains(morganDetails.Comments, comment => comment.Id == DbSeeder.InternalCommentId);
    }

    private static async Task<Guid> CreateIncidentAsync(HttpClient client, string label)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"ЛР4 {label} {Guid.NewGuid():N}",
            description = "Тестовий інцидент для регресійної перевірки авторизації.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>();
        return created!.Id;
    }

    private async Task<Incident> LoadIncidentAsync(Guid id)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.AsNoTracking().SingleAsync(item => item.Id == id);
    }

    private async Task<bool> IncidentExistsAsync(Guid id)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.AnyAsync(item => item.Id == id);
    }

    private async Task<int> CountHistoryAsync(Guid incidentId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.IncidentStatusHistory.CountAsync(item => item.IncidentId == incidentId);
    }

    private static async Task<string> WithoutTraceIdAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var fields = document.RootElement.EnumerateObject()
            .Where(property => property.Name != "traceId")
            .Select(property => $"{property.Name}={property.Value.GetRawText()}");
        return string.Join('|', fields);
    }
}
