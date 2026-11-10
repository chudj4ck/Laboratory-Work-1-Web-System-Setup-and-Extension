using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents");

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>()
            .ProducesValidationProblem();

        group.MapPost("/", CreateAsync)
            .WithName("CreateIncident")
            .Produces<CreatedIncidentResponse>(StatusCodes.Status201Created)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status409Conflict);

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = new[] { "Допустимі значення: New, Triaged, InProgress, Resolved, Closed." }
                });
            }

            parsedStatus = candidate;
        }

        return Results.Ok(await queries.GetListAsync(parsedStatus, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.GetDetailsAsync(id, cancellationToken);
        return incident is null
            ? Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(incident);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = new[] { "Допустимі значення: New, Triaged, InProgress, Resolved, Closed." }
                });
            }

            parsedStatus = candidate;
        }

        return Results.Ok(await queries.GetSeveritySummaryAsync(parsedStatus, cancellationToken));
    }

    private static async Task<IResult> CreateAsync(
        CreateIncidentRequest request,
        SecureLabDbContext db,
        CancellationToken ct)
    {
        var errors = new Dictionary<string, string[]>();

        // Валідація Severity
        bool severityIsValid = Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
                               && Enum.IsDefined(severity);

        if (!severityIsValid)
        {
            errors["severity"] = new[] { "Недопустиме значення Severity." };
        }

        string description = request.Description ?? string.Empty;

        // Валідація опису для High/Critical
        if (severityIsValid
            && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
            && !errors.ContainsKey("description")
            && description.Length < 40)
        {
            errors["description"] = new[] { "Для рівнів High або Critical опис повинен містити щонайменше 40 символів." };
        }

        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        // Перевірка предметного конфлікту - Т-03
        var title = request.Title;
        var duplicateExists = await db.Incidents.AnyAsync(
            item =>
                item.Title == title
                && item.Status != IncidentStatus.Closed,
            ct);

        if (duplicateExists)
        {
            return Results.Problem(
                title: "Інцидент уже існує",
                detail: "Активний інцидент із таким самим заголовком уже існує.",
                statusCode: StatusCodes.Status409Conflict);
        }

        // Створення сутності інциденту
        var now = DateTimeOffset.UtcNow;
        var occurredAtUtc = now;

        var incident = new Incident
        {
            Id = Guid.NewGuid(),
            OwnerUserId = DbSeeder.AliceId,
            Title = title,
            Description = description,
            Severity = severity,
            Status = IncidentStatus.New,
            OccurredAtUtc = occurredAtUtc,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };

        db.Incidents.Add(incident);
        await db.SaveChangesAsync(ct);

        // Формування DTO для відповіді
        var response = new CreatedIncidentResponse(
            incident.Id,
            incident.Title,
            incident.Severity.ToString(),
            incident.Status.ToString(),
            incident.OccurredAtUtc,
            incident.CreatedAtUtc);

        return Results.Created($"/api/incidents/{response.Id}", response);
    }
}