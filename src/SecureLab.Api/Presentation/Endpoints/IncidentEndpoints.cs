using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    private const int MaxTitleLength = 160;
    private const int MaxDescriptionLength = 4000;
    private const int MinDescriptionLengthForHighSeverity = 40;

    private static readonly string[] SeverityNames = Enum.GetNames<IncidentSeverity>();

    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents");

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/search", SearchAsync)
            .WithName("SearchIncidents")
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

    private static string EscapeLike(string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace("%", "\\%")
            .Replace("_", "\\_");
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

    private static async Task<IResult> SearchAsync(
        string? q,
        string? sortBy,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        // Значення користувача потрапляє в запит лише як параметр,
        // а спецсимволи LIKE (\, %, _) екрануються і шукаються буквально.
        var pattern = "%" + EscapeLike(q ?? string.Empty) + "%";

        var found = db.Incidents
            .AsNoTracking()
            .Where(item =>
                EF.Functions.ILike(item.Title, pattern, "\\")
                || EF.Functions.ILike(item.Description, pattern, "\\"));

        // Білий список сортування: sortBy ніколи не підставляється в SQL.
        IQueryable<Incident> ordered;
        switch (sortBy)
        {
            case null or "" or "createdAtUtc":
                ordered = found
                    .OrderByDescending(item => item.CreatedAtUtc)
                    .ThenBy(item => item.Id);
                break;
            case "severity":
                ordered = found
                    .OrderBy(item => item.Severity)
                    .ThenByDescending(item => item.CreatedAtUtc)
                    .ThenBy(item => item.Id);
                break;
            case "status":
                ordered = found
                    .OrderBy(item => item.Status)
                    .ThenByDescending(item => item.CreatedAtUtc)
                    .ThenBy(item => item.Id);
                break;
            default:
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["sortBy"] = new[] { "Допустимі значення: createdAtUtc, severity, status." }
                });
        }

        var result = await ordered
            .Select(i => new IncidentListItemResponse(
                i.Id,
                i.Title,
                i.Severity.ToString(),
                i.Status.ToString(),
                i.OccurredAtUtc,
                i.CreatedAtUtc))
            .ToListAsync(cancellationToken);

        return Results.Ok(result);
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

        // Робочий годинник API: час береться один раз на початку обробки.
        var now = DateTimeOffset.UtcNow;

        var title = request.Title?.Trim() ?? string.Empty;
        if (title.Length == 0)
        {
            errors["title"] = new[] { "Заголовок є обов'язковим." };
        }
        else if (title.Length > MaxTitleLength)
        {
            errors["title"] = new[] { $"Заголовок не повинен перевищувати {MaxTitleLength} символів." };
        }

        var description = request.Description?.Trim() ?? string.Empty;
        if (description.Length == 0)
        {
            errors["description"] = new[] { "Опис є обов'язковим." };
        }
        else if (description.Length > MaxDescriptionLength)
        {
            errors["description"] = new[] { $"Опис не повинен перевищувати {MaxDescriptionLength} символів." };
        }

        // Приймаються лише назви рівнів; числа на кшталт "7" або "1" відхиляються.
        var severity = IncidentSeverity.Low;
        var severityIsValid = request.Severity is not null
            && SeverityNames.Contains(request.Severity, StringComparer.OrdinalIgnoreCase)
            && Enum.TryParse(request.Severity, ignoreCase: true, out severity);

        if (!severityIsValid)
        {
            errors["severity"] = new[] { "Допустимі значення: Low, Medium, High, Critical." };
        }

        if (request.OccurredAtUtc is null)
        {
            errors["occurredAtUtc"] = new[] { "Дата та час виникнення інциденту є обов'язковими." };
        }
        else if (IncidentRules.IsOccurredAtTooFarInFuture(request.OccurredAtUtc.Value, now))
        {
            errors["occurredAtUtc"] = new[]
            {
                "Дата та час виникнення інциденту не можуть перевищувати поточний час більше ніж на 5 хвилин."
            };
        }

        // Логіка перевірки довжини опису для інцидентів High і Critical
        if (severityIsValid
            && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
            && !errors.ContainsKey("description")
            && description.Length < MinDescriptionLengthForHighSeverity)
        {
            errors["description"] = new[] { "Для рівнів High або Critical опис повинен містити щонайменше 40 символів." };
        }

        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

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

        // PostgreSQL (timestamptz) приймає DateTimeOffset лише зі зміщенням +00:00.
        var occurredAtUtc = request.OccurredAtUtc.GetValueOrDefault(now).ToUniversalTime();

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
