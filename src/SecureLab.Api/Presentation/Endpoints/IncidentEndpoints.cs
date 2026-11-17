using System.Diagnostics;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    private const string AuthorizationAuditCategory = "SecureLab.Authorization";
    private const int MaxTitleLength = 160;
    private const int MaxDescriptionLength = 4000;
    private const int MinDescriptionLengthForHighSeverity = 40;

    private static readonly string[] SeverityNames = Enum.GetNames<IncidentSeverity>();

    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

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

        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        // Привілейована дія: перехід New -> Triaged лише для Analyst (рішення всередині endpoint, щоб записати audit).
        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        // Дочірній ресурс: доступ до коментаря перевіряється через батьківський інцидент.
        endpoints.MapGroup("/api/incident-comments")
            .WithTags("Incident comments")
            .RequireAuthorization()
            .MapGet("/{id:guid}", GetCommentAsync)
            .WithName("GetIncidentComment")
            .Produces<IncidentCommentResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        return endpoints;
    }

    private static IResult IncidentNotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static IResult ActionForbidden() => Results.Problem(
        title: "Недостатньо прав для цієї дії",
        statusCode: StatusCodes.Status403Forbidden);

    private static IResult CommentNotFound() => Results.Problem(
        title: "Коментар не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static IResult ToResult(IncidentAccessDecision decision) => decision switch
    {
        IncidentAccessDecision.NotFound => IncidentNotFound(),
        _ => ActionForbidden()
    };

    private static string EscapeLike(string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace("%", "\\%")
            .Replace("_", "\\_");
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!IncidentAccess.TryGetViewer(httpContext.User, out var viewer))
        {
            return Results.Unauthorized();
        }

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

        return Results.Ok(await queries.GetListAsync(parsedStatus, viewer, cancellationToken));
    }

    private static async Task<IResult> SearchAsync(
        string? q,
        string? sortBy,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {

        var pattern = "%" + EscapeLike(q ?? string.Empty) + "%";

        var found = db.Incidents
            .AsNoTracking()
            .Where(item =>
                EF.Functions.ILike(item.Title, pattern, "\\")
                || EF.Functions.ILike(item.Description, pattern, "\\"));

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
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!IncidentAccess.TryGetViewer(httpContext.User, out var viewer))
        {
            return Results.Unauthorized();
        }

        var incident = await queries.GetDetailsAsync(id, viewer, cancellationToken);
        return incident is null ? IncidentNotFound() : Results.Ok(incident);
    }

    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        SecureLabDbContext db,
        CancellationToken ct)
    {
        if (!IncidentAccess.TryGetViewer(httpContext.User, out var viewer))
        {
            return Results.Unauthorized();
        }

        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, ct);

        var decision = IncidentAccess.Decide(viewer, incident, IncidentOperation.UpdateContent);
        if (decision != IncidentAccessDecision.Allow)
        {
            return ToResult(decision);
        }

        var errors = new Dictionary<string, string[]>();

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
        else if ((incident!.Severity == IncidentSeverity.High || incident.Severity == IncidentSeverity.Critical)
                 && description.Length < MinDescriptionLengthForHighSeverity)
        {
            errors["description"] = new[] { "Для рівнів High або Critical опис повинен містити щонайменше 40 символів." };
        }

        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        incident!.Title = title;
        incident.Description = description;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;

        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        SecureLabDbContext db,
        CancellationToken ct)
    {
        if (!IncidentAccess.TryGetViewer(httpContext.User, out var viewer))
        {
            return Results.Unauthorized();
        }

        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, ct);

        var decision = IncidentAccess.Decide(viewer, incident, IncidentOperation.Delete);
        if (decision != IncidentAccessDecision.Allow)
        {
            return ToResult(decision);
        }

        db.Incidents.Remove(incident!);
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        SecureLabDbContext db,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        if (!IncidentAccess.TryGetViewer(httpContext.User, out var viewer))
        {
            return Results.Unauthorized();
        }

        // Tracked entity; поля role/status/owner із тіла запиту не читаються взагалі.
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, ct);

        // 1. Рішення про право: роль із principal + видимість ресурсу.
        var decision = IncidentAccess.Decide(viewer, incident, IncidentOperation.Triage);
        if (decision != IncidentAccessDecision.Allow)
        {
            // Безпечна аудиторська подія: без cookie, пароля, токена й тіла запиту.
            // TraceId - той самий, що потрапляє в поле traceId відповіді Problem Details.
            loggerFactory.CreateLogger(AuthorizationAuditCategory).LogWarning(
                "{EventName}: subject {SubjectId}, action {Action}, resource {ResourceId}, result {Result}, at {OccurredAtUtc}, trace {TraceId}",
                "authorization.denied",
                viewer.UserId,
                "incident.triage",
                id,
                "denied",
                DateTimeOffset.UtcNow,
                Activity.Current?.Id ?? httpContext.TraceIdentifier);

            return ToResult(decision);
        }

        // 2. Допустимість переходу перевіряє сервер за поточним станом із БД.
        if (incident!.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Перехід неможливий",
                detail: "Triage дозволено лише для інциденту в статусі New.",
                statusCode: StatusCodes.Status409Conflict);
        }

        // 3. Наступний статус визначає сервер.
        var now = DateTimeOffset.UtcNow;
        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;

        db.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = viewer.UserId,
            OldStatus = IncidentStatus.New,
            NewStatus = IncidentStatus.Triaged,
            Note = "Triage виконано аналітиком.",
            CreatedAtUtc = now
        });

        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        SecureLabDbContext db,
        CancellationToken ct)
    {
        if (!IncidentAccess.TryGetViewer(httpContext.User, out var viewer))
        {
            return Results.Unauthorized();
        }

        var userId = viewer.UserId;
        var isAnalyst = viewer.IsAnalyst;

        // Умова доступу до батьківського інциденту і правило internal comment - у тому самому запиті:
        // Analyst бачить будь-який коментар; Reporter - лише звичайний коментар до власного інциденту.
        var comment = await db.IncidentComments
            .AsNoTracking()
            .Where(item => item.Id == id
                && (isAnalyst || (!item.IsInternal && item.Incident.OwnerUserId == userId)))
            .Select(item => new IncidentCommentResponse(
                item.Id,
                item.Author.DisplayName,
                item.Text,
                item.CreatedAtUtc))
            .SingleOrDefaultAsync(ct);

        return comment is null ? CommentNotFound() : Results.Ok(comment);
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
        HttpContext httpContext,
        SecureLabDbContext db,
        CancellationToken ct)
    {

        if (!Guid.TryParse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var verifiedUserId))
        {
            return Results.Problem(
                title: "Некоректний контекст користувача",
                statusCode: StatusCodes.Status500InternalServerError);
        }

        var errors = new Dictionary<string, string[]>();

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

        var occurredAtUtc = request.OccurredAtUtc.GetValueOrDefault(now).ToUniversalTime();

        var incident = new Incident
        {
            Id = Guid.NewGuid(),
            OwnerUserId = verifiedUserId,
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
