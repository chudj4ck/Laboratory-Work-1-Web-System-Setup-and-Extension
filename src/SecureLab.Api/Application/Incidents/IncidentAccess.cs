using System.Linq.Expressions;
using System.Security.Claims;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

/// <summary>Поточний користувач, визначений лише з перевіреного principal (cookie -> HttpContext.User).</summary>
public sealed record IncidentViewer(Guid UserId, bool IsAnalyst);

/// <summary>Дії над інцидентом, для яких сервер ухвалює рішення.</summary>
public enum IncidentOperation
{
    Read,
    UpdateContent,
    Delete,
    Triage
}

/// <summary>Результат рішення: дозволити, приховати (404) або заборонити видиму дію (403).</summary>
public enum IncidentAccessDecision
{
    Allow,
    NotFound,
    Forbidden
}

/// <summary>
/// Єдине правило доступу до Incident (docs/access-matrix.md).
/// Видимість: Reporter бачить лише власні інциденти, Analyst - усі.
/// Дії: зміна вмісту й видалення - лише власник; triage - лише Analyst.
/// Administrator не має опублікованих прав на Incident, тому діє як звичайний користувач.
/// </summary>
public static class IncidentAccess
{
    public static bool TryGetViewer(ClaimsPrincipal user, out IncidentViewer viewer)
    {
        viewer = null!;
        if (!Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
        {
            return false;
        }

        viewer = new IncidentViewer(userId, user.IsInRole(DbSeeder.AnalystRole));
        return true;
    }

    public static Expression<Func<Incident, bool>> VisibleTo(IncidentViewer viewer)
    {
        var userId = viewer.UserId;
        var canReadAll = viewer.IsAnalyst;
        return incident => canReadAll || incident.OwnerUserId == userId;
    }

    public static IncidentAccessDecision Decide(
        IncidentViewer viewer,
        Incident? incident,
        IncidentOperation operation)
    {
        if (incident is null || !(viewer.IsAnalyst || incident.OwnerUserId == viewer.UserId))
        {
            return IncidentAccessDecision.NotFound;
        }

        var isOwner = incident.OwnerUserId == viewer.UserId;

        return operation switch
        {
            IncidentOperation.Read => IncidentAccessDecision.Allow,
            IncidentOperation.UpdateContent or IncidentOperation.Delete => isOwner
                ? IncidentAccessDecision.Allow
                : IncidentAccessDecision.Forbidden,
            IncidentOperation.Triage => viewer.IsAnalyst
                ? IncidentAccessDecision.Allow
                : IncidentAccessDecision.Forbidden,
            _ => IncidentAccessDecision.Forbidden
        };
    }
}
