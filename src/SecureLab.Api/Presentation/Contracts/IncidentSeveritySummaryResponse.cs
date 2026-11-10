namespace SecureLab.Api.Presentation.Contracts;

public sealed record IncidentSeveritySummaryResponse(
    string Severity,
    int Count);
public sealed record CreatedIncidentResponse(
    Guid Id,
    string Title,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc);