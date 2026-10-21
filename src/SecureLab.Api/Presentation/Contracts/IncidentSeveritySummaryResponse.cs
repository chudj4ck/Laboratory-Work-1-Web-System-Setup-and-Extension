namespace SecureLab.Api.Presentation.Contracts;

public sealed record IncidentSeveritySummaryResponse(
    string Severity,
    int Count);