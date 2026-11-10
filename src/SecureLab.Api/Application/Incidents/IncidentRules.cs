namespace SecureLab.Api.Application.Incidents;

public static class IncidentRules
{
   
    public static bool IsOccurredAtTooFarInFuture(DateTimeOffset occurredAtUtc, DateTimeOffset now)
    {
        return occurredAtUtc > now.AddMinutes(5);
    }
}
