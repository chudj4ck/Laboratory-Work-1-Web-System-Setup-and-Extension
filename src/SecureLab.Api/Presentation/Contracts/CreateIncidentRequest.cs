namespace SecureLab.Api.Presentation.Contracts;

/// <summary>
/// Дані, які клієнт може передати під час створення інциденту.
/// Id, власника, статус і дати створення/оновлення формує сервер,
/// тому таких полів у запиті немає (зайві поля JSON ігноруються).
/// </summary>
public sealed record CreateIncidentRequest(
    string? Title,
    string? Description,
    string? Severity,
    DateTimeOffset? OccurredAtUtc);
