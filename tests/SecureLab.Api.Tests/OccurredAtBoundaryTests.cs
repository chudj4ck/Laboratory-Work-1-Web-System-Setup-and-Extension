using System.Globalization;
using SecureLab.Api.Application.Incidents;
using Xunit.Abstractions;

namespace SecureLab.Api.Tests;


public sealed class OccurredAtBoundaryTests(ITestOutputHelper output)
{
    private static readonly DateTimeOffset Now = Parse("2026-09-02T12:00:00Z");

    private const string PointA = "2026-09-02T12:04:59.9999999Z"; // межа - 1 tick (100 нс)
    private const string PointB = "2026-09-02T12:05:00Z";         // рівно межа
    private const string PointC = "2026-09-02T12:05:00.0000001Z"; // межа + 1 tick

    private static readonly string[] AllPoints = [PointA, PointB, PointC];

    // Правильне порівняння: той самий метод, який викликає handler.
    private static bool Correct(DateTimeOffset occurredAtUtc) =>
        IncidentRules.IsOccurredAtTooFarInFuture(occurredAtUtc, Now);

    // Мутант 1: ">" замінено на ">=".
    private static bool MutantGreaterOrEqual(DateTimeOffset occurredAtUtc) =>
        occurredAtUtc >= Now.AddMinutes(5);

    // Мутант 2: порівняння з now.AddMinutes(4).
    private static bool MutantFourMinutes(DateTimeOffset occurredAtUtc) =>
        occurredAtUtc > Now.AddMinutes(4);

    [Theory]
    [InlineData(PointA, -1)]
    [InlineData(PointB, 0)]
    [InlineData(PointC, 1)]
    public void Points_AreOneTickAroundTheBoundary(string point, long expectedTicksFromBoundary)
    {
        var distance = Parse(point) - Now.AddMinutes(5);

        Assert.Equal(expectedTicksFromBoundary, distance.Ticks);
    }

    [Theory]
    [InlineData(PointA, false)]
    [InlineData(PointB, false)]
    [InlineData(PointC, true)]
    public void CorrectRule_RejectsOnlyPointAfterBoundary(string point, bool expectedRejected)
    {
        Assert.Equal(expectedRejected, Correct(Parse(point)));
    }

    [Theory]
    [InlineData(PointA, false, false, true)]
    [InlineData(PointB, false, true, true)]
    [InlineData(PointC, true, true, true)]
    public void Matrix_CorrectRuleAndBothMutants(
        string point,
        bool expectedCorrect,
        bool expectedGreaterOrEqual,
        bool expectedFourMinutes)
    {
        var occurredAtUtc = Parse(point);

        var correct = Correct(occurredAtUtc);
        var greaterOrEqual = MutantGreaterOrEqual(occurredAtUtc);
        var fourMinutes = MutantFourMinutes(occurredAtUtc);

        output.WriteLine(
            $"now={Now:O}  point={occurredAtUtc:O}  >+5: {correct}  >=+5: {greaterOrEqual}  >+4: {fourMinutes}");

        Assert.Equal(expectedCorrect, correct);
        Assert.Equal(expectedGreaterOrEqual, greaterOrEqual);
        Assert.Equal(expectedFourMinutes, fourMinutes);
    }

    [Fact]
    public void MinimalDistinguishingSet_IsPointsAAndB()
    {
        // Достатність: на {A, B} усі три умови дають різні набори результатів.
        Assert.True(Distinguishes(PointA, PointB));

        // Жодна одна точка не розрізняє три умови (одне булеве значення має лише два варіанти).
        foreach (var point in AllPoints)
        {
            Assert.False(Distinguishes(point));
        }

        // Інші пари теж не підходять: точка C дає true для всіх трьох умов.
        Assert.False(Distinguishes(PointA, PointC));
        Assert.False(Distinguishes(PointB, PointC));
    }

    private bool Distinguishes(params string[] points)
    {
        var parsed = points.Select(Parse).ToArray();

        var signatures = new[]
        {
            Signature(parsed, Correct),
            Signature(parsed, MutantGreaterOrEqual),
            Signature(parsed, MutantFourMinutes)
        };

        output.WriteLine($"{{{string.Join(", ", points)}}} -> {string.Join(" | ", signatures)}");

        return signatures.Distinct(StringComparer.Ordinal).Count() == signatures.Length;
    }

    private static string Signature(DateTimeOffset[] points, Func<DateTimeOffset, bool> rule) =>
        string.Join(",", points.Select(rule));

    private static DateTimeOffset Parse(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
}
