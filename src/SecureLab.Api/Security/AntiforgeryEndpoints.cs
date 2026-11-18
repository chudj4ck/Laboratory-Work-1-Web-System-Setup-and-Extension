using Microsoft.AspNetCore.Antiforgery;

namespace SecureLab.Api.Security;

public static class AntiforgeryEndpoints
{
    public const string HeaderName = "X-CSRF-TOKEN";
    public const string CookieName = "SecureLab.Antiforgery";

    public static void AddSecureLabAntiforgery(this WebApplicationBuilder builder)
    {
        builder.Services.AddAntiforgery(options =>
        {
            options.HeaderName = HeaderName;
            options.Cookie.Name = CookieName;
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest
                : CookieSecurePolicy.Always;
        });
    }

    public static void MapSecureLabAntiforgery(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/auth/csrf-token", (HttpContext httpContext, IAntiforgery antiforgery) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(httpContext);
            httpContext.Response.Headers.CacheControl = "no-cache, no-store";
            return Results.Ok(new CsrfTokenResponse(tokens.RequestToken!));
        })
        .RequireAuthorization()
        .WithName("GetCsrfToken")
        .Produces<CsrfTokenResponse>();
    }
}

public sealed record CsrfTokenResponse(string Token);
