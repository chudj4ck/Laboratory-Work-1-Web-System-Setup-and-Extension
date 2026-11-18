using SecureLab.Api.Scaffolding;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Endpoints;
using SecureLab.Api.Security;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = "Client"
});
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

var connectionString = builder.Configuration.GetConnectionString("SecureLab")
    ?? throw new InvalidOperationException(
        "Connection string 'SecureLab' не налаштовано.");

builder.Services.AddDbContext<SecureLabDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddScoped<IncidentQueries>();

builder.AddLab03Identity();
builder.AddSecureLabAntiforgery();

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, _) =>
    {
        var httpContext = context.HttpContext;
        var isLogin = httpContext.Request.Path.StartsWithSegments("/api/auth/login");
        httpContext.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger(isLogin ? Lab03Identity.AuthenticationLogCategory : "SecureLab.RateLimiting")
            .LogWarning(
                "Rate limit event {EventType}: result {Result}, trace {TraceId}",
                isLogin ? "login" : "incident.search", "rate_limited", httpContext.TraceIdentifier);

        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            httpContext.Response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(
                System.Globalization.CultureInfo.InvariantCulture);
        }

        await Results.Problem(
            title: "Забагато запитів",
            detail: "Квоту запитів вичерпано. Повторіть пізніше.",
            statusCode: StatusCodes.Status429TooManyRequests)
            .ExecuteAsync(httpContext);
    };
    options.AddPolicy(Lab03Identity.LoginRateLimitPolicy, httpContext =>
    {
        var configuration = httpContext.RequestServices.GetRequiredService<IConfiguration>();
        var permitLimit = configuration.GetValue("LoginRateLimit:PermitLimit", 5);
        var windowSeconds = configuration.GetValue("LoginRateLimit:WindowSeconds", 60);

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = TimeSpan.FromSeconds(windowSeconds),
                QueueLimit = 0
            });
    });

    options.AddPolicy(IncidentEndpoints.SearchRateLimitPolicy, httpContext =>
    {
        var configuration = httpContext.RequestServices.GetRequiredService<IConfiguration>();
        var permitLimit = configuration.GetValue("SearchRateLimit:PermitLimit", 3);
        var windowSeconds = configuration.GetValue("SearchRateLimit:WindowSeconds", 10);
        var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: userId is null ? "anonymous" : $"user:{userId}",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = TimeSpan.FromSeconds(windowSeconds),
                QueueLimit = 0
            });
    });
});

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("Lab05BrowserProbe", policy =>
        {
            policy.WithOrigins("http://localhost:4173")
                .WithMethods("GET")
                .WithHeaders("X-Lab-Cors-Probe")
                .AllowCredentials();
        });
    });
}

var app = builder.Build();

var resetRequested = args.Contains("--reset-database", StringComparer.Ordinal);
await DatabaseBootstrap.InitializeAsync(app.Services, app.Configuration, app.Environment, resetRequested);

if (resetRequested)
{
    return;
}

const string ContentSecurityPolicy =
    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    + "img-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

app.Use(async (context, next) =>
{
    context.Response.OnStarting(() =>
    {
        var headers = context.Response.Headers;
        headers.XContentTypeOptions = "nosniff";
        headers["Referrer-Policy"] = "no-referrer";

        var isDevelopmentApiReference =
            app.Environment.IsDevelopment()
            && context.Request.Path.StartsWithSegments("/scalar");
        if (!isDevelopmentApiReference)
        {
            headers.ContentSecurityPolicy = ContentSecurityPolicy;
        }

        return Task.CompletedTask;
    });

    await next(context);
});

app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseRouting();
if (app.Environment.IsDevelopment())
{
    app.UseCors("Lab05BrowserProbe");
}

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", async (SecureLabDbContext dbContext, CancellationToken cancellationToken) =>
    await dbContext.Database.CanConnectAsync(cancellationToken)
        ? Results.Ok(new { status = "ready" })
        : Results.Problem(
            title: "База даних недоступна",
            statusCode: StatusCodes.Status503ServiceUnavailable))
    .WithName("GetHealth")
    .Produces(StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

app.MapIncidentEndpoints();
app.MapLab03Identity();
app.MapSecureLabAntiforgery();
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;
