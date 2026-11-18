using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Security;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public const string LoginRateLimitPolicy = "login-limit";
    public const string AuthenticationLogCategory = "SecureLab.Authentication";

    private const int MinUserNameLength = 3;
    private const int MaxUserNameLength = 256;
    private const int MaxEmailLength = 256;
    private const int MaxDisplayNameLength = 120;
    private const string AllowedUserNameCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

    private static readonly EmailAddressAttribute EmailFormat = new();

    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
          
            var userName = input.UserName?.Trim() ?? string.Empty;
            var email = input.Email?.Trim() ?? string.Empty;
            var displayName = input.DisplayName?.Trim() ?? string.Empty;

            var errors = new Dictionary<string, string[]>();

            if (userName.Length == 0)
            {
                errors["userName"] = ["Ім'я користувача є обов'язковим."];
            }
            else if (userName.Length < MinUserNameLength || userName.Length > MaxUserNameLength)
            {
                errors["userName"] = [$"Ім'я користувача має містити від {MinUserNameLength} до {MaxUserNameLength} символів."];
            }
            else if (!userName.All(character => AllowedUserNameCharacters.Contains(character)))
            {
                errors["userName"] = ["Дозволені латинські літери, цифри та символи - . _ @ +"];
            }

            if (email.Length == 0)
            {
                errors["email"] = ["Електронна пошта є обов'язковою."];
            }
            else if (email.Length > MaxEmailLength || !EmailFormat.IsValid(email))
            {
                errors["email"] = ["Вкажіть коректну адресу електронної пошти."];
            }

            if (displayName.Length == 0)
            {
                errors["displayName"] = ["Відображуване ім'я є обов'язковим."];
            }
            else if (displayName.Length > MaxDisplayNameLength)
            {
                errors["displayName"] = [$"Відображуване ім'я не повинно перевищувати {MaxDisplayNameLength} символів."];
            }

            if (string.IsNullOrEmpty(input.Password))
            {
                errors["password"] = ["Пароль є обов'язковим."];
            }

            if (errors.Count > 0)
            {
                return Results.ValidationProblem(errors);
            }

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = userName,
                Email = email,
                DisplayName = displayName
            };

            var result = await users.CreateAsync(user, input.Password!);
            if (!result.Succeeded)
            {
                var codes = result.Errors.Select(error => error.Code).ToArray();

                if (codes.Any(code => code is "DuplicateUserName" or "DuplicateEmail"))
                {
                    return Results.Problem(
                        title: "Обліковий запис уже існує",
                        detail: "Користувач із такими даними вже зареєстрований.",
                        statusCode: StatusCodes.Status409Conflict);
                }

                return Results.Problem(
                    title: "Реєстрацію відхилено",
                    detail: "Дані не відповідають вимогам. Пароль: щонайменше 10 символів, велика й мала латинські літери, цифра та інший символ.",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");

            return Results.Created("/api/me", new RegistrationResponse(user.Id, userName, displayName));
        });
        app.MapPost("/api/auth/login", async (
            LoginInput input,
            HttpContext httpContext,
            SignInManager<ApplicationUser> signIn,
            ILoggerFactory loggerFactory) =>
        {
            var logger = loggerFactory.CreateLogger(AuthenticationLogCategory);

            // Невідомий користувач, хибний пароль і порожні поля дають однакову відповідь 401.
            // У подію не потрапляють пароль, cookie, хеш, тіло запиту та введене ім'я користувача.
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
            {
                logger.LogWarning(
                    "Authentication event {EventType}: result {Result}, trace {TraceId}",
                    "login", "failed", httpContext.TraceIdentifier);
                return Results.Unauthorized();
            }

            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            if (!result.Succeeded)
            {
                logger.LogWarning(
                    "Authentication event {EventType}: result {Result}, trace {TraceId}",
                    "login", "failed", httpContext.TraceIdentifier);
                return Results.Unauthorized();
            }

            var user = await signIn.UserManager.FindByNameAsync(input.UserName);
            logger.LogInformation(
                "Authentication event {EventType}: result {Result}, user {UserId}, trace {TraceId}",
                "login", "succeeded", user?.Id, httpContext.TraceIdentifier);
            return Results.NoContent();
        }).RequireRateLimiting(LoginRateLimitPolicy);

        app.MapPost("/api/auth/logout", async (
            HttpContext httpContext,
            SignInManager<ApplicationUser> signIn,
            ILoggerFactory loggerFactory) =>
        {
            var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);

            await signIn.SignOutAsync();

            loggerFactory.CreateLogger(AuthenticationLogCategory).LogInformation(
                "Authentication event {EventType}: result {Result}, user {UserId}, trace {TraceId}",
                "logout", "succeeded", userId, httpContext.TraceIdentifier);
            return Results.NoContent();
        })
        .RequireAuthorization()
        .AddEndpointFilter<AntiforgeryFilter>();


        app.MapGet("/api/me", (HttpContext context) =>
        {
            var principal = context.User;

            if (!Guid.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
            {
                return Results.Problem(
                    title: "Некоректний контекст користувача",
                    statusCode: StatusCodes.Status500InternalServerError);
            }

            var userName = principal.FindFirstValue(ClaimTypes.Name) ?? string.Empty;
            var roles = principal.FindAll(ClaimTypes.Role).Select(claim => claim.Value).ToArray();

            return Results.Ok(new CurrentUserResponse(userId, userName, roles));
        }).RequireAuthorization();

        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);

public sealed record RegistrationResponse(Guid Id, string UserName, string DisplayName);

public sealed record CurrentUserResponse(Guid Id, string UserName, IReadOnlyList<string> Roles);
