using Microsoft.AspNetCore.Antiforgery;

namespace SecureLab.Api.Security;

public sealed class AntiforgeryFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.Problem(
                title: "Antiforgery token is missing or invalid",
                detail: "Змінювальний запит потребує дійсного request token у заголовку X-CSRF-TOKEN.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return await next(context);
    }
}
