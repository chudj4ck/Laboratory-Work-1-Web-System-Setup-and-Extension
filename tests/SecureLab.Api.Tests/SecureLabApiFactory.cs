using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public sealed class SecureLabApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        // У тестовому сервері всі клієнти мають однаковий ключ ліміту ("unknown"),
        // тому для звичайних тестів ліміт входів піднято; сам ліміт перевіряє окремий host.
        builder.UseSetting("LoginRateLimit:PermitLimit", "1000");
        // ЛР 6: так само піднято квоту search; сам search limiter перевіряє окремий host у Lab06RateLimitTests.
        builder.UseSetting("SearchRateLimit:PermitLimit", "1000");
    }
}
