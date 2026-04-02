namespace SecureCatalog.Middleware;

/// <summary>
/// Injects strict security HTTP response headers to mitigate:
/// - Clickjacking (X-Frame-Options: DENY)
/// - MIME-type confusion (X-Content-Type-Options: nosniff)
/// - Referrer leakage (Referrer-Policy)
/// - Unauthorized device access (Permissions-Policy)
/// - All JavaScript execution (CSP script-src 'none')
/// </summary>
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;

        // Strict CSP: script-src 'none' globally disables all JS execution.
        // style-src 'self' only — no unsafe-inline.
        headers["Content-Security-Policy"] =
            "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self';";

        // Prevent clickjacking
        headers["X-Frame-Options"] = "DENY";

        // Prevent MIME-type sniffing
        headers["X-Content-Type-Options"] = "nosniff";

        // Control referrer information leakage
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

        // Deny all device features
        headers["Permissions-Policy"] =
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()";

        await _next(context);
    }
}

/// <summary>Extension method for clean middleware registration.</summary>
public static class SecurityHeadersMiddlewareExtensions
{
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<SecurityHeadersMiddleware>();
    }
}
