using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using SecureCatalog.Data;
using SecureCatalog.Middleware;
using SecureCatalog.Models;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// ══════════════════════════════════════════════════════════════
// DATABASE — SQL Server Express via EF Core
// Connection string from appsettings / environment variables.
// NEVER use 'sa' — runtime user has only db_datareader/db_datawriter.
// ══════════════════════════════════════════════════════════════
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        sqlOptions =>
        {
            sqlOptions.EnableRetryOnFailure(
                maxRetryCount: 3,
                maxRetryDelay: TimeSpan.FromSeconds(10),
                errorNumbersToAdd: null);
        }));

// ══════════════════════════════════════════════════════════════
// ASP.NET CORE IDENTITY — Authentication + RBAC
// Guid PKs, lockout enabled, strict password rules.
// ══════════════════════════════════════════════════════════════
builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
{
    // Password policy — balance between security and seeded passwords
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = true;
    options.Password.RequiredUniqueChars = 2;

    // Lockout — brute-force mitigation
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.RequireUniqueEmail = true;
    options.User.AllowedUserNameCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

    options.SignIn.RequireConfirmedAccount = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// ══════════════════════════════════════════════════════════════
// COOKIE CONFIGURATION — HttpOnly, Secure, SameSite=Strict
// Mitigates XSS cookie theft, CSRF, and session hijacking.
// ══════════════════════════════════════════════════════════════
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Name = "__SecureCatalog_Auth";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
});

// ══════════════════════════════════════════════════════════════
// DATA PROTECTION API — Persist key ring for IIS App Pool recycling
// ══════════════════════════════════════════════════════════════
var keysDirectory = Path.Combine(builder.Environment.ContentRootPath, "Keys");
Directory.CreateDirectory(keysDirectory);

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keysDirectory))
    .SetApplicationName("SecureCatalog")
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90));

// ══════════════════════════════════════════════════════════════
// RATE LIMITING — DDoS & brute-force mitigation
// Aggressive limits on auth endpoints, moderate on general routes.
// ══════════════════════════════════════════════════════════════
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // Global fixed window policy
    options.AddFixedWindowLimiter("GlobalPolicy", opt =>
    {
        opt.PermitLimit = 100;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = 10;
    });

    // Strict policy for authentication endpoints
    options.AddFixedWindowLimiter("AuthPolicy", opt =>
    {
        opt.PermitLimit = 10;
        opt.Window = TimeSpan.FromMinutes(5);
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = 2;
    });

    options.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await context.HttpContext.Response.WriteAsync(
            "Demasiadas solicitudes. Intente de nuevo más tarde.", cancellationToken);
    };
});

// ══════════════════════════════════════════════════════════════
// ANTI-FORGERY — Global CSRF protection filter
// ══════════════════════════════════════════════════════════════
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Name = "__SecureCatalog_AF";
    options.HeaderName = "X-CSRF-TOKEN";
});

// ══════════════════════════════════════════════════════════════
// RAZOR PAGES with global [Authorize] — Zero Trust default
// All pages require authentication unless opted out with [AllowAnonymous].
// ══════════════════════════════════════════════════════════════
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeFolder("/");
    options.Conventions.AllowAnonymousToPage("/Account/Login");
    options.Conventions.AllowAnonymousToPage("/Account/AccessDenied");
    options.Conventions.AllowAnonymousToPage("/Error");
});

// ══════════════════════════════════════════════════════════════
// HSTS — HTTP Strict Transport Security (production only)
// ══════════════════════════════════════════════════════════════
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
});

// ══════════════════════════════════════════════════════════════
// LOGGING — Structured logging, never expose PII to client
// ══════════════════════════════════════════════════════════════
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
builder.Logging.AddFilter("SecureCatalog", LogLevel.Information);

var app = builder.Build();

// ══════════════════════════════════════════════════════════════
// MIDDLEWARE PIPELINE — Order matters for security
// ══════════════════════════════════════════════════════════════

if (!app.Environment.IsDevelopment())
{
    // Global exception handler — never leak stack traces
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
else
{
    // Even in development, don't show detailed exceptions to browser
    app.UseExceptionHandler("/Error");
}

// Force HTTPS redirect
app.UseHttpsRedirection();

// Security headers (CSP, X-Frame-Options, etc.)
app.UseSecurityHeaders();

app.UseStaticFiles();

app.UseRouting();

// Rate limiting
app.UseRateLimiter();

// Authentication & Authorization (order is critical)
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages().RequireRateLimiting("GlobalPolicy");

// ══════════════════════════════════════════════════════════════
// DATABASE SEEDING — Roles, Users, and Products
// Uses UserManager/RoleManager for proper password hashing.
// ══════════════════════════════════════════════════════════════
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        var logger = services.GetRequiredService<ILogger<Program>>();

        await context.Database.MigrateAsync();
        await SeedData.InitializeAsync(context, userManager, roleManager, logger);
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogCritical(ex, "Fatal error during database seeding. Application cannot start safely.");
        throw;
    }
}

app.Run();
