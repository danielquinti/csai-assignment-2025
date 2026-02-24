using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureCatalog.Models;

namespace SecureCatalog.Pages.Account;

/// <summary>
/// Logout handler. POST-only to prevent CSRF logout attacks.
/// Follows PRG pattern — signs out, then redirects.
/// </summary>
public class LogoutModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<LogoutModel> _logger;

    public LogoutModel(
        SignInManager<ApplicationUser> signInManager,
        ILogger<LogoutModel> logger)
    {
        _signInManager = signInManager;
        _logger = logger;
    }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        _logger.LogInformation("User '{UserName}' logged out.", User?.Identity?.Name ?? "Unknown");
        await _signInManager.SignOutAsync();
        return RedirectToPage("/Account/Login");
    }
}
