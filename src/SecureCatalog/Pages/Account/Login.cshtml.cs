using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using SecureCatalog.DTOs;
using SecureCatalog.Models;

namespace SecureCatalog.Pages.Account;

/// <summary>
/// Login page model.
/// Threat mitigations:
/// - Rate limiting on POST to prevent credential stuffing
/// - Anti-forgery token validation (CSRF)
/// - LocalRedirect to prevent Open Redirect
/// - Generic error messages to prevent user enumeration
/// - Account lockout after 5 failed attempts
/// </summary>
[AllowAnonymous]
public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<LoginModel> _logger;

    public LoginModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ILogger<LoginModel> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
    }

    [BindProperty]
    public LoginDTO Input { get; set; } = new();

    public string? ErrorMessage { get; set; }

    public string? ReturnUrl { get; set; }

    public void OnGet(string? returnUrl = null)
    {
        ReturnUrl = returnUrl;
    }

    [EnableRateLimiting("AuthPolicy")]
    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/Products");

        if (!ModelState.IsValid)
        {
            ErrorMessage = "Por favor, complete todos los campos correctamente.";
            return Page();
        }

        // Attempt sign-in with lockout enabled for brute-force protection
        var result = await _signInManager.PasswordSignInAsync(
            Input.UserName,
            Input.Password,
            isPersistent: false,
            lockoutOnFailure: true);

        if (result.Succeeded)
        {
            // Update LastLoginAt audit field
            var user = await _userManager.FindByNameAsync(Input.UserName);
            if (user != null)
            {
                user.LastLoginAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
            }

            _logger.LogInformation("User '{UserName}' logged in successfully.", Input.UserName);

            // LocalRedirect prevents Open Redirect vulnerability
            return LocalRedirect(returnUrl);
        }

        if (result.IsLockedOut)
        {
            _logger.LogWarning("User '{UserName}' account locked out due to too many failed attempts.", Input.UserName);
            ErrorMessage = "Su cuenta ha sido bloqueada temporalmente. Intente de nuevo más tarde.";
            return Page();
        }

        // Generic error message — never reveal if username exists or password is wrong
        _logger.LogWarning("Failed login attempt for user '{UserName}'.", Input.UserName);
        ErrorMessage = "Credenciales inválidas. Verifique su usuario y contraseña.";
        return Page();
    }
}
