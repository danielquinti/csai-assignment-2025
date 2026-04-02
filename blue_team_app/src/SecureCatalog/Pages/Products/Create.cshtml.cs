using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureCatalog.Data;
using SecureCatalog.DTOs;
using SecureCatalog.Models;

namespace SecureCatalog.Pages.Products;

/// <summary>
/// Create product page — Admin only.
/// Threat mitigations:
/// - RBAC: [Authorize(Roles = "Admin")] blocks Cliente at routing level
/// - Mass Assignment: Binds to CreateProductDTO, not Product entity
/// - CSRF: [ValidateAntiForgeryToken] on POST
/// - PRG: Redirect after successful creation prevents duplicate submissions
/// - Input validation: Strict allowlist regex on all string fields
/// </summary>
[Authorize(Roles = "Admin")]
public class CreateModel : PageModel
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<CreateModel> _logger;

    public CreateModel(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        ILogger<CreateModel> logger)
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
    }

    [BindProperty]
    public CreateProductDTO Input { get; set; } = new();

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var currentUserId = Guid.Parse(_userManager.GetUserId(User)!);

        // Map DTO to entity — prevents Mass Assignment
        var product = new Product
        {
            Nombre = Input.Nombre,
            Precio = Input.Precio,
            Descripcion = Input.Descripcion,
            OwnerId = currentUserId
        };

        _context.Products.Add(product);
        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Admin '{UserName}' created product '{ProductId}'.",
            User.Identity?.Name, product.Id);

        TempData["SuccessMessage"] = "Producto creado exitosamente.";

        // PRG pattern: Redirect to prevent duplicate form submission on refresh
        return RedirectToPage("/Products/Index");
    }
}
