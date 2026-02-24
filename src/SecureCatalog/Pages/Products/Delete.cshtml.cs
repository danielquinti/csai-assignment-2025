using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCatalog.Data;

namespace SecureCatalog.Pages.Products;

/// <summary>
/// Delete product handler — Admin only, POST only.
/// Threat mitigations:
/// - RBAC: [Authorize(Roles = "Admin")]
/// - CSRF: [ValidateAntiForgeryToken] — deletion via GET is impossible
/// - Existence check: Verifies product exists before delete
/// - No GET handler: Prevents CSRF via link clicks
/// - PRG: Redirect after deletion
/// </summary>
[Authorize(Roles = "Admin")]
public class DeleteModel : PageModel
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<DeleteModel> _logger;

    public DeleteModel(ApplicationDbContext context, ILogger<DeleteModel> logger)
    {
        _context = context;
        _logger = logger;
    }

    // No OnGet — deletion MUST NOT be possible via GET
    // This page exists only as a POST target

    public async Task<IActionResult> OnPostAsync(Guid id)
    {
        var product = await _context.Products
            .FirstOrDefaultAsync(p => p.Id == id);

        if (product == null)
        {
            // Don't reveal whether the ID ever existed
            return NotFound();
        }

        _context.Products.Remove(product);
        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Admin '{UserName}' deleted product '{ProductId}' ('{ProductName}').",
            User.Identity?.Name, product.Id, product.Nombre);

        TempData["SuccessMessage"] = "Producto eliminado exitosamente.";

        // PRG pattern
        return RedirectToPage("/Products/Index");
    }
}
