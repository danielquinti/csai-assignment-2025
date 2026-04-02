using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCatalog.Data;
using SecureCatalog.DTOs;
using SecureCatalog.Models;

namespace SecureCatalog.Pages.Products;

/// <summary>
/// Product detail page.
/// Threat mitigations:
/// - IDOR: Clientes can only view products they own
/// - Non-existent IDs return 404 (no info leakage)
/// - ViewModel prevents entity exposure
/// </summary>
[Authorize]
public class DetailModel : PageModel
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;

    public DetailModel(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }

    public ProductViewModel? Product { get; set; }

    public async Task<IActionResult> OnGetAsync(Guid id)
    {
        var currentUserId = Guid.Parse(_userManager.GetUserId(User)!);
        var isAdmin = User.IsInRole("Admin");

        var product = await _context.Products
            .Include(p => p.Owner)
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == id);

        if (product == null)
        {
            return NotFound();
        }

        // IDOR protection: Cliente can only see their own products
        if (!isAdmin && product.OwnerId != currentUserId)
        {
            return NotFound(); // Return 404, not 403, to prevent existence leakage
        }

        Product = new ProductViewModel
        {
            Id = product.Id,
            Nombre = product.Nombre,
            Precio = product.Precio,
            Descripcion = product.Descripcion,
            OwnerId = product.OwnerId,
            OwnerUserName = product.Owner?.UserName ?? "Desconocido",
            RowVersion = Convert.ToBase64String(product.RowVersion)
        };

        return Page();
    }
}
