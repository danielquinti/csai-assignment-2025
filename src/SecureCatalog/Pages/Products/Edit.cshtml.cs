using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCatalog.Data;
using SecureCatalog.DTOs;

namespace SecureCatalog.Pages.Products;

/// <summary>
/// Edit product page — Admin only.
/// Threat mitigations:
/// - RBAC: [Authorize(Roles = "Admin")]
/// - Mass Assignment: Binds to EditProductDTO, not Product entity
/// - CSRF: [ValidateAntiForgeryToken]
/// - Concurrency: RowVersion check prevents lost updates
/// - Existence check: Verifies product ID exists before update
/// - PRG: Redirect after successful update
/// </summary>
[Authorize(Roles = "Admin")]
public class EditModel : PageModel
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<EditModel> _logger;

    public EditModel(ApplicationDbContext context, ILogger<EditModel> logger)
    {
        _context = context;
        _logger = logger;
    }

    [BindProperty]
    public EditProductDTO Input { get; set; } = new();

    public async Task<IActionResult> OnGetAsync(Guid id)
    {
        var product = await _context.Products
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == id);

        if (product == null)
        {
            return NotFound();
        }

        Input = new EditProductDTO
        {
            Id = product.Id,
            Nombre = product.Nombre,
            Precio = product.Precio,
            Descripcion = product.Descripcion,
            RowVersion = Convert.ToBase64String(product.RowVersion)
        };

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        // Verify the product exists
        var product = await _context.Products
            .FirstOrDefaultAsync(p => p.Id == Input.Id);

        if (product == null)
        {
            return NotFound();
        }

        // Map DTO fields to entity — prevents Mass Assignment
        product.Nombre = Input.Nombre;
        product.Precio = Input.Precio;
        product.Descripcion = Input.Descripcion;

        // Set the original RowVersion for concurrency check
        _context.Entry(product).Property(p => p.RowVersion)
            .OriginalValue = Convert.FromBase64String(Input.RowVersion);

        try
        {
            await _context.SaveChangesAsync();

            _logger.LogInformation(
                "Admin '{UserName}' updated product '{ProductId}'.",
                User.Identity?.Name, product.Id);

            TempData["SuccessMessage"] = "Producto actualizado exitosamente.";
            return RedirectToPage("/Products/Index");
        }
        catch (DbUpdateConcurrencyException)
        {
            _logger.LogWarning(
                "Concurrency conflict editing product '{ProductId}' by '{UserName}'.",
                Input.Id, User.Identity?.Name);

            TempData["ErrorMessage"] =
                "El producto fue modificado por otro usuario. Recargue e intente de nuevo.";

            // Reload fresh data
            var freshProduct = await _context.Products
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == Input.Id);

            if (freshProduct == null)
            {
                return NotFound();
            }

            Input = new EditProductDTO
            {
                Id = freshProduct.Id,
                Nombre = freshProduct.Nombre,
                Precio = freshProduct.Precio,
                Descripcion = freshProduct.Descripcion,
                RowVersion = Convert.ToBase64String(freshProduct.RowVersion)
            };

            ModelState.AddModelError(string.Empty,
                "El producto fue modificado por otro usuario. Se han cargado los datos actuales.");

            return Page();
        }
    }
}
