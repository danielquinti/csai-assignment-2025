using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCatalog.Data;
using SecureCatalog.DTOs;
using SecureCatalog.Models;

namespace SecureCatalog.Pages.Products;

/// <summary>
/// Product catalog listing.
/// Threat mitigations:
/// - IDOR: Clientes only see their own products (OwnerId filter)
/// - Mass Assignment: Returns ProductViewModel, never raw EF entities
/// - Data isolation enforced at query level, not just UI
/// </summary>
[Authorize]
public class IndexModel : PageModel
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;

    public IndexModel(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }

    public IList<ProductViewModel> Products { get; set; } = new List<ProductViewModel>();

    public async Task OnGetAsync()
    {
        var currentUserId = Guid.Parse(_userManager.GetUserId(User)!);
        var isAdmin = User.IsInRole("Admin");

        // Data isolation: Admin sees all, Cliente sees only their own
        var query = _context.Products
            .Include(p => p.Owner)
            .AsNoTracking();

        if (!isAdmin)
        {
            query = query.Where(p => p.OwnerId == currentUserId);
        }

        var products = await query.OrderBy(p => p.Nombre).ToListAsync();

        // Map to ViewModel — never expose raw EF entity to view
        Products = products.Select(p => new ProductViewModel
        {
            Id = p.Id,
            Nombre = p.Nombre,
            Precio = p.Precio,
            Descripcion = p.Descripcion,
            OwnerId = p.OwnerId,
            OwnerUserName = p.Owner?.UserName ?? "Desconocido",
            RowVersion = Convert.ToBase64String(p.RowVersion)
        }).ToList();
    }
}
