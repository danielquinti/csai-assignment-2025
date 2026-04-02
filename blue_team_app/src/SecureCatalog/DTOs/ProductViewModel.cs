namespace SecureCatalog.DTOs;

/// <summary>
/// Read-only ViewModel for displaying product data in views.
/// Never exposes the raw EF Core entity to the presentation layer.
/// All string properties are HTML-encoded upon rendering by Razor tag helpers.
/// </summary>
public class ProductViewModel
{
    public Guid Id { get; set; }
    public string Nombre { get; set; } = string.Empty;
    public decimal Precio { get; set; }
    public string? Descripcion { get; set; }
    public Guid OwnerId { get; set; }
    public string OwnerUserName { get; set; } = string.Empty;

    /// <summary>Base64-encoded RowVersion for concurrency in edit forms.</summary>
    public string RowVersion { get; set; } = string.Empty;
}
