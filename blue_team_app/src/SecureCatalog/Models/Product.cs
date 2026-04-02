using System.ComponentModel.DataAnnotations;

namespace SecureCatalog.Models;

/// <summary>
/// Product entity with Guid PK (prevents IDOR enumeration), 
/// strict field constraints, and optimistic concurrency via RowVersion.
/// </summary>
public class Product
{
    /// <summary>
    /// Sequential GUID primary key — prevents index fragmentation
    /// while remaining unpredictable to external actors.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>Product name. Max 100 chars enforced at DB and model level.</summary>
    [Required(ErrorMessage = "El nombre del producto es obligatorio.")]
    [MaxLength(100, ErrorMessage = "El nombre no puede exceder 100 caracteres.")]
    public string Nombre { get; set; } = string.Empty;

    /// <summary>
    /// Decimal(18,2) for financial precision. Non-negative enforced via validation.
    /// </summary>
    [Required(ErrorMessage = "El precio es obligatorio.")]
    [Range(0.00, 999999999999999999.99, ErrorMessage = "El precio debe ser un valor positivo.")]
    public decimal Precio { get; set; }

    /// <summary>Optional description. Max 1000 chars. HTML-encoded on display.</summary>
    [MaxLength(1000, ErrorMessage = "La descripción no puede exceder 1000 caracteres.")]
    public string? Descripcion { get; set; }

    /// <summary>
    /// FK to the owning user. Enforces data isolation — 
    /// only the owner or Admin may access this product.
    /// </summary>
    public Guid OwnerId { get; set; }

    /// <summary>Navigation property to the owning user.</summary>
    public ApplicationUser? Owner { get; set; }

    /// <summary>
    /// Optimistic concurrency token. Prevents the "lost update" anomaly 
    /// when two admins edit the same product simultaneously.
    /// </summary>
    [Timestamp]
    public byte[] RowVersion { get; set; } = Array.Empty<byte>();
}
