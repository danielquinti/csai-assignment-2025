using System.ComponentModel.DataAnnotations;

namespace SecureCatalog.DTOs;

/// <summary>
/// DTO for creating a product. Prevents Mass Assignment by exposing
/// only the fields a client may supply — no Id, OwnerId, or RowVersion.
/// Strict allowlist validation via RegularExpression on string inputs.
/// </summary>
public class CreateProductDTO
{
    [Required(ErrorMessage = "El nombre del producto es obligatorio.")]
    [MaxLength(100, ErrorMessage = "El nombre no puede exceder 100 caracteres.")]
    [RegularExpression(@"^[\p{L}\p{N}\s\-\.,;:()¡!¿?'""áéíóúñÁÉÍÓÚÑüÜ]+$",
        ErrorMessage = "El nombre contiene caracteres no permitidos.")]
    [Display(Name = "Nombre")]
    public string Nombre { get; set; } = string.Empty;

    [Required(ErrorMessage = "El precio es obligatorio.")]
    [Range(0.01, 999999999999999999.99, ErrorMessage = "El precio debe ser un valor positivo.")]
    [Display(Name = "Precio")]
    public decimal Precio { get; set; }

    [MaxLength(1000, ErrorMessage = "La descripción no puede exceder 1000 caracteres.")]
    [RegularExpression(@"^[\p{L}\p{N}\s\-\.,;:()¡!¿?'""áéíóúñÁÉÍÓÚÑüÜ\r\n]+$",
        ErrorMessage = "La descripción contiene caracteres no permitidos.")]
    [Display(Name = "Descripción")]
    public string? Descripcion { get; set; }
}
