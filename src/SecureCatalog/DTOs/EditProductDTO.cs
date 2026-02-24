using System.ComponentModel.DataAnnotations;

namespace SecureCatalog.DTOs;

/// <summary>
/// DTO for editing a product. Includes the RowVersion concurrency token
/// to prevent lost updates. Never includes OwnerId to block reassignment.
/// </summary>
public class EditProductDTO
{
    [Required]
    public Guid Id { get; set; }

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

    /// <summary>
    /// Concurrency token submitted as Base64 hidden field.
    /// Prevents overwriting another admin's simultaneous edits.
    /// </summary>
    [Required(ErrorMessage = "Token de concurrencia faltante. Recargue la página.")]
    public string RowVersion { get; set; } = string.Empty;
}
