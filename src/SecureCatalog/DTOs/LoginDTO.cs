using System.ComponentModel.DataAnnotations;

namespace SecureCatalog.DTOs;

/// <summary>
/// DTO for the login form. Strict allowlist validation on username.
/// Prevents injection via login field.
/// </summary>
public class LoginDTO
{
    [Required(ErrorMessage = "El nombre de usuario es obligatorio.")]
    [MaxLength(256, ErrorMessage = "El nombre de usuario es demasiado largo.")]
    [RegularExpression(@"^[a-zA-Z0-9\-._@+]+$",
        ErrorMessage = "El nombre de usuario contiene caracteres no permitidos.")]
    [Display(Name = "Usuario")]
    public string UserName { get; set; } = string.Empty;

    [Required(ErrorMessage = "La contraseña es obligatoria.")]
    [MaxLength(128, ErrorMessage = "La contraseña es demasiado larga.")]
    [DataType(DataType.Password)]
    [Display(Name = "Contraseña")]
    public string Password { get; set; } = string.Empty;
}
