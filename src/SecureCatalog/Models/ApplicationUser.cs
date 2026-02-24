using Microsoft.AspNetCore.Identity;

namespace SecureCatalog.Models;

/// <summary>
/// Extended ASP.NET Core Identity user with audit fields.
/// Uses Guid PK to prevent IDOR via sequential ID enumeration.
/// Inherits password hashing (PBKDF2), security stamps, and lockout from IdentityUser.
/// </summary>
public class ApplicationUser : IdentityUser<Guid>
{
    /// <summary>UTC timestamp of account creation for audit trail.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>UTC timestamp of last successful login for anomaly detection.</summary>
    public DateTime? LastLoginAt { get; set; }
}
