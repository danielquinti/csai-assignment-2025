using Microsoft.AspNetCore.Identity;
using SecureCatalog.Models;

namespace SecureCatalog.Data;

/// <summary>
/// Secure data seeding using UserManager/RoleManager to ensure
/// all passwords are cryptographically hashed (PBKDF2 via Identity defaults).
/// Never inserts plaintext passwords or raw SQL.
/// </summary>
public static class SeedData
{
    public static async Task InitializeAsync(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole<Guid>> roleManager,
        ILogger logger)
    {
        // ── 1. Seed Roles ──
        string[] roles = { "Admin", "Cliente" };
        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                var result = await roleManager.CreateAsync(new IdentityRole<Guid>
                {
                    Name = role,
                    NormalizedName = role.ToUpperInvariant()
                });

                if (result.Succeeded)
                {
                    logger.LogInformation("Role '{Role}' created successfully.", role);
                }
                else
                {
                    logger.LogError("Failed to create role '{Role}': {Errors}",
                        role, string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
        }

        // ── 2. Seed Users ──
        // Base user (Cliente)
        var clienteUser = await userManager.FindByNameAsync("user");
        if (clienteUser == null)
        {
            clienteUser = new ApplicationUser
            {
                UserName = "user",
                Email = "user@securecatalog.local",
                NormalizedUserName = "USER",
                NormalizedEmail = "USER@SECURECATALOG.LOCAL",
                EmailConfirmed = true,
                LockoutEnabled = true,
                CreatedAt = DateTime.UtcNow
            };

            // Password hashed by Identity's PBKDF2 implementation
            // Strong password with mixed case, digits, and special chars
            var result = await userManager.CreateAsync(clienteUser, "j{m:3(P?Pv29");
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(clienteUser, "Cliente");
                logger.LogInformation("Seeded user 'user' with role 'Cliente'.");
            }
            else
            {
                logger.LogError("Failed to seed user 'user': {Errors}",
                    string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }

        // Admin user
        var adminUser = await userManager.FindByNameAsync("admin");
        if (adminUser == null)
        {
            adminUser = new ApplicationUser
            {
                UserName = "admin",
                Email = "admin@securecatalog.local",
                NormalizedUserName = "ADMIN",
                NormalizedEmail = "ADMIN@SECURECATALOG.LOCAL",
                EmailConfirmed = true,
                LockoutEnabled = true,
                CreatedAt = DateTime.UtcNow
            };

            var result2 = await userManager.CreateAsync(adminUser, "v[9T8B2MQ&;k");
            if (result2.Succeeded)
            {
                await userManager.AddToRoleAsync(adminUser, "Admin");
                logger.LogInformation("Seeded user 'admin' with role 'Admin'.");
            }
            else
            {
                logger.LogError("Failed to seed user 'admin': {Errors}",
                    string.Join(", ", result2.Errors.Select(e => e.Description)));
            }
        }

        // ── 3. Seed Products ──
        if (!context.Products.Any())
        {
            // Re-fetch users to ensure we have their generated Guids
            var seededUser = await userManager.FindByNameAsync("user");
            var seededAdmin = await userManager.FindByNameAsync("admin");

            if (seededUser != null && seededAdmin != null)
            {
                context.Products.AddRange(
                    new Product
                    {
                        Nombre = "Producto de ejemplo del cliente",
                        Precio = 29.99m,
                        Descripcion = "Este producto pertenece al usuario cliente para demostración.",
                        OwnerId = seededUser.Id
                    },
                    new Product
                    {
                        Nombre = "Producto de ejemplo del administrador",
                        Precio = 49.99m,
                        Descripcion = "Este producto pertenece al usuario administrador para demostración.",
                        OwnerId = seededAdmin.Id
                    }
                );

                await context.SaveChangesAsync();
                logger.LogInformation("Seeded 2 demo products successfully.");
            }
            else
            {
                logger.LogWarning("Could not seed products — user accounts not found.");
            }
        }
    }
}
