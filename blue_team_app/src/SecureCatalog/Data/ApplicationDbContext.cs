using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureCatalog.Models;

namespace SecureCatalog.Data;

/// <summary>
/// Application database context inheriting from IdentityDbContext to leverage
/// ASP.NET Core Identity tables (users, roles, claims, tokens).
/// Uses Guid PKs throughout to prevent IDOR enumeration attacks.
/// </summary>
public class ApplicationDbContext : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    /// <summary>Products table with strict schema constraints.</summary>
    public DbSet<Product> Products => Set<Product>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // ── Product entity configuration ──
        builder.Entity<Product>(entity =>
        {
            entity.HasKey(p => p.Id);

            // Sequential GUID generation at DB level to avoid index fragmentation
            entity.Property(p => p.Id)
                .HasDefaultValueSql("NEWSEQUENTIALID()");

            entity.Property(p => p.Nombre)
                .IsRequired()
                .HasMaxLength(100);

            // Decimal(18,2) for absolute financial precision
            entity.Property(p => p.Precio)
                .HasColumnType("decimal(18,2)")
                .IsRequired();

            entity.Property(p => p.Descripcion)
                .HasMaxLength(1000);

            // Optimistic concurrency token
            entity.Property(p => p.RowVersion)
                .IsRowVersion();

            // FK to ApplicationUser with Restrict delete to prevent cascading data loss
            entity.HasOne(p => p.Owner)
                .WithMany()
                .HasForeignKey(p => p.OwnerId)
                .OnDelete(DeleteBehavior.Restrict)
                .IsRequired();

            // Index for efficient owner-scoped queries
            entity.HasIndex(p => p.OwnerId);
        });

        // ── ApplicationUser configuration ──
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(u => u.CreatedAt)
                .IsRequired()
                .HasDefaultValueSql("GETUTCDATE()");

            entity.Property(u => u.LastLoginAt);
        });
    }
}
