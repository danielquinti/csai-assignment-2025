**Domain Requirement: Database Entities & Schema**

Design the EF Core entities based on the following requirements. Do not write raw SQL; use Entity Framework Core Code-First conventions and Fluent API for all constraints. 

**1. Users (Usuarios)**
Do not build a custom user table from scratch. You MUST inherit from ASP.NET Core Identity's `IdentityUser<Guid>` to handle authentication, password hashing, and security stamps natively.
Extend the default Identity User with the following requirements:
* **Primary Key:** Must be a `Guid` (combats IDOR).
* **Email:** Must be unique, strictly validated format, and max length 256.
* **Role (Rol):** Implement using ASP.NET Core Identity Roles (`IdentityRole<Guid>`). Users will be assigned either 'Cliente' or 'Admin'.
* **Account Security:** Enable `LockoutEnabled` by default to mitigate brute-force attacks.
* **Audit Fields:** Add `CreatedAt` (UTC DateTime) and `LastLoginAt` (UTC DateTime).

**2. Products (Productos)**
Create a strict EF Core entity for products.
* **Primary Key (`Id`):** Must be a `Guid` generated sequentially (e.g., `NewId()` or `newsequentialid()` equivalent in EF Core) to prevent index fragmentation while maintaining unpredictability.
* **Name (`Nombre`):** Required string, maximum length of 100 characters to prevent database bloat/buffer exhaustion.
* **Price (`Precio`):** MUST be configured as a `decimal(18,2)` to ensure absolute financial precision and prevent floating-point rounding vulnerabilities. Cannot be negative.
* **Owner (`Identificador de usuario responsable`):** A foreign key linking to the User's `Guid`. This enforces the Principle of Least Privilege—only the owner or an 'Admin' can modify this product. Enforce `Restrict` or `NoAction` on delete to prevent accidental cascading data loss.
* **Description (`Descripcion`):** Optional string, strict maximum length of 1000 characters. All inputs must be strictly HTML-encoded upon display since we are operating without JavaScript.
* **Concurrency Token (`RowVersion`):** Add a `byte[]` property marked with `[Timestamp]` (or `.IsRowVersion()` in Fluent API) to implement optimistic concurrency. This prevents the "lost update" anomaly if two users try to edit the same product simultaneously.