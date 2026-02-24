# SecureCatalog — Zero Trust Product Catalog

A secure, **JavaScript-free** (SSR-only) product catalog built with **ASP.NET Core 8.0** and **SQL Server Express**, implementing a strict **Zero Trust** security architecture.

---

## Project Overview

SecureCatalog is a hardened web application that demonstrates enterprise-grade security patterns in a Razor Pages application. The entire UI operates without any JavaScript — relying exclusively on server-side rendering, standard HTML form submissions, and HTTP redirects. A strict Content Security Policy (`script-src 'none'`) is enforced globally.

### Key Security Features

| Layer | Mitigation |
|---|---|
| **Authentication** | ASP.NET Core Identity with PBKDF2 password hashing, account lockout |
| **Authorization** | Role-Based Access Control (RBAC) — Admin & Cliente roles |
| **CSRF** | Anti-forgery tokens on every POST form; all mutations via POST only |
| **IDOR** | Guid PKs, owner-scoped queries, backend ownership verification |
| **Mass Assignment** | DTOs/ViewModels — never bind directly to EF Core entities |
| **Concurrency** | Optimistic concurrency via `RowVersion` timestamp tokens |
| **Transport** | HTTPS enforced, HSTS with 1-year max-age |
| **Headers** | CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff |
| **Rate Limiting** | Fixed-window rate limiter on all endpoints; aggressive on auth routes |
| **Data Protection** | DPAPI key ring persisted to disk for IIS App Pool recycle survival |

---

## Prerequisites

- **.NET 8.0 SDK** (LTS) — [Download](https://dotnet.microsoft.com/download/dotnet/8.0)
- **SQL Server Express** or **LocalDB** — [Download](https://www.microsoft.com/en-us/sql-server/sql-server-downloads)
- **Visual Studio 2022** or **VS Code** with C# Dev Kit extension
- **Git** (optional, for cloning)

---

## Setup and Execution

### 1. Clone the Repository

```bash
git clone <repository-url>
cd csai-assignment-2025
```

### 2. Configure the Connection String

The default connection string in `src/SecureCatalog/appsettings.json` targets a local SQL Server Express instance:

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=localhost\\SQLEXPRESS;Database=SecureCatalogDb;Trusted_Connection=True;MultipleActiveResultSets=true;TrustServerCertificate=True;Encrypt=True;"
}
```

If using **LocalDB** instead, replace with:
```json
"DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=SecureCatalogDb;Trusted_Connection=True;MultipleActiveResultSets=true;TrustServerCertificate=True;"
```

> **Security Note:** For production, use environment variables or the .NET Secret Manager. Never commit production connection strings to source control.

### 3. Restore Dependencies

```bash
cd src/SecureCatalog
dotnet restore
```

### 4. Apply Database Migrations

```bash
dotnet ef database update
```

This creates the database schema (Identity tables + Products table) using Code-First migrations.

### 5. Run the Application

```bash
dotnet run
```

Navigate to `https://localhost:7249` in your browser.

> The application automatically seeds roles, users, and demo products on first startup.

---

## Seeded Credentials

| Role | Username | Password | Access Level |
|---|---|---|---|
| **Admin** | `admin` | `Admin123` | Full CRUD on all products |
| **Cliente** | `user` | `Password1` | Read-only, own products only |

---

## Security Testing Guide (Manual Verification)

### 1. Testing RBAC & Routing

1. Log in as `user` / `Password1`
2. Manually navigate to `https://localhost:7249/Products/Create`
3. **Expected:** You are redirected to the Access Denied page (403). The `[Authorize(Roles = "Admin")]` attribute blocks the request at the routing level — the UI button hiding is purely cosmetic.

### 2. Testing IDOR Protection

1. Log in as `admin` / `Admin123`
2. Navigate to `/Products` and note the GUID of the admin's product from the URL (click "Detalle")
3. Log out and log in as `user` / `Password1`
4. Manually navigate to `/Products/Detail/{admin-product-guid}`
5. **Expected:** A `404 Not Found` response. The server returns 404 (not 403) to avoid confirming the resource exists — preventing information leakage.

### 3. Testing Anti-CSRF & JS-Free Architecture

1. Log in as `admin`
2. Navigate to `/Products/Create`
3. Open Developer Tools (F12) → View Page Source
4. Find the hidden `__RequestVerificationToken` field inside the form
5. Disable JavaScript entirely in the browser (DevTools → Settings → Disable JavaScript)
6. Submit the form — it should work perfectly since the app requires zero JavaScript
7. **Expected:** The form submits successfully via standard HTML POST. The anti-forgery token is validated server-side.

### 4. Testing the PRG Pattern

1. Log in as `admin`
2. Create a new product via `/Products/Create`
3. After successful creation, you are redirected to `/Products` (HTTP 302)
4. Press **F5** (Refresh) on the product list page
5. **Expected:** The page refreshes normally without any "Confirm Form Resubmission" browser dialog. This proves the Post-Redirect-Get pattern is working correctly.

### 5. Testing Rate Limiting

1. Navigate to the login page
2. Submit incorrect credentials rapidly (10+ times within 5 minutes)
3. **Expected:** After hitting the limit, you receive an HTTP 429 "Too Many Requests" response. Additionally, ASP.NET Core Identity locks the account after 5 failed attempts for 15 minutes.

### 6. Testing Concurrency Control

1. Open two browser tabs (both logged in as `admin`)
2. In both tabs, navigate to edit the same product
3. Submit changes in Tab 1
4. Submit changes in Tab 2
5. **Expected:** Tab 2 receives a concurrency conflict error message, preventing the "lost update" anomaly.

### 7. Testing Security Headers

1. Open Developer Tools (F12) → Network tab
2. Inspect any response's headers
3. **Expected headers present:**
   - `Content-Security-Policy: ... script-src 'none' ...`
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Permissions-Policy: camera=(), microphone=(), ...`

---

## IIS Production Deployment

### 1. Publish the Application

```bash
dotnet publish -c Release -o ./publish
```

### 2. Configure IIS

1. **Install the ASP.NET Core Hosting Bundle** on the Windows Server
2. **Create an Application Pool:**
   - Set **.NET CLR Version** to **"No Managed Code"**
   - Set **Pipeline Mode** to **Integrated**
3. **Create a Website** pointing to the `./publish` directory
4. **Bind HTTPS** with a valid TLS certificate

### 3. Folder Permissions

Grant the IIS Application Pool Identity (`IIS AppPool\SecureCatalog`) the following:

| Path | Permission |
|---|---|
| Published application folder | Read & Execute |
| `Keys/` directory (Data Protection key ring) | Read & Write |
| SQL Server Express database | `db_datareader`, `db_datawriter` roles only |

> **CRITICAL:** The Data Protection key ring (`Keys/` folder) must be readable/writable by the App Pool Identity. Without this, cryptographic operations (cookies, anti-forgery tokens) will fail after an App Pool recycle, causing session drops and authentication failures.

### 4. Production Connection String

Set the connection string as an environment variable on the server:

```powershell
[Environment]::SetEnvironmentVariable("ConnectionStrings__DefaultConnection", "Server=localhost\SQLEXPRESS;Database=SecureCatalogDb;User Id=SecureCatalogApp;Password=<STRONG_PASSWORD>;Encrypt=True;TrustServerCertificate=False;", "Machine")
```

> **Principle of Least Privilege:** Create a dedicated SQL login (`SecureCatalogApp`) with only `db_datareader` and `db_datawriter` roles. Never use `sa`.

### 5. Hosting Model

The application is configured for **In-Process hosting** (`<AspNetCoreHostingModel>InProcess</AspNetCoreHostingModel>`) in the `.csproj`, which provides better performance on IIS by running the app inside the `w3wp.exe` process.

---

## Project Structure

```
src/SecureCatalog/
├── Data/
│   ├── ApplicationDbContext.cs      # EF Core DbContext with Fluent API config
│   ├── SeedData.cs                  # Secure seeding via UserManager/RoleManager
│   └── Migrations/                  # Code-First migration files
├── DTOs/
│   ├── CreateProductDTO.cs          # Input DTO for product creation
│   ├── EditProductDTO.cs            # Input DTO with concurrency token
│   ├── LoginDTO.cs                  # Login form input with allowlist validation
│   └── ProductViewModel.cs          # Read-only view model for display
├── Middleware/
│   └── SecurityHeadersMiddleware.cs # CSP, X-Frame-Options, etc.
├── Models/
│   ├── ApplicationUser.cs           # IdentityUser<Guid> with audit fields
│   └── Product.cs                   # Product entity with RowVersion
├── Pages/
│   ├── Account/                     # Login, Logout, AccessDenied
│   ├── Products/                    # Index, Detail, Create, Edit, Delete
│   ├── Shared/_Layout.cshtml        # Shared layout (no JS)
│   ├── Error.cshtml                 # Safe error page (no stack trace leaks)
│   ├── _ViewImports.cshtml
│   └── _ViewStart.cshtml
├── Properties/launchSettings.json
├── wwwroot/css/site.css             # CSS-only styling
├── Program.cs                       # App config with all security middleware
├── appsettings.json
├── appsettings.Development.json
└── appsettings.Production.json
```

---

## Threat Model Summary

| Threat | Mitigation |
|---|---|
| SQL Injection | EF Core LINQ only; parameterized queries if raw SQL needed |
| XSS | CSP `script-src 'none'`; Razor auto-encodes all output |
| CSRF | Anti-forgery tokens + SameSite=Strict cookies + POST-only mutations |
| IDOR | Guid PKs + OwnerId verification at query level |
| Mass Assignment | DTOs/ViewModels; never bind to EF entities |
| Brute Force | Rate limiting + Identity lockout (5 attempts / 15 min) |
| Clickjacking | X-Frame-Options: DENY + CSP frame-ancestors: none |
| Session Hijacking | HttpOnly + Secure + SameSite=Strict cookies |
| Open Redirect | `LocalRedirect()` on login |
| Lost Updates | Optimistic concurrency via RowVersion |
| Info Leakage | Generic error pages; 404 for unauthorized IDOR attempts |

---

## License

This project is for educational purposes as part of a Cybersecurity & AI assignment.
