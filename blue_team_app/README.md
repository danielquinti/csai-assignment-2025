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

This guide assumes a **fresh Windows Server (Core or Desktop Experience)** with no preinstalled software. All steps are performed entirely via **PowerShell** (no GUI required).

- **Windows Server 2019 / 2022** (Core or with Desktop Experience)
- **Administrator access** (all commands run in an elevated PowerShell session)
- **Network connectivity** to download installers

---

## Step-by-Step Setup on a Bare Windows Server

> **Important:** Open an **elevated PowerShell** session (Run as Administrator) for all steps below.

### Step 1 — Install .NET 8.0 SDK

Download and silently install the .NET 8.0 SDK:

```powershell
# Download the .NET 8.0 SDK installer
Invoke-WebRequest -Uri "https://dot.net/v1/dotnet-install.ps1" -OutFile "$env:TEMP\dotnet-install.ps1"

# Install the .NET 8.0 SDK (machine-wide)
& "$env:TEMP\dotnet-install.ps1" -Channel 8.0 -InstallDir "C:\Program Files\dotnet" -Runtime aspnetcore

# Also install the full SDK (needed to build/publish)
& "$env:TEMP\dotnet-install.ps1" -Channel 8.0 -InstallDir "C:\Program Files\dotnet"
```

Alternatively, use the standalone installer for an offline server:

```powershell
# Download the offline SDK installer
Invoke-WebRequest -Uri "https://download.visualstudio.microsoft.com/download/pr/dotnet-sdk-8.0-win-x64.exe" `
    -OutFile "$env:TEMP\dotnet-sdk-8.0.exe"

# Silent install
Start-Process -FilePath "$env:TEMP\dotnet-sdk-8.0.exe" -ArgumentList "/install", "/quiet", "/norestart" -Wait
```

Add `dotnet` to PATH if not already present:

```powershell
$dotnetPath = "C:\Program Files\dotnet"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$dotnetPath*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$dotnetPath", "Machine")
}
# Refresh the current session
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine")
```

Verify the installation:

```powershell
dotnet --version
# Expected output: 8.0.x
```

### Step 2 — Install SQL Server Express

Download and silently install SQL Server Express:

```powershell
# Download SQL Server Express installer
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=866658" `
    -OutFile "$env:TEMP\SQLServerExpress.exe"

# Extract the installer
Start-Process -FilePath "$env:TEMP\SQLServerExpress.exe" -ArgumentList "/QS", "/x:$env:TEMP\SQLExpress" -Wait

# Run silent installation
Start-Process -FilePath "$env:TEMP\SQLExpress\setup.exe" -ArgumentList @(
    "/Q",
    "/ACTION=Install",
    "/FEATURES=SQLENGINE",
    "/INSTANCENAME=SQLEXPRESS",
    "/SQLSVCACCOUNT=`"NT AUTHORITY\NETWORK SERVICE`"",
    "/SQLSYSADMINACCOUNTS=`"BUILTIN\Administrators`"",
    "/TCPENABLED=1",
    "/SECURITYMODE=SQL",
    "/SAPWD=<SA_TEMP_PASSWORD>",
    "/IACCEPTSQLSERVERLICENSETERMS"
) -Wait
```

> **Note:** Replace `<SA_TEMP_PASSWORD>` with a strong temporary password. The `sa` account will **not** be used by the application — it is only needed for initial database setup.

Add `sqlcmd` to PATH:

```powershell
$sqlCmdPath = "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn"
# If the above path does not exist, try:
# $sqlCmdPath = "C:\Program Files\Microsoft SQL Server\150\Tools\Binn"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$sqlCmdPath*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$sqlCmdPath", "Machine")
}
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine")
```

Verify SQL Server is running:

```powershell
Get-Service -Name "MSSQL`$SQLEXPRESS"
# Status should be "Running"

# If not running:
Start-Service -Name "MSSQL`$SQLEXPRESS"
Set-Service -Name "MSSQL`$SQLEXPRESS" -StartupType Automatic
```

### Step 3 — Install Git (Optional)

```powershell
# Download Git for Windows
Invoke-WebRequest -Uri "https://github.com/git-for-windows/git/releases/latest/download/Git-2.47.1-64-bit.exe" `
    -OutFile "$env:TEMP\GitInstaller.exe"

# Silent install
Start-Process -FilePath "$env:TEMP\GitInstaller.exe" -ArgumentList "/VERYSILENT", "/NORESTART" -Wait

# Refresh PATH
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
```

If Git is not available, transfer the repository as a `.zip` file and extract it:

```powershell
Expand-Archive -Path "C:\path\to\csai-assignment-2025.zip" -DestinationPath "C:\Apps"
```

### Step 4 — Clone or Copy the Repository

```powershell
cd C:\Apps
git clone <repository-url>
cd csai-assignment-2025
```

### Step 5 — Create a Dedicated SQL Login (Principle of Least Privilege)

> **Security:** The application must never connect as `sa`. Create a dedicated login with minimal permissions.

```powershell
sqlcmd -S localhost\SQLEXPRESS -Q "CREATE LOGIN [SecureCatalogApp] WITH PASSWORD = 'awita12A', CHECK_POLICY = ON;"
```

> Replace `<STRONG_PASSWORD>` with a cryptographically strong password (20+ characters, mixed case, digits, symbols).

The database itself will be created automatically by EF Core migrations on first startup. After the first run, restrict the login's permissions:

```powershell
sqlcmd -S localhost\SQLEXPRESS -Q "
USE [SecureCatalogDb];
CREATE USER [SecureCatalogApp] FOR LOGIN [SecureCatalogApp];
ALTER ROLE [db_datareader] ADD MEMBER [SecureCatalogApp];
ALTER ROLE [db_datawriter] ADD MEMBER [SecureCatalogApp];
GO
"
```

### Step 6 — Set the Connection String (Environment Variable)

> **Never store production credentials in `appsettings.json` or source control.** Use a machine-level environment variable.

```powershell
[Environment]::SetEnvironmentVariable(
    "ConnectionStrings__DefaultConnection",
    "Server=localhost\SQLEXPRESS;Database=SecureCatalogDb;Trusted_Connection=True;MultipleActiveResultSets=true;TrustServerCertificate=True;Encrypt=True;",
    "Machine"
)

# Refresh the current session
$env:ConnectionStrings__DefaultConnection = [Environment]::GetEnvironmentVariable("ConnectionStrings__DefaultConnection", "Machine")
```

> For SQL Authentication (instead of Windows/Trusted), use:
> ```
> Server=localhost\SQLEXPRESS;Database=SecureCatalogDb;User Id=SecureCatalogApp;Password=<STRONG_PASSWORD>;MultipleActiveResultSets=true;TrustServerCertificate=True;Encrypt=True;
> ```

### Step 7 — Restore Dependencies and Publish

```powershell
cd C:\Apps\csai-assignment-2025\src\SecureCatalog

# Restore NuGet packages
dotnet restore

# Publish a Release build (self-contained optional)
dotnet publish -c Release -o C:\Apps\SecureCatalog\publish
```

### Step 8 — Configure the Windows Firewall

Open the HTTPS port so the application is reachable from the network:

```powershell
New-NetFirewallRule -DisplayName "SecureCatalog HTTPS" `
    -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

# Also open 5000/5001 if running Kestrel directly (see Step 9a)
New-NetFirewallRule -DisplayName "SecureCatalog Kestrel HTTPS" `
    -Direction Inbound -Protocol TCP -LocalPort 5001 -Action Allow
```

### Step 9 — Generate a Self-Signed TLS Certificate (or Install Your Own)

For testing/internal use, generate a self-signed certificate:

```powershell
$cert = New-SelfSignedCertificate `
    -DnsName "your-server-hostname" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(2) `
    -KeyAlgorithm RSA -KeyLength 2048

# Export the thumbprint (needed for Kestrel or IIS binding)
$cert.Thumbprint
```

> **Production:** Use a certificate from a trusted CA. Import the `.pfx` file:
> ```powershell
> Import-PfxCertificate -FilePath "C:\certs\securecatalog.pfx" -CertStoreLocation "Cert:\LocalMachine\My" -Password (ConvertTo-SecureString -String "<PFX_PASSWORD>" -AsPlainText -Force)
> ```

---

## Launching the Service

Choose **one** of the following deployment methods:

### Option A — Run as a Windows Service (Kestrel, Recommended for Simplicity)

This runs the application directly on Kestrel as a background Windows Service — no IIS required.

**1. Configure Kestrel URLs**

Set the URLs and HTTPS certificate via environment variables:

```powershell
[Environment]::SetEnvironmentVariable("ASPNETCORE_URLS", "https://0.0.0.0:5001", "Machine")
[Environment]::SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Production", "Machine")

# Point Kestrel to the TLS certificate (use the thumbprint from Step 9)
[Environment]::SetEnvironmentVariable("ASPNETCORE_Kestrel__Certificates__Default__Subject", "your-server-hostname", "Machine")
[Environment]::SetEnvironmentVariable("ASPNETCORE_Kestrel__Certificates__Default__Store", "My", "Machine")
[Environment]::SetEnvironmentVariable("ASPNETCORE_Kestrel__Certificates__Default__Location", "LocalMachine", "Machine")
[Environment]::SetEnvironmentVariable("ASPNETCORE_Kestrel__Certificates__Default__AllowInvalid", "true", "Machine")
```

**2. Register as a Windows Service**

```powershell
# Create the Windows Service
New-Service -Name "SecureCatalog" `
    -BinaryPathName "C:\Apps\SecureCatalog\publish\SecureCatalog.exe" `
    -DisplayName "SecureCatalog Web Application" `
    -Description "Zero Trust Product Catalog - ASP.NET Core" `
    -StartupType Automatic

# Start the service
Start-Service -Name "SecureCatalog"

# Verify it is running
Get-Service -Name "SecureCatalog"
```

**3. Verify**

From another machine on the network:

```powershell
Invoke-WebRequest -Uri "https://<server-ip>:5001" -UseBasicParsing -SkipCertificateCheck
```

> **Managing the service:**
> ```powershell
> Stop-Service -Name "SecureCatalog"
> Restart-Service -Name "SecureCatalog"
> # View logs:
> Get-WinEvent -LogName Application -MaxEvents 50 | Where-Object { $_.Message -like "*SecureCatalog*" }
> ```

### Option B — Deploy with IIS (In-Process Hosting via HTTPS)

**1. Install IIS (Server Core)**

```powershell
# Install IIS with required features (no GUI needed)
Install-WindowsFeature -Name Web-Server, Web-Common-Http, Web-Default-Doc, `
    Web-Http-Errors, Web-Static-Content, Web-Http-Redirect, `
    Web-Health, Web-Http-Logging, Web-Request-Monitor, `
    Web-Performance, Web-Stat-Compression, `
    Web-Security, Web-Filtering, `
    Web-App-Dev, Web-Net-Ext45, Web-Asp-Net45, Web-ISAPI-Ext, Web-ISAPI-Filter `
    -IncludeManagementTools
```

**2. Install the ASP.NET Core Hosting Bundle**

```powershell
# Download the .NET 8.0 Hosting Bundle
Invoke-WebRequest -Uri "https://download.visualstudio.microsoft.com/download/pr/hosting-bundle-8.0-win.exe" `
    -OutFile "$env:TEMP\dotnet-hosting-bundle.exe"

# Silent install
Start-Process -FilePath "$env:TEMP\dotnet-hosting-bundle.exe" -ArgumentList "/install", "/quiet", "/norestart" -Wait

# Restart IIS to load the ASP.NET Core module
Stop-Service -Name W3SVC
Start-Service -Name W3SVC
```

> **Critical:** The Hosting Bundle must be installed **after** IIS. If IIS was installed later, re-run the Hosting Bundle installer.

**3. Deploy the Published Files**

Copy the published output to the IIS content root:

```powershell
$appPath = "C:\inetpub\wwwroot\SecureCatalog"
$keysPath = "$appPath\Keys"

# Create the deployment directory and Keys subfolder
New-Item -ItemType Directory -Path $keysPath -Force

# Copy published files (adjust source path as needed)
Copy-Item -Path "C:\Apps\SecureCatalog\publish\*" -Destination $appPath -Recurse -Force
```

**4. Generate a Self-Signed TLS Certificate for IIS**

> Skip this step if you already have a trusted CA certificate imported into `Cert:\LocalMachine\My`.

```powershell
# Generate a self-signed certificate valid for your server's IP and hostname
$cert = New-SelfSignedCertificate `
    -DnsName "192.168.56.10", "localhost", "$env:COMPUTERNAME" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(2) `
    -KeyAlgorithm RSA -KeyLength 2048 `
    -FriendlyName "SecureCatalog IIS"

# Save the thumbprint — needed for the IIS HTTPS binding
$thumbprint = $cert.Thumbprint
Write-Host "Certificate Thumbprint: $thumbprint"
```

> **Important:** Replace `192.168.56.10` with the actual IP address of your server. Add any additional DNS names or IPs that clients will use to connect.

**5. Create the IIS Application Pool and HTTPS Site**

```powershell
Import-Module WebAdministration

# --- Application Pool ---
New-WebAppPool -Name "SecureCatalogPool" -ErrorAction SilentlyContinue
Set-ItemProperty "IIS:\AppPools\SecureCatalogPool" -Name "managedRuntimeVersion" -Value ""
Set-ItemProperty "IIS:\AppPools\SecureCatalogPool" -Name "managedPipelineMode" -Value "Integrated"
Set-ItemProperty "IIS:\AppPools\SecureCatalogPool" -Name "autoStart" -Value $true

# --- Remove Default Web Site (avoids port conflicts) ---
Remove-WebSite -Name "Default Web Site" -ErrorAction SilentlyContinue

# --- Create the HTTPS website ---
# Using port 443 (standard HTTPS). Leave -HostHeader empty to accept all hostnames.
New-Website -Name "SecureCatalog" `
    -PhysicalPath $appPath `
    -ApplicationPool "SecureCatalogPool" `
    -Port 443 `
    -IPAddress "*" `
    -HostHeader "" `
    -Ssl `
    -Force

# --- Bind the TLS certificate to the HTTPS site ---
# Use the thumbprint from Step 4 (or set it manually)
# $thumbprint = "<YOUR_CERTIFICATE_THUMBPRINT>"
$appId = [guid]::NewGuid().ToString()
netsh http add sslcert ipport=0.0.0.0:443 certhash=$thumbprint appid="{$appId}" certstorename=My

Write-Host "HTTPS binding configured with certificate: $thumbprint"
```

> **Alternative port:** If port 443 is in use, replace `-Port 443` with another port (e.g., `-Port 8443`) and update the firewall rule accordingly.

**6. Set Folder Permissions**

Grant the IIS Application Pool Identity the permissions it needs:

```powershell
$appPath = "C:\inetpub\wwwroot\SecureCatalog"

# Reset ACLs to a clean state
icacls $appPath /reset /T /C /Q

# App Pool identity: Read & Execute on the entire site
icacls $appPath /grant "IIS AppPool\SecureCatalogPool:(OI)(CI)RX" /T

# App Pool identity: Modify on Keys/ (Data Protection key ring)
icacls "$appPath\Keys" /grant "IIS AppPool\SecureCatalogPool:(OI)(CI)M" /T

# IIS anonymous user: Read & Execute
icacls $appPath /grant "IUSR:(OI)(CI)RX" /T
```

> **CRITICAL:** The Data Protection key ring (`Keys/` folder) **must** be writable by the App Pool Identity. Without this, anti-forgery tokens, authentication cookies, and encrypted data will fail after an App Pool recycle.

**7. Open the Firewall**

```powershell
New-NetFirewallRule -DisplayName "SecureCatalog HTTPS (443)" `
    -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
```

**8. Start the Site and Verify**

```powershell
Stop-Website -Name "SecureCatalog" -ErrorAction SilentlyContinue
Restart-WebAppPool -Name "SecureCatalogPool"
Start-Website -Name "SecureCatalog"
```

Verify locally on the server:

```powershell
Invoke-WebRequest -Uri "https://localhost" -UseBasicParsing -SkipCertificateCheck
```

Verify from the host machine (or another machine on the network):

```powershell
Invoke-WebRequest -Uri "https://192.168.56.10" -UseBasicParsing -SkipCertificateCheck
```

> **Note:** `-SkipCertificateCheck` is required when using a self-signed certificate. In a browser, you will need to accept the certificate warning manually.

**9. Hosting Model**

The application is configured for **In-Process hosting** (`<AspNetCoreHostingModel>InProcess</AspNetCoreHostingModel>`) in the `.csproj`, which provides better performance on IIS by running the app inside the `w3wp.exe` process.

**10. Troubleshooting IIS**

```powershell
# Check IIS site status
Get-Website -Name "SecureCatalog"

# View recent ASP.NET Core Module errors
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='IIS AspNetCore Module V2'} -MaxEvents 5 |
    Select-Object TimeCreated, Message | Format-List

# Enable stdout logging for debugging (edit web.config in the app folder)
# Set stdoutLogEnabled="true" in the aspNetCore element, then:
New-Item -ItemType Directory -Path "$appPath\logs" -Force
icacls "$appPath\logs" /grant "IIS AppPool\SecureCatalogPool:(OI)(CI)M" /T
Restart-WebAppPool -Name "SecureCatalogPool"

# View stdout logs
Get-Content "$appPath\logs\stdout_*.log" -Tail 50

# Verify the HTTPS binding and certificate
Get-WebBinding -Name "SecureCatalog"
netsh http show sslcert ipport=0.0.0.0:443
```

> **Common issues:**
> - **HTTP 400 Invalid Hostname:** The site has a Host Header filter. Recreate the binding with `-HostHeader ""`.
> - **502.5 / CLR exited prematurely:** Check stdout logs. Usually a missing connection string or file permission issue.
> - **Access to Keys denied:** Re-run the `icacls` command for the `Keys/` folder.
> - **CREATE DATABASE permission denied:** Pre-create the database with an admin account (see Step 5 in setup).

---

## Post-Deployment Database Lockdown

After the first successful startup (EF Core will auto-migrate and seed the database), restrict the SQL login:

```powershell
sqlcmd -S localhost\SQLEXPRESS -Q "
-- Revoke any elevated permissions; keep only reader/writer
USE [SecureCatalogDb];
EXEC sp_addrolemember 'db_datareader', 'SecureCatalogApp';
EXEC sp_addrolemember 'db_datawriter', 'SecureCatalogApp';
-- Deny DDL operations to the runtime user
DENY CREATE TABLE TO [SecureCatalogApp];
DENY ALTER ANY SCHEMA TO [SecureCatalogApp];
GO
"
```

> **Principle of Least Privilege:** The runtime SQL login (`SecureCatalogApp`) has only `db_datareader` and `db_datawriter` roles. Never use `sa` for the application.

---

## Auto-Start on Boot

### For Windows Service (Option A)

The service is already set to `Automatic` startup. Verify:

```powershell
Get-Service -Name "SecureCatalog" | Select-Object Name, Status, StartType
```

### For IIS (Option B)

IIS starts automatically with Windows. Ensure the Application Pool starts automatically:

```powershell
Set-ItemProperty "IIS:\AppPools\SecureCatalogPool" -Name "autoStart" -Value $true
Set-ItemProperty "IIS:\AppPools\SecureCatalogPool" -Name "startMode" -Value "AlwaysRunning"
```

---

## Seeded Credentials

| Role | Username | Password | Access Level |
|---|---|---|---|
| **Admin** | `admin` | `Admin123` | Full CRUD on all products |
| **Cliente** | `user` | `Password1` | Read-only, own products only |

> The application automatically seeds roles, users, and demo products on first startup (via `MigrateAsync` + `SeedData.InitializeAsync`).

---

## Viewing Logs on a Headless Server

```powershell
# Application stdout/stderr (if running as a Windows Service)
Get-WinEvent -LogName Application -MaxEvents 100 |
    Where-Object { $_.ProviderName -eq ".NET Runtime" -or $_.Message -like "*SecureCatalog*" } |
    Format-List TimeCreated, Message

# IIS logs (if using Option B)
Get-Content "C:\inetpub\logs\LogFiles\W3SVC*\*.log" -Tail 50

# Enable IIS stdout logging for debugging (edit web.config in publish folder)
# Set stdoutLogEnabled="true" in the aspNetCore element, then restart the site.
```

---

## Security Testing Guide (Manual Verification)

> All tests below can be run from a remote machine using a browser or `Invoke-WebRequest` / `curl`.

### 1. Testing RBAC & Routing

1. Log in as `user` / `Password1`
2. Manually navigate to `/Products/Create`
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
3. View page source and find the hidden `__RequestVerificationToken` field
4. Disable JavaScript entirely in the browser
5. Submit the form — it should work perfectly since the app requires zero JavaScript
6. **Expected:** The form submits successfully via standard HTML POST. The anti-forgery token is validated server-side.

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

From the server or a remote machine:

```powershell
$response = Invoke-WebRequest -Uri "https://<server-ip>:5001/Account/Login" -UseBasicParsing -SkipCertificateCheck
$response.Headers
```

**Expected headers present:**
- `Content-Security-Policy: ... script-src 'none' ...`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), ...`

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
