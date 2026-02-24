**System Action: Generate Project Documentation (README.md)**

Now that the application code is complete and has passed the security audit, generate a comprehensive `README.md` file for the repository. This file must serve as a quick-start guide for a developer to run the application locally and a manual for testing its specific security implementations.

Structure the `README.md` with the following sections:

**1. Project Overview**
* Briefly describe the application: A secure, JavaScript-free (SSR-only) product catalog built with ASP.NET Core and SQL Server Express, utilizing a strict "Zero Trust" architecture.

**2. Prerequisites**
* List the required tools to run this locally (e.g., .NET SDK [specify LTS version], Visual Studio 2022 or VS Code, SQL Server Express / LocalDB).

**3. Setup and Execution**
* Provide the exact terminal/CLI commands required to:
    * Restore dependencies.
    * Apply Entity Framework Core Code-First migrations to build the SQL Express database (`dotnet ef database update`).
    * Run the application locally (`dotnet run`).

**4. Seeded Credentials**
* Document the default accounts that are created when the database initializes so the evaluator can log in immediately:
    * **Admin:** `admin` / `sk3213r`
    * **Base User:** `user` / `contraseña`

**5. Security Testing Guide (Manual Verification)**
Provide a step-by-step guide on how the developer can manually test and prove that our security mitigations are working. Include instructions for:
* **Testing RBAC & Routing:** Log in as the 'user' and attempt to manually navigate to the `/Productos/Crear` URL. Explain what should happen (403 Forbidden or redirect).
* **Testing IDOR Protection:** Log in as 'user', inspect the Product ID of the admin's seeded product, and try to navigate to `/Productos/Detalle/{admin-product-guid}`. Explain the expected rejection.
* **Testing Anti-CSRF & JS-Free Architecture:** Instruct the user to open the browser's Developer Tools (F12) on a form page, disable JavaScript entirely, and verify that the form still submits successfully. Also, instruct them to view the page source to find the hidden `__RequestVerificationToken` field.
* **Testing the PRG Pattern:** Instruct the user to log in as 'Admin', create a new product, and then press the browser's "Refresh" button on the subsequent list page to verify that it does *not* trigger a duplicate form submission warning.