**Domain Requirement: Views, Authorization, and Data Seeding**

Implement the user interface and access control logic based on the following requirements. Adhere strictly to the "No JavaScript" and "Zero Trust" rules established in the master prompt. All UI state and navigation must be handled via Razor Pages (server-side rendering) and standard HTML `<form>` submissions.

**1. Authentication Flow (Login Page)**
* Create a dedicated Razor Page for Login.
* The form must include an Anti-Forgery Token (`@Html.AntiForgeryToken()`).
* Upon successful authentication, strictly use `LocalRedirect(returnUrl)` to navigate the user to the Product Catalog. This prevents Open Redirect vulnerabilities.
* Apply Rate Limiting aggressively to this specific POST endpoint to prevent credential stuffing.

**2. Product Catalog (Data Isolation & UI)**
* **The View (`Index.cshtml`):** This is the landing page post-login. 
    * Display the products in a semantic HTML `<table>` or CSS Grid layout.
    * **Base User ('Cliente'):** Can only see the table of products.
    * **Admin ('Admin'):** Use Razor conditional logic (`@if (User.IsInRole("Admin"))`) to render "Create", "Edit", and "Delete" controls.
* **The Controller/PageModel Logic (Crucial):** Do not rely on the UI to protect data.
    * When querying EF Core for the list, evaluate the user's role:
        * If `Admin`: `dbContext.Products.ToList()`
        * If `Cliente`: `dbContext.Products.Where(p => p.OwnerId == CurrentUser.Id).ToList()`
    * This guarantees Data Isolation (preventing IDOR) at the database level.

**3. State-Changing Operations (Admin CRUD)**
* **Create & Edit:** Must be separate Razor Pages with HTML forms. Ensure all input fields utilize ASP.NET Core `tag helpers` (`asp-for`) to trigger server-side validation messages visually.
* **Delete Action:** **DO NOT use an `<a>` tag (GET request) for deleting products.** Deletion must be implemented as a minimalist HTML `<form method="post">` containing only a "Delete" button and the Anti-Forgery Token. This prevents CSRF attacks where an attacker tricks an admin into clicking a malicious delete link.
* **Backend Authorization:** Decorate the Create, Edit, and Delete PageModels with `[Authorize(Roles = "Admin")]`. Furthermore, before updating or deleting, the backend must verify the target Product ID actually exists to prevent enumeration attacks.

**4. Secure Data Seeding (Initialization)**
The application must seed initial data upon the first run. Do not use raw SQL for this; use the `UserManager` and `RoleManager` to ensure passwords are cryptographically hashed using Identity's default PBKDF2/Argon2 implementation.
* **Seed Roles:** "Admin" and "Cliente".
* **Seed Users:**
    * Username/Email: `user` | Password: `contraseña` | Role: `Cliente`
    * Username/Email: `admin` | Password: `sk3213r` | Role: `Admin`
* **Seed Products:**
    * Create one dummy product and assign its `OwnerId` to the generated `Guid` of the 'user'.
    * Create a second dummy product and assign its `OwnerId` to the generated `Guid` of the 'admin'.