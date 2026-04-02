**System Action: Final DevSecOps Code Review and Audit**

Before finalizing the output and presenting the complete code for this ASP.NET Core application, you must conduct a rigorous, zero-trust security audit of your own generated code. 

Review all Controllers, PageModels, Razor Views, EF Core Entities, and Program.cs/Startup configurations against the following strict checklist. If you detect *any* violation of these rules, you must immediately rewrite that section of the code and explain the vulnerability you patched.

**1. The "No-JavaScript" & UI Architecture Audit:**
* [ ] **Zero JS:** Search your output for `<script>`, `onclick`, `onsubmit`, or any AJAX/Fetch calls. Are there any? If yes, remove them completely.
* [ ] **Strict CSP:** Does the HTTP header middleware explicitly enforce `Content-Security-Policy: script-src 'none';`?
* [ ] **PRG Pattern:** Do all successful `POST` actions (Create, Edit, Delete) end with a `RedirectToAction`, `RedirectToPage`, or `LocalRedirect` (HTTP 302)? They MUST NOT return a `View()` upon success.

**2. Anti-CSRF & State Change Audit:**
* [ ] **GET vs POST:** Are there any state-changing operations (like deleting a product) mapped to a `GET` request or an `<a>` tag? If yes, convert them to an HTML `<form method="post">`.
* [ ] **Tokens:** Does every single `<form>` contain `@Html.AntiForgeryToken()`? Does every single `[HttpPost]` action have the `[ValidateAntiForgeryToken]` attribute?

**3. Data Isolation & IDOR Audit:**
* [ ] **List Views:** In the `GET /Productos` logic, does the query explicitly filter by `OwnerId == CurrentUser.Id` when the user is in the 'Cliente' role?
* [ ] **Detail/Edit/Delete Views:** Before fetching or modifying a single product by its `Guid`, does the backend verify that the `OwnerId` matches the currently logged-in user (unless they are an 'Admin')? 

**4. Database & Entity Audit:**
* [ ] **Mass Assignment Protection:** Are you binding HTTP form data directly to the `Product` database entity? If yes, rewrite it to use a dedicated `CreateProductDTO` or `EditProductViewModel`.
* [ ] **Precision:** Is the product `Precio` strictly configured as `decimal(18,2)`?
* [ ] **Concurrency:** Does the Edit POST action validate the `RowVersion` (Concurrency Token) to prevent lost updates?
* [ ] **Primary Keys:** Are all IDs (User and Product) implemented as `Guid` rather than predictable integers?

**5. Authentication & Access Control Audit:**
* [ ] **RBAC Enforcement:** Are `[Authorize]` and `[Authorize(Roles = "Admin")]` applied at the Controller/Class or Action/Method level? (Hiding UI elements in Razor does not count).
* [ ] **Passwords:** Is the seeding logic utilizing the `UserManager` to properly hash the passwords (`contraseña` and `sk3213r`), or are they being inserted as plaintext? They MUST be hashed.

**Execution:**
Output a brief audit report confirming each of these 5 sections has been verified. If you found errors in your initial draft, detail what you changed. Then, provide the final, hardened, production-ready codebase.