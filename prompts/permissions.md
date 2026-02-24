**Domain Requirement: Permissions Matrix and Role-Based Access Control (RBAC)**

Implement Role-Based Access Control for the product catalog.

**CRITICAL CONSTRAINT (No-JavaScript Architecture):** Since JavaScript is strictly prohibited, you cannot use AJAX/Fetch calls. Therefore, the HTTP verbs `PUT` and `DELETE` cannot be natively emitted by the browser. You must map these actions to secure HTTP `POST` requests sent via standard HTML `<form>` submissions.

Furthermore, instead of returning `200 OK` or `201 Created` with a JSON payload (like in a REST API), successful mutation actions (`POST` for create, update, or delete) must strictly implement the **PRG (Post-Redirect-Get) Pattern**. They must return a `302 Found` status code, redirecting the user back to the list view. Denied access must return a `403 Forbidden` or redirect to the ASP.NET Core Identity "Access Denied" page.

Apply the following permission matrix at the Controller/PageModel level using the `[Authorize]` attribute:

**1. Read List (Conceptual: GET /productos)**
* **Implementation Route:** `GET /Products`
* **Permissions:** `[Authorize]` (Accessible to 'Cliente' and 'Admin')
* **Cliente Action:** ✅ 200 OK (Renders HTML view. Note: Filter internally so they only see their own products, mitigating IDOR).
* **Admin Action:** ✅ 200 OK (Renders HTML view with all products).

**2. Create New (Conceptual: POST /productos)**
* **Implementation Route:** `POST /Products/Create`
* **Permissions:** `[Authorize(Roles = "Admin")]`
* **Cliente Action:** ❌ 403 Forbidden (Access denied at the routing level).
* **Admin Action:** ✅ Success (Saves to DB and returns `302 Redirect` to `/Products`).
* **Extra Security:** Requires `[ValidateAntiForgeryToken]`.

**3. Update Data (Conceptual: PUT /productos/:id)**
* **Implementation Route:** `POST /Products/Edit/{id:guid}`
* **Permissions:** `[Authorize(Roles = "Admin")]`
* **Cliente Action:** ❌ 403 Forbidden.
* **Admin Action:** ✅ Success (Updates DB after validating concurrency token and returns `302 Redirect`).
* **Extra Security:** Requires `[ValidateAntiForgeryToken]`.

**4. Delete Item (Conceptual: DELETE /productos/:id)**
* **Implementation Route:** `POST /Products/Delete/{id:guid}`
* **Permissions:** `[Authorize(Roles = "Admin")]`
* **Cliente Action:** ❌ 403 Forbidden.
* **Admin Action:** ✅ Success (Deletes from DB and returns `302 Redirect`).
* **Extra Security:** Requires `[ValidateAntiForgeryToken]`. **Under no circumstances** should deleting a product be allowed via a `GET` request (e.g., typing the URL or clicking an `<a>` link), as this opens the door to lethal CSRF attacks.

**UI Security Directive:**
Hiding buttons in the HTML (`@if(User.IsInRole("Admin"))`) is purely a UX enhancement, not a security measure. Role validation MUST be enforced on the backend (Controller/PageModel). You must assume a malicious 'Cliente' user will attempt to send a forged POST request to `/Products/Delete/1234` directly. The `[Authorize(Roles = "Admin")]` attribute must block this attempt before it ever reaches the database logic.