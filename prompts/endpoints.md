**Domain Requirement: Secure Routing & Endpoint Controllers**

Implement the following routes. **CRITICAL CONSTRAINT:** Because this application strictly forbids JavaScript, you must not create a JSON-based REST API using `ControllerBase`. You must implement these as MVC Controllers returning `View()` or `RedirectToAction()`, or as Razor Pages. 

Since native HTML `<form>` elements only support GET and POST, you must implement the conceptual PUT and DELETE actions as highly secured POST endpoints.

**1. Catalog Listing (Concept: GET /productos)**
* **Route:** `/Productos` (HTTP GET)
* **Allowed Roles:** Admin, Cliente
* **Security & Action:** Retrieves the list of products. 
    * If `Admin`, fetch all. 
    * If `Cliente`, fetch ONLY where `OwnerId == CurrentUser.Id`.
    * Pass the data to the View using a strictly typed ViewModel, not the raw EF Core entity.

**2. Product Detail (Concept: GET /productos/{id})**
* **Route:** `/Productos/Detalle/{id:guid}` (HTTP GET)
* **Allowed Roles:** Admin, Cliente
* **Security & Action:** Retrieves a single product. 
    * **IDOR Protection:** The controller MUST verify that the requested `{id}` belongs to the `CurrentUser` (unless the user is an `Admin`). If a `Cliente` requests an `{id}` they do not own, immediately return a `404 Not Found` or `403 Forbidden`. Do not leak the existence of other users' products.

**3. Create Product (Concept: POST /productos)**
* **Route:** `/Productos/Crear` (HTTP POST)
* **Allowed Roles:** Admin ONLY (`[Authorize(Roles = "Admin")]`)
* **Security & Action:** Creates a new product.
    * Must validate the `[ValidateAntiForgeryToken]`.
    * Must bind input using a specific `CreateProductDTO`. Do not bind directly to the database entity to prevent Mass Assignment.
    * Validate `ModelState`. If invalid, return the View with sanitized error messages.

**4. Update Product (Concept: PUT /productos/{id})**
* **Route:** `/Productos/Editar/{id:guid}` (HTTP POST) *Adapted from PUT for HTML form compatibility.*
* **Allowed Roles:** Admin ONLY (`[Authorize(Roles = "Admin")]`)
* **Security & Action:** Updates an existing product.
    * Must validate the `[ValidateAntiForgeryToken]`.
    * Must verify the `{id}` exists in the database before attempting an update.
    * Must validate the EF Core Concurrency Token (`RowVersion`) submitted in the form as a hidden field to prevent overwriting another Admin's simultaneous edits.

**5. Delete Product (Concept: DELETE /productos/{id})**
* **Route:** `/Productos/Eliminar/{id:guid}` (HTTP POST) *Adapted from DELETE for HTML form compatibility.*
* **Allowed Roles:** Admin ONLY (`[Authorize(Roles = "Admin")]`)
* **Security & Action:** Deletes a product.
    * **CRITICAL:** This must be a POST request triggered by a form containing only a submit button. It must validate `[ValidateAntiForgeryToken]`. Do not allow deletion via a GET request to prevent CSRF.