**Sub-Directive: Advanced Security by Design & Edge-Case Mitigation**
In addition to the core security baselines, you must architect the application to neutralize the following advanced threat vectors. Implement these defensive design patterns proactively when processing the domain requirements found in the `prompts/` directory.

**1. Server-Side Request Forgery (SSRF) & Outbound Traffic**
If the application must make outbound HTTP requests (e.g., to third-party APIs or webhooks):
* **Zero-Trust `HttpClient`:** Never pass user-supplied URIs directly to `HttpClient`. 
* **Strict Allowlisting:** Maintain a hardcoded, configuration-based allowlist of permitted destination hostnames or IP addresses. Attempting to route outside this list must trigger a fatal security exception.
* **Disable Redirects:** Configure the `HttpClientHandler` to disable automatic redirects (`AllowAutoRedirect = false`) to prevent an attacker from bypassing the allowlist by redirecting a trusted domain to an internal IP (e.g., `169.254.169.254` or `127.0.0.1`).
* **Network Segmentation:** Assume the application server is in a DMZ. Code must not attempt to resolve or connect to internal hostnames unless explicitly documented in the domain requirements.

**2. Advanced Injection (Beyond Standard SQLi & XSS)**
Since JavaScript is disabled, attackers will pivot to secondary injection vectors. 
* **CSS & HTML Injection:** Even without `<script>` tags, an attacker can exfiltrate data (like CSRF tokens) using CSS attribute selectors and background-image requests. Strictly HTML-encode all user input. Never allow user-controlled data to define inline `style` attributes, CSS class names, or structural HTML elements.
* **Second-Order SQLi & Wildcard Denial of Service (DoS):** When implementing search functionality using EF Core `LIKE` or `Contains()`, explicitly escape SQL wildcard characters (`%`, `_`, `[`, `]`) from the user's input before querying the database to prevent table-scanning DoS attacks.
* **Dynamic Sorting Injection:** Never use raw user input to define `ORDER BY` columns in dynamic LINQ. Map user-facing sort parameters (e.g., `?sort=name`) to a strict `switch` statement that references hardcoded EF Core property selectors.

**3. Insecure Direct Object References (IDOR) & Access Control**
* **Opaque Identifiers:** Do not use predictable, sequential integers for primary keys exposed to the client. Use `Guid` (UUIDv4) for all database primary keys and route parameters to prevent enumeration.
* **Context-Aware Authorization:** It is not enough to verify a user is authenticated. Every single data retrieval or modification method must independently verify ownership (e.g., `WHERE Resource.OwnerId == CurrentUser.Id`). Enforce this at the repository or service layer, not just the controller/page level.

**4. Path Traversal & Safe File Handling**
If the domain requirements involve file uploads or downloads:
* **Path Canonicalization:** Never use user input (like a filename) directly in `Path.Combine()`. Generate a new, random GUID for the filename upon upload on the server side. Keep the original filename purely as metadata in the database, if needed.
* **Storage Isolation:** Store all uploaded files outside of the application's web root (`wwwroot`). Files must never be directly addressable via a URL. 
* **Content-Disposition & Sniffing:** When serving files back to the user, always use a `Content-Disposition: attachment` header to force a download rather than rendering in the browser, mitigating the risk of HTML/SVG payload execution.
* **Magic Number Validation:** Do not trust the file extension or the `Content-Type` header provided by the client. Validate the file's raw byte signature (magic numbers) to ensure it matches the expected file type before processing or saving.