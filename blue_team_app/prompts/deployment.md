**Deployment Target & Environmental Constraints:**

This application will be developed locally but the final production environment is **IIS (Internet Information Services) hosted on a Windows Server Virtual Machine**. The agent must configure the application architecture to be optimized and secure for this specific environment.

**1. IIS Hosting Configuration:**
* Configure the application to use the **In-Process hosting model** (`<AspNetCoreHostingModel>InProcess</AspNetCoreHostingModel>` in the `.csproj`).
* Ensure IIS Integration middleware is properly configured to capture Windows Server context if necessary.

**2. Data Protection & Cryptography:**
* **CRITICAL:** Configure the ASP.NET Core Data Protection API (`builder.Services.AddDataProtection()`) to explicitly persist cryptographic keys to a designated secure directory or the Windows Registry. You must document in the README that the IIS Application Pool Identity (`IIS AppPool\YourApp`) requires read/write permissions to this key ring location. Failure to do this will result in cryptographic failures and session drops during IIS App Pool recycles.

**3. Database Connection:**
* Assume SQL Server Express is installed on the same Windows Server VM. 
* Prepare the `appsettings.json` and `appsettings.Production.json` to handle standard SQL Server connection strings (e.g., utilizing `Server=localhost\SQLEXPRESS`).

**4. Deployment Documentation:**
* Add a dedicated section to the `README.md` titled **"IIS Production Deployment."** * This section must instruct the administrator on how to:
    1. Publish the app (`dotnet publish -c Release`).
    2. Create an IIS Application Pool (Set .NET CLR Version to "No Managed Code").
    3. Assign the correct Windows folder permissions so the App Pool Identity can read the published files and access the SQLite/SQL Express database.