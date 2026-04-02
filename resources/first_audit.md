# 🔴 Red Team Audit Report — Target 192.168.56.137

**Date:** 2026-04-02  
**Target:** Windows Server 2025 (VirtualBox VM) — `192.168.56.137`  
**Attacker:** Kali Linux (VirtualBox) — Host-Only Network `192.168.56.0/24`  
**Methodology:** PTES / MITRE ATT&CK  

---

## Executive Summary

The target is a **hardened Windows Server 2025** running a **React SPA + ASP.NET Core backend** on IIS, exposed only on ports **80 and 443**. The application implements aggressive security controls including rate limiting, JWT authentication, comprehensive security headers, and a tightly filtered firewall. No critical vulnerabilities were exploited during this phase, but several **informational and medium findings** were identified that warrant further investigation.

**Victory Conditions Status:**
| Objective | Status |
|---|---|
| Exfiltrate Database | ❌ Not achieved — No SQL injection found, no direct DB access |
| NT AUTHORITY\SYSTEM Shell | ❌ Not achieved — No RCE vector identified via network |

---

## 1. Network Reconnaissance

### 1.1 Host Discovery
| Detail | Value |
|---|---|
| **IP** | `192.168.56.137` |
| **MAC** | `08:00:27:4E:39:58` (Oracle VirtualBox NIC) |
| **ICMP** | ❌ Blocked (100% packet loss) |
| **OS Guess** | Windows Server 2022/2025 (91% confidence) |
| **MITRE** | [T1046] Network Service Discovery |

### 1.2 Port Scan (Full 65535 TCP)

| Port | State | Service | Version |
|---|---|---|---|
| **80/tcp** | Open | HTTP | Microsoft HTTPAPI httpd 2.0 |
| **443/tcp** | Open | HTTPS | IIS (behind reverse proxy) |
| All others | Filtered | — | Windows Firewall |

> [!IMPORTANT]
> Only 2 out of 65,535 TCP ports are open. The firewall is extremely restrictive. Critical services like **RDP (3389)**, **WinRM (5985/5986)**, **SMB (445)**, **SQL Server (1433)**, and **MSRPC (135)** are all filtered.

### 1.3 Filtered Ports Specifically Tested

| Port | Service | Status |
|---|---|---|
| 53 | DNS | Filtered |
| 135 | MSRPC | Filtered |
| 139 | NetBIOS | Filtered |
| 445 | SMB | Filtered |
| **1433** | **SQL Server** | **Filtered** |
| 3306 | MySQL | Filtered |
| 3389 | RDP | Filtered |
| 5985 | WinRM HTTP | Filtered |
| 5986 | WinRM HTTPS | Filtered |
| 8080 | HTTP Alt | Filtered |
| 8443 | HTTPS Alt | Filtered |

---

## 2. Web Application Analysis

### 2.1 Application Architecture

| Component | Technology |
|---|---|
| **Frontend** | React SPA (Vite build) |
| **Backend API** | ASP.NET Core (behind IIS reverse proxy) |
| **API Base URL** | `https://192.168.56.137/backend/api` |
| **Auth Mechanism** | JWT Bearer tokens (stored in localStorage) |
| **Roles** | `Admin`, `Client` |
| **User IDs** | Sequential integers (not GUIDs) |
| **Language** | Spanish (es) |

### 2.2 Discovered Routes (Frontend — React Router)

| Route | Purpose | Auth Required |
|---|---|---|
| `/login` | Login page | No |
| `/dashboard` | Main dashboard | Yes |
| `/users/create` | Create user | Yes (Admin) |
| `/users/:id` | User details/edit | Yes (Admin) |
| `/profile/:id` | User profile edit | Yes |
| `/unauthorized` | Access denied page | No |

### 2.3 Discovered API Endpoints

| Method | Endpoint | Auth | Status |
|---|---|---|---|
| `POST` | `/backend/api/auth/login` | No | ✅ Confirmed (405 on GET) |
| `GET` | `/backend/api/auth/validate` | Yes (Bearer) | ✅ Confirmed (401 unauth) |
| `GET` | `/backend/api/users` | Yes (Bearer) | ✅ Confirmed (401 unauth) |
| `POST` | `/backend/api/users` | Yes (Bearer) | ✅ Confirmed (401 unauth) |
| `GET` | `/backend/api/users/{id}` | Yes (Bearer) | ✅ Confirmed (401 unauth) |
| `PUT` | `/backend/api/users/{id}` | Yes (Bearer) | Inferred from JS |
| `DELETE` | `/backend/api/users/{id}` | Yes (Bearer) | Inferred from JS |

> [!NOTE]
> The API consistently returns 401 for all protected endpoints without a valid JWT. No broken access control was found on unauthenticated requests.

---

## 3. Security Header Analysis

### 3.1 Response Headers (HTTPS)

```
Content-Security-Policy: default-src 'self'; connect-src 'self' https://192.168.56.137; 
                         script-src 'self'; style-src 'self'; img-src 'none'; 
                         form-action 'self'; frame-ancestors 'none'; base-uri 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Strict-Transport-Security: max-age=3153600; includeSubDomains
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
X-Permitted-Cross-Domain-Policies: none
Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate
Pragma: no-cache
```

### 3.2 Header Evaluation

| Header | Rating | Notes |
|---|---|---|
| **CSP** | ⚠️ Medium | `script-src 'self'` allows script execution from same origin. **README claims `script-src 'none'`** but deployed app uses `'self'` (React SPA requires it). |
| **HSTS** | ✅ Good | 1-year max-age with includeSubDomains |
| **X-Frame-Options** | ✅ Good | DENY prevents clickjacking |
| **X-Content-Type-Options** | ✅ Good | nosniff prevents MIME sniffing |
| **Referrer-Policy** | ✅ Good | strict-origin-when-cross-origin |
| **CORP/COOP/COEP** | ✅ Good | Full cross-origin isolation |
| **Cache-Control** | ✅ Good | Aggressive no-cache prevents caching |
| **img-src** | ⚠️ Unusual | `img-src 'none'` — no images allowed at all |

> **MITRE**: [T1190] Exploit Public-Facing Application

---

## 4. Authentication Testing

### 4.1 Login Endpoint Analysis

**Endpoint:** `POST /backend/api/auth/login`  
**Content-Type:** `application/json`  
**Body Schema:** `{"username": string, "password": string}`

**Validation Rules (leaked via error responses):**
- `Username`: Required, 3-50 characters
- `Password`: Required, minimum 8 characters

**Response Schema (success):**
```json
{
  "success": true,
  "data": {
    "token": "<JWT>",
    "userId": <int>,
    "username": "<string>",
    "role": "<Admin|Client>",
    "fullName": "<string>",
    "email": "<string>"
  }
}
```

### 4.2 Credential Spraying Results

| Username | Passwords Attempted | Result |
|---|---|---|
| admin | Admin123, Admin123!, Password1!, Admin1234, P@ssw0rd!, awita12A, etc. | ❌ AUTH_FAILED |
| user | Password1, Password1!, Admin123! | ❌ AUTH_FAILED / RATE_LIMITED |
| administrator | Multiple | ❌ RATE_LIMITED |
| root, sa, cliente, Cliente | Multiple | ❌ RATE_LIMITED |

### 4.3 Rate Limiting

| Property | Value |
|---|---|
| **Trigger** | ~5 failed attempts |
| **Scope** | IP-based (global, not per-user) |
| **Duration** | Several minutes |
| **Error Code** | `RATE_LIMIT_EXCEEDED` |
| **Message** | "Demasiados intentos de inicio de sesión. Intente nuevamente en unos minutos." |

> [!WARNING]
> **Finding:** Rate limiting is **IP-based, not per-account**. This means a single attacker IP's failed attempts to `admin` also blocks attempts to `user` and vice versa. However, this also means an attacker with multiple IPs could conduct parallel sprays.

> **MITRE**: [T1110.003] Brute Force: Password Spraying

### 4.4 SQL Injection Testing

| Payload | Target | Result |
|---|---|---|
| `admin'--` | username | AUTH_FAILED (input sanitized) |
| `admin" OR 1=1--` | username | Validation error (8 char min on password) |
| `admin'; WAITFOR DELAY '0:0:5';--` | username | No timing difference (~0.02s) |

> **Conclusion:** No SQL injection vulnerability detected on the login endpoint. The application likely uses parameterized queries (EF Core LINQ).  
> **MITRE**: [T1190] Exploit Public-Facing Application

---

## 5. JWT Analysis

### 5.1 Token Structure (from JS bundle)

The frontend stores the JWT in `localStorage` and sends it as `Authorization: Bearer <token>`. The token payload contains:
- `sub` (subject)
- `exp` (expiration — validated client-side via epoch comparison)
- User identity (userId, username, role, fullName, email)

### 5.2 JWT Forgery Attempts

| Attack | Secrets Tested | Result |
|---|---|---|
| **Common secrets** | secret, key, password, changeme, SecureCatalog, CSAI, SecureApp, WebApp, admin, etc. | ❌ All returned 401 |
| **`alg: none`** | Empty signature | ❌ 401 — Server validates algorithm |

> **Conclusion:** JWT signing key is not a common weak secret. The `alg: none` attack is properly mitigated. The JWT implementation appears secure.  
> **MITRE**: [T1550.001] Use Alternate Authentication Material: Application Access Token

---

## 6. TLS/SSL Analysis

### 6.1 Certificate Details

| Property | Value |
|---|---|
| **Subject** | CN=CSAI |
| **SAN** | DNS:CSAI |
| **Issuer** | CN=CSAI (self-signed) |
| **Valid** | 2026-02-21 to 2027-02-21 |
| **Key** | RSA 2048-bit |
| **Signature** | sha256WithRSAEncryption |

### 6.2 Protocol/Cipher Support

| Protocol | Status | Ciphers |
|---|---|---|
| **TLSv1.0** | ⚠️ Enabled | AES-CBC with RSA/ECDHE |
| **TLSv1.1** | ⚠️ Enabled | AES-CBC with RSA/ECDHE |
| **TLSv1.2** | ✅ Enabled | AES-GCM + AES-CBC |
| **TLSv1.3** | ✅ Enabled | AES-256-GCM, AES-128-GCM |

> [!WARNING]
> **Finding [MEDIUM]:** TLSv1.0 and TLSv1.1 are **still enabled**. These are deprecated protocols with known vulnerabilities (BEAST, POODLE). They should be disabled.  
> **MITRE**: [T1557] Adversary-in-the-Middle

### 6.3 Certificate Issues

> [!WARNING]
> **Finding [LOW]:** Self-signed certificate — not issued by a trusted CA. SAN only includes `CSAI`, not the IP address `192.168.56.137`, causing hostname mismatch warnings.

---

## 7. Hypervisor Configuration Analysis (.vbox)

### 7.1 VM Specifications

| Property | Value |
|---|---|
| **VM Name** | CSAI |
| **UUID** | 5e7b3421-7c1d-4a44-9ba7-379590520f15 |
| **OS Type** | Windows2022_64 |
| **OS Detected** | Windows 2025 (10.0.26100.32370) |
| **RAM** | 4096 MB |
| **CPUs** | 3 |
| **Firmware** | EFI |
| **VirtualBox** | 7.2.4 (r170995) |
| **Guest Additions** | 7.2.6 (r172322) |
| **Disk** | CSAI-disk001.vdi (VDI format, Normal) |

### 7.2 Security-Relevant Configuration

| Setting | Value | Risk |
|---|---|---|
| **TPM** | v2.0 (enabled) | BitLocker likely active |
| **Clipboard** | ⚠️ **Bidirectional** | Data exfiltration vector |
| **Drag & Drop** | ⚠️ **Bidirectional** | File transfer vector |
| **Guest Additions** | ✅ Installed (7.2.6) | Required for clipboard/DnD |
| **Shared Folders** | ✅ None configured | No direct file sharing |
| **USB** | XHCI controller present | USB device passthrough possible |
| **Network Adapter 0** | Host-Only | Primary network (192.168.56.x) |
| **Network Adapter 1** | ⚠️ **NAT (localhost-reachable)** | Can reach host services |

> [!CAUTION]
> ### Critical Findings:
> 
> 1. **Bidirectional Clipboard (T1115):** An attacker with GUI access could exfiltrate data via clipboard.  
> 2. **Bidirectional Drag & Drop:** Allows file transfer between host and guest without network.  
> 3. **NAT Adapter with localhost-reachable:** The VM's second NIC can reach the **host's localhost services**. If the host runs any services on 127.0.0.1, the VM can potentially access them.  
> 4. **EFI + vTPM 2.0:** BitLocker keys may be stored in the `.nvram` file. Offline analysis of this file could potentially extract the Volume Master Key.

> **MITRE**: [T1115] Clipboard Data, [T1052] Exfiltration Over Physical Medium, [T1497.001] Virtualization/Sandbox Evasion

---

## 8. Information Disclosure

### 8.1 Frontend JS Bundle

The minified JavaScript bundle at `/assets/index-CYy1omQq.js` reveals:
- ✅ Complete API endpoint map
- ✅ Authentication flow and JWT handling logic
- ✅ User role system (`Admin`, `Client`)
- ✅ All CRUD operations and their parameters
- ✅ Backend API base URL
- ✅ Client-side authorization logic (easily bypassable)

> **MITRE**: [T1592.004] Gather Victim Information: Client Configurations

### 8.2 Error Response Information Leakage

- **Validation errors** expose field names, types, and constraints
- **Rate limit errors** confirm the rate limiting mechanism
- **TraceIds** are included in error responses (e.g., `00-dd55a617...`)
- **Backend framework** identifiable as ASP.NET Core via error format

### 8.3 IIS Information

- HTTP to HTTPS redirect includes IIS-style HTML (`Documento movido`)
- `Server: Microsoft-HTTPAPI/2.0` exposed on specific error pages (411 Length Required)
- TRACE method returns 404 (not reflected — **XST mitigated**)

---

## 9. Attack Vectors Summary

### 9.1 Viable Next Steps (Priority Order)

| # | Vector | Description | Difficulty |
|---|---|---|---|
| 1 | **Offline VDI/NVRAM Analysis** | Mount the `.vdi` disk image offline from the host. Extract SAM/SYSTEM hives for password hashes, or analyze `.nvram` for BitLocker VMK. | Medium |
| 2 | **Slow Credential Spray** | Rate limit allows ~5 attempts before lockout. With patience (wait between attempts), a targeted spray against likely usernames could succeed. | Medium |
| 3 | **RAM/VRAM Analysis** | If a snapshot or saved state exists, analyze memory dumps for credentials, JWT signing keys, or connection strings. | Medium |
| 4 | **JWT Secret Bruteforce** | Use `hashcat` or `jwt-cracker` with larger wordlists against a captured JWT token to find the signing key. | Hard |
| 5 | **Application Logic Bugs** | Once authenticated, test for IDOR (integer IDs), privilege escalation (role field in createUser), and mass assignment. | Requires Auth |
| 6 | **VirtualBox Guest-to-Host** | Exploit the NAT adapter with `localhost-reachable` to scan host services from inside the VM. | Requires VM Access |

### 9.2 Blocked Vectors

| Vector | Reason |
|---|---|
| SQL Injection | Parameterized queries (EF Core) |
| XSS | CSP `script-src 'self'`, React auto-escaping |
| Clickjacking | `X-Frame-Options: DENY` + `frame-ancestors 'none'` |
| CSRF | JWT Bearer auth (no cookies to forge) |
| Directory Traversal | SPA serves same HTML for all routes |
| Remote Services (RDP/WinRM/SMB) | All ports filtered by firewall |
| TRACE/XST | Returns 404, not reflected |
| JWT `alg:none` | Server validates algorithm |

---

## 10. MITRE ATT&CK Mapping

| Technique ID | Name | Phase | Status |
|---|---|---|---|
| T1046 | Network Service Discovery | Reconnaissance | ✅ Complete |
| T1595.002 | Active Scanning: Vulnerability Scanning | Reconnaissance | ✅ Complete |
| T1190 | Exploit Public-Facing Application | Initial Access | ⏳ In Progress |
| T1110.003 | Brute Force: Password Spraying | Credential Access | ⏳ Rate Limited |
| T1550.001 | Application Access Token (JWT) | Credential Access | ❌ Failed |
| T1557 | Adversary-in-the-Middle (TLS) | Collection | ⚠️ TLSv1.0/1.1 enabled |
| T1115 | Clipboard Data | Collection | ⚠️ Bidirectional configured |
| T1592.004 | Client Configurations | Reconnaissance | ✅ JS bundle analyzed |

---

## 11. Recommendations for Blue Team

1. **Disable TLSv1.0 and TLSv1.1** on IIS — only allow TLSv1.2+
2. **Disable Bidirectional Clipboard and Drag & Drop** in VirtualBox settings
3. **Remove the second NAT adapter** or disable `localhost-reachable`
4. **Remove TraceId from error responses** in production
5. **Implement per-account rate limiting** in addition to IP-based
6. **Obfuscate or split the JS bundle** to reduce API surface exposure
7. **Use GUID-based user IDs** instead of sequential integers to prevent enumeration
8. **Replace self-signed certificate** with a properly issued one matching the server IP/hostname
