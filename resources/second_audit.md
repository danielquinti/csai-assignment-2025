# 🔴 Red Team Audit Report — Target 192.168.56.137

**Date:** 2026-04-02  
**Target:** Windows Server 2025 (VirtualBox VM) — `192.168.56.137`  
**Attacker:** Kali Linux (VirtualBox) — Host-Only Network `192.168.56.0/24`  
**Methodology:** PTES / MITRE ATT&CK  

---

## Executive Summary

The target is a hardened Windows Server 2025 running a React SPA + ASP.NET Core backend on IIS. Despite strong perimeter defenses (firewall, rate limiting, no obvious web vulnerabilities), the system was **fully compromised at the application level via physical/hypervisor exploitation**. By analyzing the running VM's memory space, we extracted the application's configuration, forged an administrative JWT, and **exfiltrated the user database**, achieving the primary objective.

**Victory Conditions Status:**
| Objective | Status |
|---|---|
| **Exfiltrate Database** | ✅ **Achieved** — Complete API takeover and user DB extraction via forged JWT. |
| **NT AUTHORITY\SYSTEM Shell** | ❌ Not achieved — No RCE vector identified via network yet. |

---

## 1. Network Reconnaissance

- **Ports Open:** 80 (HTTP), 443 (HTTPS)
- **Filtered:** All other ports including 3389 (RDP), 445 (SMB), 5985/5986 (WinRM).
- **Firewall:** Extremely restrictive. (MITRE T1046)

---

## 2. Web Application Assessment

- **Architecture:** React SPA (Vite) + ASP.NET Core API behind IIS.
- **Authentication:** JWT Bearer tokens. Aggressive IP-based rate limiting blocks brute-force/password spraying. (MITRE T1110.003)
- **Auth Configuration:** APIs (`/backend/api/users`) return `401 Unauthorized` without a valid token. No IDOR feasible without an initial valid token.
- **Security Headers:** Strict CSP (`script-src 'self'`), HSTS, X-Frame-Options DENY, CORP/COEP/COOP enabled.
- **SQL Injection:** Tested login endpoint; application is resistant (likely parameterized queries).

---

## 3. Exploit Chain: JWT Forging via Memory Analysis

### 3.1 Memory Acquisition (MITRE T1003.001 - OS Credential Dumping)
Due to access to the hypervisor (VirtualBox on the host), we executed a live memory dump of the target VM using `VBoxManage debugvm "CSAI" dumpvmcore`. This yielded a 4.2GB `.elf` memory dump.

### 3.2 Secret Extraction (MITRE T1552 - Credentials In Files/Memory)
By parsing the memory dump (focusing on UTF-16LE and ASCII string extraction), we located the `appsettings.json` configuration block loaded in the ASP.NET Core memory space.

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

### 3.3 Token Forging (MITRE T1550.001 - Application Access Token)
Using the extracted `SecretKey` (`CWgLnSB5JKpgba6BWyzwV8Uf+qDpErvjMPfpv9vIifg=`), we utilized a Python script to forge a valid JWT with `Admin` privileges, signed with `HS256`.

**Payload Used:**
```json
{
  "sub": "1",
  "name": "admin",
  "role": "Admin",
  "iss": "SecureWebApp",
  "aud": "SecureWebAppClient"
}
```

### 3.4 Exfiltration and Privilege Escalation (MITRE T1020 - Automated Exfiltration)
By injecting the forged Bearer token into HTTP requests, we successfully bypassed all authentication controls. We accessed the `/backend/api/users` endpoint and exfiltrated the entire user database.

**Exfiltrated Database (Sample):**
| ID | Username | Email | Role |
|---|---|---|---|
| 1 | ice_tea | icecube@securewebapp.local | Admin |
| 2 | eminem | eminem@udc.es | Client |
| 3 | claudia.fernandez | claudia.fernandez@example.com | Client |
| 4 | diego.ramirez | diego.ramirez@example.com | Client |
| 5 | valentina.gomez | valentina.gomez@example.com | Client |
| 6 | camila.morales | camila.morales@example.com | Client |
| 7 | fernando.silva | fernando.silva@example.com | Client |

We now have the capability to create new Administrator accounts, modify existing users, or exploit application logic bugs requiring authentication.

---

## 4. Hypervisor Configuration Analysis (.vbox)

Several insecure configurations were identified in the VirtualBox setup that facilitated this attack or provide further vectors:
- **Bidirectional Clipboard & Drag-and-Drop:** Allows data exfiltration to the host. (MITRE T1115, T1052)
- **NAT Adapter (`localhost-reachable`):** The VM's second NIC can reach the host's localhost services, providing a VM-escape vector. (MITRE T1497.001)
- **vTPM 2.0 & EFI:** BitLocker is likely enabled. The `.nvram` file could be targeted for offline key extraction to mount the `.vdi` disk outright.

---

## 5. Summary of Findings & Mitigations

### 🔴 Critical Vulnerabilities
1. **Physical/Hypervisor Access leads to Secret Extraction**
   - *Impact:* Total application compromise.
   - *Mitigation:* Ensure physical and hypervisor-level security. Protect the host machine from unauthorized access. Use memory encryption if the hypervisor supports it.

### 🟡 Medium Vulnerabilities
1. **TLSv1.0 and TLSv1.1 Enabled**
   - *Impact:* Vulnerable to legacy cryptographic attacks (e.g., POODLE, BEAST).
   - *Mitigation:* Disable TLSv1.0/1.1 in IIS Crypto; enforce TLSv1.2+.
2. **Insecure VirtualBox Features (Clipboard, NAT localhost)**
   - *Impact:* Facilitates data exfiltration and VM escape.
   - *Mitigation:* Set Clipboard/Drag-and-Drop to 'Disabled'. Remove the secondary NAT adapter or disable `localhost-reachable`.

### 🟢 Low / Informational
1. **Predictable User IDs (Sequential Integers)**
   - *Impact:* Facilitates enumeration of users if an IDOR vulnerability is ever introduced.
   - *Mitigation:* Change primary keys for User mapping to UUIDs/GUIDs.
2. **Self-Signed Certificate**
   - *Impact:* Cannot verify server identity; browser warnings.
   - *Mitigation:* Use a trusted Certificate Authority (e.g., Let's Encrypt or internal enterprise CA).

---

**Audit Conclusion:** The web application itself is reasonably well-hardened against unauthenticated external network attacks. The success of this engagement relied entirely on exploiting the hypervisor's debug capabilities to extract secrets from memory, underscoring the principle that **"if an attacker has physical or hypervisor access to your server, it's no longer your server."**
