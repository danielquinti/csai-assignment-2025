import jwt
import time

# Extracted from memory dump (Step 4.2 of audit report)
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
