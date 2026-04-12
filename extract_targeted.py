import re
import os

def extract_jwt_secrets(file_path):
    print(f"Scanning {file_path} for JWT Secrets...")
    # Patterns for SecretKey labels (ASCII and UTF-16LE)
    labels = [b"SecretKey", b"S\x00e\x00c\x00r\x00e\x00t\x00K\x00e\x00y"]
    b64_pattern = re.compile(rb'[a-zA-Z0-9+/]{43}=')
    
    found_candidates = []
    
    with open(file_path, "rb") as f:
        chunk_size = 1024 * 1024 * 50 # 50MB
        overlap = 1024
        pos = 0
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            
            for label in labels:
                idx = chunk.find(label)
                while idx != -1:
                    # Look in the next 300 bytes for a Base64 string
                    context = chunk[idx:idx+300]
                    matches = b64_pattern.findall(context)
                    for m in matches:
                        cand = m.decode('ascii')
                        if cand not in found_candidates:
                            found_candidates.append(cand)
                            print(f"Found candidate near label: {cand}")
                    idx = chunk.find(label, idx + 1)
            
            pos += chunk_size - overlap
            f.seek(pos)

    # If no candidate found near labels, try a broad entropy-based search or just give all candidates
    print(f"\nTotal Candidates found near 'SecretKey': {len(found_candidates)}")
    with open("candidates.txt", "w") as out:
        for c in found_candidates:
            out.write(c + "\n")

if __name__ == "__main__":
    extract_jwt_secrets(r"c:\temp\csai_mem_new.elf")
