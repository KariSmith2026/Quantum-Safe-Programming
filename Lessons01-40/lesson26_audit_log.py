import oqs
import hashlib
import json
import time

UPDATE_FILE = "firmware_update_v1.0.3.txt"
SIGNATURE_FILE = "firmware_update_v1.0.3.sig"
AUDIT_LOG = "pqc_audit_log.json"

# Load update content
with open(UPDATE_FILE, "rb") as f:
    data = f.read()

# Hash the update file
file_hash = hashlib.sha256(data).hexdigest()

# ML-DSA signer
signer = oqs.Signature("ML-DSA-65")

log = {
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    "update_file": UPDATE_FILE,
    "file_hash_sha256": file_hash,
    "events": []
}

# Key generation
public_key = signer.generate_keypair()
log["events"].append({
    "event": "key_generation",
    "algorithm": "ML-DSA-65",
    "status": "success"
})

# Signing
signature = signer.sign(data)
with open(SIGNATURE_FILE, "wb") as f:
    f.write(signature)

log["events"].append({
    "event": "signing",
    "signature_file": SIGNATURE_FILE,
    "signature_size": len(signature),
    "status": "success"
})

# Verification
valid = signer.verify(data, signature, public_key)
log["events"].append({
    "event": "verification",
    "valid": valid,
    "status": "success" if valid else "failure"
})

# Tampering test
tampered = data.replace(b"1.0.3", b"1.0.9")
valid_tampered = signer.verify(tampered, signature, public_key)

log["events"].append({
    "event": "tampering_detection",
    "tampered_valid": valid_tampered,
    "status": "failure" if not valid_tampered else "unexpected_success"
})

# Save audit log
with open(AUDIT_LOG, "w") as f:
    json.dump(log, f, indent=4)

print("Audit log written to:", AUDIT_LOG)
print("Verification valid:", valid)
print("Tampered valid:", valid_tampered)
