import oqs

UPDATE_FILE = "firmware_update_v1.0.3.txt"
SIGNATURE_FILE = "firmware_update_v1.0.3.sig"

# Load update content
with open(UPDATE_FILE, "rb") as f:
    data = f.read()

# ML-DSA signer
signer = oqs.Signature("ML-DSA-65")
public_key = signer.generate_keypair()

# Sign update
signature = signer.sign(data)

# Save signature
with open(SIGNATURE_FILE, "wb") as f:
    f.write(signature)

# Verify original
valid = signer.verify(data, signature, public_key)
print("Original update valid:", valid)

# Tamper with update
tampered = data.replace(b"1.0.3", b"1.0.9")

valid_tampered = signer.verify(tampered, signature, public_key)
print("Tampered update valid:", valid_tampered)
