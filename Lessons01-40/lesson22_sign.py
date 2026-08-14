import oqs

# Create ML-DSA signer (Dilithium)
signer = oqs.Signature("ML-DSA-65")

# Generate keypair
public_key = signer.generate_keypair()

# Message to sign
message = b"Quantum-safe file signing test."

# Sign the message
signature = signer.sign(message)

# Verify the signature
valid = signer.verify(message, signature, public_key)

print("Message:", message)
print("Signature valid:", valid)

# Tampering test
tampered = b"Quantum-safe file signing FAIL."
valid_tampered = signer.verify(tampered, signature, public_key)

print("Tampered message valid:", valid_tampered)
