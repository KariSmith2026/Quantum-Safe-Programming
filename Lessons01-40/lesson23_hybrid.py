import oqs
import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# -----------------------------
# Classical ECDH
# -----------------------------
start_ecdh = time.time()

# Generate ECDH keypair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Derive classical shared secret
peer_private = ec.generate_private_key(ec.SECP256R1())
peer_public = peer_private.public_key()

classical_shared = private_key.exchange(ec.ECDH(), peer_public)

end_ecdh = time.time()

# -----------------------------
# Post-Quantum ML-KEM
# -----------------------------
start_pqc = time.time()

kem = oqs.KeyEncapsulation("ML-KEM-768")
pqc_public = kem.generate_keypair()
ciphertext, pqc_client_shared = kem.encap_secret(pqc_public)
pqc_server_shared = kem.decap_secret(ciphertext)

end_pqc = time.time()

# -----------------------------
# Hybrid Key Derivation
# -----------------------------
combined = classical_shared + pqc_client_shared

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"hybrid-ecdh-mlkem",
)

hybrid_key = hkdf.derive(combined)

print("Classical ECDH time:", end_ecdh - start_ecdh)
print("ML-KEM time:", end_pqc - start_pqc)
print("Hybrid key length:", len(hybrid_key))
print("Hybrid key (hex):", hybrid_key.hex())
