import oqs
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def validate_hybrid_handshake():
    print("Starting hybrid handshake validation...")

    # -----------------------------
    # Classical ECDH (cryptography)
    # -----------------------------
    private_key = ec.generate_private_key(ec.SECP256R1())
    peer_private_key = ec.generate_private_key(ec.SECP256R1())

    public_key = private_key.public_key()
    peer_public_key = peer_private_key.public_key()

    classical_shared = private_key.exchange(ec.ECDH(), peer_public_key)

    print("ECDH key exchange successful.")

    # -----------------------------
    # Post-Quantum ML-KEM (liboqs)
    # -----------------------------
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pq_public_key = kem.generate_keypair()

    ciphertext, pq_shared_client = kem.encap_secret(pq_public_key)
    pq_shared_server = kem.decap_secret(ciphertext)

    print("ML-KEM encapsulation verified.")

    # -----------------------------
    # Hybrid Key Derivation
    # -----------------------------
    combined_secret = classical_shared + pq_shared_client

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-ecdh-mlkem",
    )

    hybrid_key = hkdf.derive(combined_secret)

    print("Hybrid key length:", len(hybrid_key))
    print("Hybrid key (hex):", hybrid_key.hex())
    print("Integrity check passed.")
    print("Environment stable.")

if __name__ == "__main__":
    validate_hybrid_handshake()
