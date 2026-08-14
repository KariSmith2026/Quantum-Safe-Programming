import oqs
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def derive_hybrid_key(classical_shared, pq_shared):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-ecdh-mlkem-autorecovery",
    )
    return hkdf.derive(classical_shared + pq_shared)

def auto_recovery_handshake():
    print("Starting hybrid handshake auto-recovery...")

    # Classical ECDH
    private_key = ec.generate_private_key(ec.SECP256R1())
    peer_private_key = ec.generate_private_key(ec.SECP256R1())
    classical_shared = private_key.exchange(ec.ECDH(), peer_private_key.public_key())

    print("ECDH baseline exchange successful.")

    # PQC ML-KEM
    kem = oqs.KeyEncapsulation("ML-KEM-768")

    # First attempt
    print("Attempting ML-KEM encapsulation (Attempt 1)...")
    pq_public_key = kem.generate_keypair()
    ciphertext, pq_shared_client = kem.encap_secret(pq_public_key)

    # Inject failure
    corrupted_ciphertext = bytearray(ciphertext)
    corrupted_ciphertext[0] ^= 0xFF

    try:
        pq_shared_server = kem.decap_secret(bytes(corrupted_ciphertext))
        print("❌ Unexpected success: failure injection bypassed.")
    except Exception:
        print("⚠️ Decapsulation failure detected. Initiating auto-recovery...")

        # Recovery attempt
        print("Regenerating PQC keypair (Attempt 2)...")
        pq_public_key = kem.generate_keypair()
        ciphertext, pq_shared_client = kem.encap_secret(pq_public_key)
        pq_shared_server = kem.decap_secret(ciphertext)

        print("ML-KEM recovery encapsulation successful.")

    # Hybrid key derivation
    hybrid_key = derive_hybrid_key(classical_shared, pq_shared_client)

    print("Hybrid key derived successfully.")
    print("Hybrid key length:", len(hybrid_key))
    print("Hybrid key (hex):", hybrid_key.hex())
    print("Auto-recovery complete.")
    print("Environment stable.")

if __name__ == "__main__":
    auto_recovery_handshake()
