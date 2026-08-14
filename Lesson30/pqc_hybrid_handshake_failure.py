import oqs
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def simulate_failure():
    print("Starting hybrid handshake failure injection...")

    # Classical ECDH
    private_key = ec.generate_private_key(ec.SECP256R1())
    peer_private_key = ec.generate_private_key(ec.SECP256R1())

    classical_shared = private_key.exchange(ec.ECDH(), peer_private_key.public_key())
    print("ECDH baseline exchange successful.")

    # PQC ML-KEM
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pq_public_key = kem.generate_keypair()

    ciphertext, pq_shared_client = kem.encap_secret(pq_public_key)

    print("Injecting failure: corrupting ciphertext...")
    corrupted_ciphertext = bytearray(ciphertext)
    corrupted_ciphertext[0] ^= 0xFF  # flip first byte

    try:
        pq_shared_server = kem.decap_secret(bytes(corrupted_ciphertext))
        print("❌ Unexpected success: decapsulation should have failed.")
    except Exception as e:
        print("✅ Expected failure detected during decapsulation.")
        print("Error type:", type(e).__name__)
        print("Error message:", str(e))

    # Hybrid key derivation attempt (should not proceed normally)
    combined_secret = classical_shared + pq_shared_client

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-ecdh-mlkem-failure-test",
    )

    hybrid_key = hkdf.derive(combined_secret)

    print("Hybrid key derived from partial secrets (for testing only).")
    print("Hybrid key length:", len(hybrid_key))
    print("Hybrid key (hex):", hybrid_key.hex())
    print("Failure injection complete.")
    print("Environment stable.")

if __name__ == "__main__":
    simulate_failure()
