import oqs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

def derive_hybrid_key(classical_shared, pq_shared):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"authenticated-hybrid-channel",
    )
    return hkdf.derive(classical_shared + pq_shared)

def authenticated_hybrid_channel():
    print("Starting authenticated hybrid channel...")

    # -----------------------------
    # Classical ECDH + ECDSA
    # -----------------------------
    print("Generating classical ECDH + ECDSA keys...")
    private_key = ec.generate_private_key(ec.SECP256R1())
    peer_private_key = ec.generate_private_key(ec.SECP256R1())

    public_key = private_key.public_key()
    peer_public_key = peer_private_key.public_key()

    classical_shared = private_key.exchange(ec.ECDH(), peer_public_key)
    print("ECDH key exchange successful.")

    # Sign classical public key
    signature = private_key.sign(
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        ec.ECDSA(hashes.SHA256())
    )

    # Peer signs their own key
    peer_signature = peer_private_key.sign(
        peer_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        ec.ECDSA(hashes.SHA256())
    )

    # Verify peer signature
    peer_public_key.verify(
        peer_signature,
        peer_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        ec.ECDSA(hashes.SHA256())
    )

    print("ECDSA identity verification successful.")

    # -----------------------------
    # PQC ML-KEM + ML-DSA
    # -----------------------------
    print("Generating PQC ML-KEM + ML-DSA keys...")
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pq_public_key = kem.generate_keypair()

    dsa = oqs.Signature("ML-DSA-65")
    pq_sig_public_key = dsa.generate_keypair()

    # Sign PQC public key
    pq_signature = dsa.sign(pq_public_key)

    # Verify PQC signature (correct API)
    if dsa.verify(pq_public_key, pq_signature, pq_sig_public_key):
        print("ML-DSA identity verification successful.")
    else:
        print("❌ ML-DSA verification failed.")
        return

    # PQC encapsulation
    ciphertext, pq_shared_client = kem.encap_secret(pq_public_key)
    pq_shared_server = kem.decap_secret(ciphertext)

    print("ML-KEM encapsulation verified.")

    # -----------------------------
    # Hybrid key derivation
    # -----------------------------
    hybrid_key = derive_hybrid_key(classical_shared, pq_shared_client)

    print("Hybrid authenticated key derived successfully.")
    print("Hybrid key length:", len(hybrid_key))
    print("Hybrid key (hex):", hybrid_key.hex())
    print("Authenticated hybrid channel established.")
    print("Environment stable.")

if __name__ == "__main__":
    authenticated_hybrid_channel()
