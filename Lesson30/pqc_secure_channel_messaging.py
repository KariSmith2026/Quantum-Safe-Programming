import oqs
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def derive_hybrid_key(classical_shared, pq_shared):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-secure-channel",
    )
    return hkdf.derive(classical_shared + pq_shared)

def encrypt_message(hybrid_key, plaintext):
    aesgcm = AESGCM(hybrid_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext

def decrypt_message(hybrid_key, nonce, ciphertext):
    aesgcm = AESGCM(hybrid_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()

def secure_channel_demo():
    print("Starting secure channel messaging demo...")

    # Classical ECDH
    private_key = ec.generate_private_key(ec.SECP256R1())
    peer_private_key = ec.generate_private_key(ec.SECP256R1())
    classical_shared = private_key.exchange(ec.ECDH(), peer_private_key.public_key())

    print("ECDH shared secret established.")

    # PQC ML-KEM
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pq_public_key = kem.generate_keypair()
    ciphertext, pq_shared_client = kem.encap_secret(pq_public_key)
    pq_shared_server = kem.decap_secret(ciphertext)

    print("ML-KEM shared secret established.")

    # Hybrid key
    hybrid_key = derive_hybrid_key(classical_shared, pq_shared_client)

    print("Hybrid key derived.")
    print("Hybrid key length:", len(hybrid_key))
    print("Hybrid key (hex):", hybrid_key.hex())

    # Secure messaging
    message = "Quantum-safe messaging channel operational."
    print("\nEncrypting message:", message)

    nonce, encrypted = encrypt_message(hybrid_key, message)
    print("Ciphertext (hex):", encrypted.hex())

    decrypted = decrypt_message(hybrid_key, nonce, encrypted)
    print("Decrypted message:", decrypted)

    print("\nSecure channel messaging validated.")
    print("Environment stable.")

if __name__ == "__main__":
    secure_channel_demo()
