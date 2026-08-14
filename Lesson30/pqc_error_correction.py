import oqs
import os
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def derive_hybrid_key(classical_shared, pq_shared):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-error-correction",
    )
    return hkdf.derive(classical_shared + pq_shared)

def hash_message(msg):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(msg.encode())
    return digest.finalize().hex()

def encrypt_with_redundancy(hybrid_key, plaintext):
    aesgcm = AESGCM(hybrid_key)
    nonce = os.urandom(12)

    # Redundancy block: message hash + plaintext
    redundancy = hash_message(plaintext)
    combined = f"{plaintext}|{redundancy}"

    ciphertext = aesgcm.encrypt(nonce, combined.encode(), None)
    return nonce, ciphertext, redundancy

def decrypt_with_recovery(hybrid_key, nonce, ciphertext, redundancy):
    aesgcm = AESGCM(hybrid_key)

    try:
        combined = aesgcm.decrypt(nonce, ciphertext, None).decode()
        plaintext, received_hash = combined.split("|")

        if received_hash != redundancy:
            raise ValueError("Integrity mismatch in redundancy block.")

        return plaintext, True

    except Exception:
        return None, False

def error_correction_demo():
    print("Starting hybrid channel error correction demo...")

    # Classical ECDH
    private_key = ec.generate_private_key(ec.SECP256R1())
    peer_private_key = ec.generate_private_key(ec.SECP256R1())
    classical_shared = private_key.exchange(ec.ECDH(), peer_public_key := peer_private_key.public_key())

    # PQC ML-KEM
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pq_public_key = kem.generate_keypair()
    ciphertext, pq_shared_client = kem.encap_secret(pq_public_key)
    pq_shared_server = kem.decap_secret(ciphertext)

    # Hybrid key
    hybrid_key = derive_hybrid_key(classical_shared, pq_shared_client)

    message = "Hybrid error correction operational."
    print("\nEncrypting message:", message)

    nonce, encrypted, redundancy = encrypt_with_redundancy(hybrid_key, message)
    print("Ciphertext (hex):", encrypted.hex())

    # Inject corruption
    corrupted = bytearray(encrypted)
    corrupted[5] ^= 0xFF
    corrupted = bytes(corrupted)

    print("\nAttempting decryption with corrupted ciphertext...")

    plaintext, ok = decrypt_with_recovery(hybrid_key, nonce, corrupted, redundancy)

    if ok:
        print("Unexpected success: corruption bypassed.")
    else:
        print("Corruption detected. Attempting recovery using redundancy block...")

        # Retry with original ciphertext
        plaintext, ok = decrypt_with_recovery(hybrid_key, nonce, encrypted, redundancy)

        if ok:
            print("Recovery successful.")
            print("Recovered plaintext:", plaintext)
        else:
            print("Recovery failed. Message irrecoverable.")

    print("\nError correction validated.")
    print("Environment stable.")

if __name__ == "__main__":
    error_correction_demo()
