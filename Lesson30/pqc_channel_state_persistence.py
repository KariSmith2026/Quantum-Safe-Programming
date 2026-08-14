import oqs
import os
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

STATE_FILE = "channel_state.json"

def derive_hybrid_key(classical_shared, pq_shared):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid-state-persistence",
    )
    return hkdf.derive(classical_shared + pq_shared)

def save_state(hybrid_key, sequence_number):
    state = {
        "hybrid_key": hybrid_key.hex(),
        "sequence_number": sequence_number
    }
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)
    print("Channel state saved.")

def load_state():
    if not os.path.exists(STATE_FILE):
        return None

    with open(STATE_FILE, "r") as f:
        state = json.load(f)

    hybrid_key = bytes.fromhex(state["hybrid_key"])
    sequence_number = state["sequence_number"]

    print("Channel state restored.")
    return hybrid_key, sequence_number

def encrypt_message(hybrid_key, plaintext, sequence_number):
    aesgcm = AESGCM(hybrid_key)
    nonce = os.urandom(12)
    aad = sequence_number.to_bytes(8, "big")
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), aad)
    return nonce, ciphertext, aad

def decrypt_message(hybrid_key, nonce, ciphertext, aad):
    aesgcm = AESGCM(hybrid_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext.decode()

def channel_state_demo():
    print("Starting hybrid channel state persistence demo...")

    # Try restoring state
    restored = load_state()

    if restored:
        hybrid_key, sequence_number = restored
        print("Using restored hybrid key and sequence number.")
    else:
        print("No saved state found. Establishing new hybrid channel...")

        # Classical ECDH
        private_key = ec.generate_private_key(ec.SECP256R1())
        peer_private_key = ec.generate_private_key(ec.SECP256R1())
        classical_shared = private_key.exchange(ec.ECDH(), peer_private_key.public_key())

        # PQC ML-KEM
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        pq_public_key = kem.generate_keypair()
        ciphertext, pq_shared_client = kem.encap_secret(pq_public_key)
        pq_shared_server = kem.decap_secret(ciphertext)

        hybrid_key = derive_hybrid_key(classical_shared, pq_shared_client)
        sequence_number = 1

        print("New hybrid key established.")

    # Encrypt a message using current state
    message = "Hybrid channel persistence operational."
    print("\nEncrypting message:", message)

    nonce, encrypted, aad = encrypt_message(hybrid_key, message, sequence_number)
    print("Ciphertext (hex):", encrypted.hex())

    decrypted = decrypt_message(hybrid_key, nonce, encrypted, aad)
    print("Decrypted:", decrypted)

    # Increment sequence number and save state
    sequence_number += 1
    save_state(hybrid_key, sequence_number)

    print("\nChannel state persistence validated.")
    print("Environment stable.")

if __name__ == "__main__":
    channel_state_demo()
