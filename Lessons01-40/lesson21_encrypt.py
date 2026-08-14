import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# ML-KEM handshake
server = oqs.KeyEncapsulation("ML-KEM-768")
public_key = server.generate_keypair()
ciphertext, client_shared = server.encap_secret(public_key)
server_shared = server.decap_secret(ciphertext)

assert client_shared == server_shared

# Use shared secret as AES key (truncate to 32 bytes for AES-256)
key = client_shared[:32]
aesgcm = AESGCM(key)

# Encrypt
nonce = os.urandom(12)
message = b"Quantum-safe encryption test message."
ciphertext = aesgcm.encrypt(nonce, message, None)

# Decrypt
plaintext = aesgcm.decrypt(nonce, ciphertext, None)

print("Original message:", message)
print("Decrypted message:", plaintext)
print("Match:", message == plaintext)
