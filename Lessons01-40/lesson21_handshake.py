import oqs

# Server side
server = oqs.KeyEncapsulation("ML-KEM-768")
public_key = server.generate_keypair()

# Client side
ciphertext, client_shared = server.encap_secret(public_key)

# Server decapsulates
server_shared = server.decap_secret(ciphertext)

print("Client shared secret:", client_shared.hex())
print("Server shared secret:", server_shared.hex())
print("Match:", client_shared == server_shared)
