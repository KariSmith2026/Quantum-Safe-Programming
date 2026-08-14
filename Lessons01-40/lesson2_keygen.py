import oqs

# Quantum-Safe Key Generation Example
# Author: Kari Smith
# Date: July 27, 2026

kem = oqs.KEM("Kyber512")

public_key = kem.generate_keypair()
private_key = kem.export_secret_key()

print("Quantum-Safe Keypair Generated Successfully")
print("Public Key Length:", len(public_key))
print("Private Key Length:", len(private_key))

