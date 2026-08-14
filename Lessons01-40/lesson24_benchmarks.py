import oqs
import time
import os

# -----------------------------
# Benchmark ML-KEM
# -----------------------------
kem = oqs.KeyEncapsulation("ML-KEM-768")

start_kem_keygen = time.time()
public_key = kem.generate_keypair()
end_kem_keygen = time.time()

start_kem_encap = time.time()
ciphertext, client_shared = kem.encap_secret(public_key)
end_kem_encap = time.time()

start_kem_decap = time.time()
server_shared = kem.decap_secret(ciphertext)
end_kem_decap = time.time()

# -----------------------------
# Benchmark ML-DSA
# -----------------------------
sig = oqs.Signature("ML-DSA-65")

start_sig_keygen = time.time()
sig_public = sig.generate_keypair()
end_sig_keygen = time.time()

message = b"PQC benchmark test message."

start_sig_sign = time.time()
signature = sig.sign(message)
end_sig_sign = time.time()

start_sig_verify = time.time()
valid = sig.verify(message, signature, sig_public)
end_sig_verify = time.time()

# -----------------------------
# Output
# -----------------------------
print("=== ML-KEM Benchmarks ===")
print("Keygen time:", end_kem_keygen - start_kem_keygen)
print("Encapsulation time:", end_kem_encap - start_kem_encap)
print("Decapsulation time:", end_kem_decap - start_kem_decap)
print("Ciphertext size:", len(ciphertext))
print("Shared secret size:", len(client_shared))

print("\n=== ML-DSA Benchmarks ===")
print("Keygen time:", end_sig_keygen - start_sig_keygen)
print("Sign time:", end_sig_sign - start_sig_sign)
print("Verify time:", end_sig_verify - start_sig_verify)
print("Signature size:", len(signature))
print("Signature valid:", valid)

# -----------------------------
# Failure Mode Simulation
# -----------------------------
tampered = b"PQC benchmark tampered message."

fail_valid = sig.verify(tampered, signature, sig_public)

print("\n=== Failure Mode ===")
print("Tampered signature valid:", fail_valid)
