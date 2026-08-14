import oqs
import os
import json
import time
from cryptography.hazmat.primitives import hashes

AUDIT_FILE = "audit_log.json"
STATE_FILE = "channel_state.json"

def hash_event(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    return digest.finalize().hex()

def load_audit_log():
    if not os.path.exists(AUDIT_FILE):
        return []
    with open(AUDIT_FILE, "r") as f:
        return json.load(f)

def save_audit_log(log):
    with open(AUDIT_FILE, "w") as f:
        json.dump(log, f, indent=4)

def wipe_state():
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
    print("Session state wiped.")

def secure_shutdown():
    print("Starting hybrid channel secure shutdown...")

    # Load existing audit log
    audit_log = load_audit_log()

    # ML-DSA for signing shutdown event
    dsa = oqs.Signature("ML-DSA-65")
    audit_public_key = dsa.generate_keypair()

    shutdown_event = "Hybrid channel terminated securely."
    event_hash = hash_event(shutdown_event)
    signature = dsa.sign(event_hash.encode())

    audit_entry = {
        "timestamp": time.time(),
        "event": shutdown_event,
        "event_hash": event_hash,
        "signature": signature.hex()
    }

    audit_log.append(audit_entry)
    save_audit_log(audit_log)

    print("\nFinal audit entry added:")
    print(json.dumps(audit_entry, indent=4))

    # Wipe session state
    wipe_state()

    print("\nSecure shutdown complete.")
    print("Environment stable.")

if __name__ == "__main__":
    secure_shutdown()
