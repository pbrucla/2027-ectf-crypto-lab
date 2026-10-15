import json
import os
from pathlib import Path


def encode_message(message: dict) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode()

def decode_message(data: bytes) -> dict:
    return json.loads(data.decode())

def keys_dir() -> Path:
    # Repo-root keys/ by default. Tests point LAB_KEYS_DIR at a temp folder.
    default = Path(__file__).resolve().parents[2] / "keys"
    return Path(os.environ.get("LAB_KEYS_DIR", default))

def load_public_key():
    from cryptography.hazmat.primitives import serialization
    with open(keys_dir() / "ground_public.pem", "rb") as f:
        return serialization.load_pem_public_key(
            f.read()
        )

def load_private_key():
    from cryptography.hazmat.primitives import serialization
    with open(keys_dir() / "ground_private.pem", "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

def load_firmware_key() -> bytes:
    # Part 4: shared ChaCha20-Poly1305 key, stored as hex text.
    return bytes.fromhex((keys_dir() / "firmware.key").read_text().strip())

# Part 5: PBKDF2 work factor the ground server uses (OWASP's PBKDF2-HMAC-SHA256 recommendation)
PBKDF2_ITERATIONS = 600_000

def load_firmware_password() -> str:
    # Part 5: shared password the firmware key is derived from.
    return (keys_dir() / "firmware_password.txt").read_text().strip()
