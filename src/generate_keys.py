import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()


private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


KEYS_DIR.mkdir(parents=True, exist_ok=True)

(KEYS_DIR / "ground_private.pem").write_bytes(private_bytes)
(KEYS_DIR / "ground_public.pem").write_bytes(public_bytes)

# Part 4: symmetric key shared by the ground server and the UAV
(KEYS_DIR / "firmware.key").write_text(ChaCha20Poly1305.generate_key().hex())

# Part 5: password shared by the ground server and the UAV
(KEYS_DIR / "firmware_password.txt").write_text(secrets.token_urlsafe(16))


print("Generated ground key pair, firmware key, and firmware password.")