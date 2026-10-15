import hashlib
import os

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from common.protocol import encode_message
from uav.uav import UAV

# ---------- Building messages ----------

def update_message(version=2, code="LEGITIMATE FLIGHT SOFTWARE"):
    # Key order matches the README: type, firmware (version, code).
    return {
        "type": "UPDATE",
        "firmware": {"version": version, "code": code},
    }


def with_hash(message):
    # Part 1: "signature" holds the SHA-256 hex digest of the encoded
    # message (before "signature" is added). "signature" goes last.
    digest = hashlib.sha256(encode_message(message)).hexdigest()
    return {**message, "signature": digest}


def with_signature(message, private_key):
    # Part 2: "signature" holds an Ed25519 signature over the encoded
    # message (before "signature" is added), hex-encoded.
    signature = private_key.sign(encode_message(message))
    return {**message, "signature": signature.hex()}


def encrypted_update_message(version, code, firmware_key, associated_version=None):
    # Part 4: "code" is ChaCha20-Poly1305 ciphertext, with the version as
    # associated data. associated_version lets a test bind it to a different
    # version than the one in the message.
    if associated_version is None:
        associated_version = version

    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(firmware_key).encrypt(
        nonce, code.encode(), str(associated_version).encode()
    )
    return {
        "type": "UPDATE",
        "firmware": {
            "version": version,
            "nonce": nonce.hex(),
            "code": ciphertext.hex(),
        },
    }


def password_update_message(version, code, password, iterations, salt=None):
    # Part 5: like encrypted_update_message(), but the key is derived from
    # password with PBKDF2-HMAC-SHA256, and "salt" and "iterations" are sent.
    if salt is None:
        salt = os.urandom(16)

    firmware_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    ).derive(password.encode())

    message = encrypted_update_message(version, code, firmware_key)
    nonce, ciphertext = message["firmware"]["nonce"], message["firmware"]["code"]
    message["firmware"] = {
        "version": version,
        "salt": salt.hex(),
        "iterations": iterations,
        "nonce": nonce,
        "code": ciphertext,
    }
    return message


# ---------- Delivering messages ----------

def deliver(uav, message):
    """Send a message to the UAV the same way run() does.

    Returns True if the UAV installed the message's firmware.
    Like run(), an exception while handling counts as a rejection.
    """
    try:
        uav.handle_message(message)
    except Exception as e:  # noqa: BLE001 -- same as run(): any error is a rejection
        print(f"[test] UAV raised {type(e).__name__}: {e}")

    return uav.current_firmware == message["firmware"]


def deliver_encrypted(uav, message, code="LEGITIMATE FLIGHT SOFTWARE"):
    """Like deliver(), for Parts 4 and 5.

    Returns True if the UAV installed the message's version with the
    decrypted code. (deliver() compares against the message's firmware,
    which is ciphertext here.)
    """
    try:
        uav.handle_message(message)
    except Exception as e:  # noqa: BLE001 -- same as run(): any error is a rejection
        print(f"[test] UAV raised {type(e).__name__}: {e}")

    expected = {"version": message["firmware"]["version"], "code": code}
    return uav.current_firmware == expected


# ---------- Fixtures ----------

@pytest.fixture
def ground_key(tmp_path, monkeypatch):
    """A fresh ground key pair in a temp folder, used by the UAV for this test.

    Returns the private key, for signing messages as the ground server.
    """
    private_key = Ed25519PrivateKey.generate()

    (tmp_path / "ground_private.pem").write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (tmp_path / "ground_public.pem").write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    monkeypatch.setenv("LAB_KEYS_DIR", str(tmp_path))
    return private_key


@pytest.fixture
def uav_part1():
    return UAV(part=1)


@pytest.fixture
def uav_part2(ground_key):
    # Depends on ground_key so the key files exist before the UAV is created.
    return UAV(part=2)


@pytest.fixture
def uav_part3(ground_key):
    return UAV(part=3)


@pytest.fixture
def firmware_key(ground_key, tmp_path):
    """A fresh shared firmware key, next to the ground key pair."""
    key = ChaCha20Poly1305.generate_key()
    (tmp_path / "firmware.key").write_text(key.hex())
    return key


@pytest.fixture
def uav_part4(ground_key, firmware_key):
    return UAV(part=4)


# Real PBKDF2 at 600,000 iterations is deliberately slow, so most Part 5
# tests lower the UAV's minimum to this.
TEST_ITERATIONS = 1_000


@pytest.fixture
def firmware_password(ground_key, tmp_path):
    """A shared firmware password, next to the ground key pair."""
    password = "correct horse battery staple"
    (tmp_path / "firmware_password.txt").write_text(password)
    return password


@pytest.fixture
def uav_part5(ground_key, firmware_password):
    uav = UAV(part=5)
    uav.security.min_iterations = TEST_ITERATIONS
    return uav
