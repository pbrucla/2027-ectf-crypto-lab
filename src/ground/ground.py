import hashlib
import os
import socket

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from common.protocol import (
    PBKDF2_ITERATIONS,
    encode_message,
    load_firmware_key,
    load_firmware_password,
    load_private_key,
)

UAV_ADDRESS = ("127.0.0.1", 9000)

def send(message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.sendto(
        encode_message(message),
        UAV_ADDRESS,
    )

    sock.close()


def update_message(version, code):
    # Key order matches the README: type, firmware (version, code).
    # "signature" is added last by the helpers below.
    return {
        "type": "UPDATE",
        "firmware": {
            "version": version,
            "code": code,
        },
    }


def update_firmware(version, code):
    # No protection: no hash, no signature.
    message = update_message(version, code)

    send(message)
    print(f"[GROUND] Sent: {message}")

    return message


def update_firmware_with_hash(version, code):
    # Part 1: "signature" holds the SHA256 hex digest of the encoded message.
    message = update_message(version, code)
    message["signature"] = hashlib.sha256(encode_message(message)).hexdigest()

    send(message)
    print(f"[GROUND] Sent: {message}")

    return message


def update_firmware_signed(version, code):
    # Part 2: "signature" holds an Ed25519 signature of the encoded message,
    # hex-encoded. The private key is loaded here, not on import, so
    # `import ground` works before keys are generated.
    try:
        private_key = load_private_key()
    except FileNotFoundError:
        raise FileNotFoundError(
            "No ground private key found. Run `uv run python generate_keys.py` "
            "from the src folder first."
        ) from None

    message = update_message(version, code)
    message["signature"] = private_key.sign(encode_message(message)).hex()

    send(message)
    print(f"[GROUND] Sent: {message}")

    return message


def update_firmware_encrypted(version, code):
    # Part 4: "code" is encrypted with ChaCha20-Poly1305 under the shared
    # firmware key, with the version as associated data. The whole message
    # is then signed, exactly like update_firmware_signed().
    try:
        firmware_key = load_firmware_key()
        private_key = load_private_key()
    except FileNotFoundError:
        raise FileNotFoundError(
            "Missing keys. Run `uv run python generate_keys.py` "
            "from the src folder first."
        ) from None

    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(firmware_key).encrypt(
        nonce, code.encode(), str(version).encode()
    )

    message = {
        "type": "UPDATE",
        "firmware": {
            "version": version,
            "nonce": nonce.hex(),
            "code": ciphertext.hex(),
        },
    }
    message["signature"] = private_key.sign(encode_message(message)).hex()

    send(message)
    print(f"[GROUND] Sent: {message}")

    return message


def update_firmware_password(version, code, password=None, iterations=PBKDF2_ITERATIONS):
    # Part 5: like update_firmware_encrypted(), but the key is derived from a
    # password with PBKDF2-HMAC-SHA256. The salt is random per update and
    # sent in the clear next to the iteration count; both are signed.
    try:
        if password is None:
            password = load_firmware_password()
        private_key = load_private_key()
    except FileNotFoundError:
        raise FileNotFoundError(
            "Missing keys. Run `uv run python generate_keys.py` "
            "from the src folder first."
        ) from None

    salt = os.urandom(16)
    firmware_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).derive(password.encode())

    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(firmware_key).encrypt(
        nonce, code.encode(), str(version).encode()
    )

    message = {
        "type": "UPDATE",
        "firmware": {
            "version": version,
            "salt": salt.hex(),
            "iterations": iterations,
            "nonce": nonce.hex(),
            "code": ciphertext.hex(),
        },
    }
    message["signature"] = private_key.sign(encode_message(message)).hex()

    send(message)
    print(f"[GROUND] Sent: {message}")

    return message
