"""Part 4: Confidentiality with ChaCha20-Poly1305.

Run with:  uv run pytest tests/test_part4.py
"""

from conftest import (
    deliver_encrypted,
    encrypted_update_message,
    update_message,
    with_signature,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

CODE = "LEGITIMATE FLIGHT SOFTWARE"


# ---------- Part 4: the UAV decrypts the firmware ----------

def test_encrypted_update_is_decrypted_and_installed(uav_part4, ground_key, firmware_key):
    message = with_signature(encrypted_update_message(2, CODE, firmware_key), ground_key)

    assert deliver_encrypted(uav_part4, message)


def test_ciphertext_hides_the_code(firmware_key):
    # What Wireshark sees: no plaintext anywhere in the firmware.
    message = encrypted_update_message(2, CODE, firmware_key)

    assert CODE not in str(message)
    assert CODE.encode().hex() not in str(message)


def test_unencrypted_update_is_rejected(uav_part4, ground_key):
    # A Part 2/3-style signed update with plaintext code.
    message = with_signature(update_message(version=2, code=CODE), ground_key)

    assert not deliver_encrypted(uav_part4, message)


def test_wrong_firmware_key_is_rejected(uav_part4, ground_key):
    # Signed by the ground server, but encrypted under a different key.
    other_key = ChaCha20Poly1305.generate_key()
    message = with_signature(encrypted_update_message(2, CODE, other_key), ground_key)

    assert not deliver_encrypted(uav_part4, message)


def test_flipped_ciphertext_bit_is_rejected(uav_part4, ground_key, firmware_key):
    # Flip one bit of the ciphertext before signing: the signature is fine,
    # so only the Poly1305 tag can catch it.
    message = encrypted_update_message(2, CODE, firmware_key)
    code = bytearray(bytes.fromhex(message["firmware"]["code"]))
    code[0] ^= 0x01
    message["firmware"]["code"] = code.hex()
    message = with_signature(message, ground_key)

    assert not deliver_encrypted(uav_part4, message)


def test_wrong_associated_data_is_rejected(uav_part4, ground_key, firmware_key):
    # Ciphertext bound to v2, placed in a v3 message: the version must be
    # used as associated data when decrypting.
    message = encrypted_update_message(3, CODE, firmware_key, associated_version=2)
    message = with_signature(message, ground_key)

    assert not deliver_encrypted(uav_part4, message)


def test_malformed_nonce_is_rejected(uav_part4, ground_key, firmware_key):
    message = encrypted_update_message(2, CODE, firmware_key)
    message["firmware"]["nonce"] = "not hex"
    message = with_signature(message, ground_key)

    assert not deliver_encrypted(uav_part4, message)


def test_replayed_encrypted_update_is_rejected(uav_part4, ground_key, firmware_key):
    # Encryption doesn't replace Part 3: replays must still fail.
    old_update = with_signature(encrypted_update_message(2, CODE, firmware_key), ground_key)
    new_update = with_signature(encrypted_update_message(3, CODE, firmware_key), ground_key)

    assert deliver_encrypted(uav_part4, old_update)
    assert deliver_encrypted(uav_part4, new_update)
    assert not deliver_encrypted(uav_part4, old_update)


def test_failed_decryption_does_not_advance_counter(uav_part4, ground_key, firmware_key):
    other_key = ChaCha20Poly1305.generate_key()
    bad = with_signature(encrypted_update_message(3, CODE, other_key), ground_key)
    good = with_signature(encrypted_update_message(3, CODE, firmware_key), ground_key)

    assert not deliver_encrypted(uav_part4, bad)
    assert deliver_encrypted(uav_part4, good)
