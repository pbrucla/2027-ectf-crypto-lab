"""Part 5: Keys from passwords with PBKDF2.

Run with:  uv run pytest tests/test_part5.py
"""

from conftest import (
    TEST_ITERATIONS,
    deliver_encrypted,
    encrypted_update_message,
    password_update_message,
    with_signature,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from common.protocol import PBKDF2_ITERATIONS
from uav.security import Security
from uav.uav import UAV

CODE = "LEGITIMATE FLIGHT SOFTWARE"


# ---------- Part 5a: deriving the key ----------

def test_derived_key_matches_known_vector():
    # RFC 7914 section 11 test vector for PBKDF2-HMAC-SHA256
    # (P="passwd", S="salt", c=1), first 32 bytes.
    key = Security().derive_firmware_key("passwd", b"salt", 1)

    assert key.hex() == "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"


def test_derived_key_is_32_bytes():
    # ChaCha20-Poly1305 needs a 256-bit key.
    key = Security().derive_firmware_key("password", b"0" * 16, TEST_ITERATIONS)

    assert len(key) == 32


def test_derivation_is_deterministic():
    # The ground server and the UAV must arrive at the same key.
    security = Security()
    first = security.derive_firmware_key("password", b"0" * 16, TEST_ITERATIONS)
    second = security.derive_firmware_key("password", b"0" * 16, TEST_ITERATIONS)

    assert first == second


def test_different_salts_give_different_keys():
    security = Security()
    first = security.derive_firmware_key("password", b"0" * 16, TEST_ITERATIONS)
    second = security.derive_firmware_key("password", b"1" * 16, TEST_ITERATIONS)

    assert first != second


def test_different_iterations_give_different_keys():
    security = Security()
    first = security.derive_firmware_key("password", b"0" * 16, TEST_ITERATIONS)
    second = security.derive_firmware_key("password", b"0" * 16, TEST_ITERATIONS + 1)

    assert first != second


# ---------- Part 5b: the UAV decrypts with the derived key ----------

def test_password_update_is_accepted(uav_part5, ground_key, firmware_password):
    message = password_update_message(2, CODE, firmware_password, TEST_ITERATIONS)

    assert deliver_encrypted(uav_part5, with_signature(message, ground_key))


def test_default_iterations_are_accepted(ground_key, firmware_password):
    # The real settings: the ground server's default work factor must meet
    # the UAV's real minimum. (Slow on purpose: about half a second.)
    uav = UAV(part=5)
    message = password_update_message(2, CODE, firmware_password, PBKDF2_ITERATIONS)

    assert deliver_encrypted(uav, with_signature(message, ground_key))


def test_wrong_password_is_rejected(uav_part5, ground_key):
    message = password_update_message(2, CODE, "wrong password", TEST_ITERATIONS)

    assert not deliver_encrypted(uav_part5, with_signature(message, ground_key))


def test_too_few_iterations_are_rejected(uav_part5, ground_key, firmware_password):
    # Signed by the ground server and the right password, but a weaker
    # work factor than the UAV allows.
    message = password_update_message(2, CODE, firmware_password, TEST_ITERATIONS - 1)

    assert not deliver_encrypted(uav_part5, with_signature(message, ground_key))


def test_changed_salt_is_rejected(uav_part5, ground_key, firmware_password):
    # Re-signed after the change, so only the derived key can catch it.
    message = password_update_message(2, CODE, firmware_password, TEST_ITERATIONS)
    message["firmware"]["salt"] = "00" * 16

    assert not deliver_encrypted(uav_part5, with_signature(message, ground_key))


def test_part4_update_is_rejected(uav_part5, ground_key):
    # A Part 4 update has no salt or iterations to derive a key from.
    message = encrypted_update_message(2, CODE, ChaCha20Poly1305.generate_key())

    assert not deliver_encrypted(uav_part5, with_signature(message, ground_key))


def test_replayed_password_update_is_rejected(uav_part5, ground_key, firmware_password):
    old_update = with_signature(
        password_update_message(2, CODE, firmware_password, TEST_ITERATIONS), ground_key
    )
    new_update = with_signature(
        password_update_message(3, CODE, firmware_password, TEST_ITERATIONS), ground_key
    )

    assert deliver_encrypted(uav_part5, old_update)
    assert deliver_encrypted(uav_part5, new_update)
    assert not deliver_encrypted(uav_part5, old_update)
