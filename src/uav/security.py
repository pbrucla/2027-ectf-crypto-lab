import hashlib
import hmac

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from common.protocol import (
    encode_message,
    load_firmware_key,
    load_firmware_password,
    load_public_key,
)


# Helper function to extract the unsigned bytes of a message
def unsigned_bytes(message):
    unsigned = dict(message)
    unsigned.pop("signature", None)
    return encode_message(unsigned)

class Security:
    # To verify, extract the signature from the message and check it against the unsigned bytes.

    def __init__(self):
        # Part 3: newest firmware version accepted so far (the UAV ships with v1)
        self.highest_version = 1

        # Part 5: fewest PBKDF2 iterations the UAV will accept
        self.min_iterations = 600_000

    # Part 1
    def verify_firmware_hash(self, message):
        # TODO: Implement SHA256 hash verification
        # 1. Extract signature from message using get()
        # 2. Extract unsigned bytes from message using unsigned_bytes()
        # 3. Use hashlib.sha256() and hexdigest() to hash the unsigned bytes
        # 4. Use hmac.compare_digest() to compare 
        received = message.get("signature")
        hashed = hashlib.sha256(unsigned_bytes(message)).hexdigest()
        return hmac.compare_digest(received,hashed)

    # Part 2
    def verify_firmware_signature(self, message):
        # TODO: Implement Ed25519 signature verification
        # 1. Extract signature from message using get() and convert it from hex to bytes
        # 2. Extract unsigned bytes from message using unsigned_bytes()
        # 3. Load the public key using load_public_key()
        # 4. Use public_key.verify() to verify the signature against the unsigned bytes
        # 5. Catch InvalidSignature and return False
        sig = bytes.fromhex(message.get("signature"))
        data = unsigned_bytes(message)
        public_key = load_public_key()

        try:
            public_key.verify(sig,data)
        except InvalidSignature:
            return False
        
        return True
    
    # Part 3
    def verify_firmware_counter(self, message):
        # TODO: Implement anti-rollback check
        # (The signature is checked before this is called, so the version can be trusted.)
        # 1. Extract the version from message["firmware"]
        # 2. Reject it unless it is strictly newer than self.highest_version
        # 3. Otherwise, update self.highest_version and return True

        return True

    # Part 4
    def decrypt_firmware(self, message, key=None):
        # TODO: Implement ChaCha20-Poly1305 decryption
        # (The signature is checked before this is called.)
        # 1. Extract the nonce and code (ciphertext) from message["firmware"] and convert them from hex to bytes
        # 2. If key is None, load the shared key using load_firmware_key() (Part 5 passes in a derived key)
        # 3. Use ChaCha20Poly1305(key).decrypt() with the version as associated data: str(version).encode()
        # 4. Return the decrypted code as a string with decode()
        # 5. Catch InvalidTag and return None

        return message["firmware"]["code"]

    # Part 5
    def derive_firmware_key(self, password, salt, iterations):
        # TODO: Implement PBKDF2-HMAC-SHA256 key derivation
        # 1. Create a PBKDF2HMAC with algorithm=hashes.SHA256(), length=32, salt, and iterations
        # 2. Return .derive() of the password as bytes (encode())
        # (A PBKDF2HMAC object can only derive once, so make a new one each call.)

        return bytes(32)

    def decrypt_firmware_password(self, message):
        # TODO: Implement password-based decryption
        # (The signature is checked before this is called, so salt and iterations can be trusted.)
        # 1. Extract the salt (hex) and iterations from message["firmware"]
        # 2. Return None if iterations is below self.min_iterations
        # 3. Load the password using load_firmware_password()
        # 4. Derive the key with derive_firmware_key()
        # 5. Return decrypt_firmware(message, key)

        return message["firmware"]["code"]
