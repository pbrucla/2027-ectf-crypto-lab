# 2027 eCTF Cryptography Lab
This is a small cryptography lab to practice thinking about the 2027 eCTF scenario and how we would design a system to be robust against cryptographic attacks. In the actual eCTF competition, the UAV and ground server will most likely be separate boards. 

Hello there! random change!


When you start the scenario, the UAV runs continuously, listening for firmware updates. You will use the ground server to send legitimate updates, and the attacker to send malicious ones.

## Requirements
- [uv](https://docs.astral.sh/uv/) (it installs Python and the dependencies for you on the first `uv run`)
- [Wireshark](https://www.wireshark.org/) (only needed for Parts 2b and 4)

## Scenario

From the eCTF website: “In the 2027 eCTF, teams will design and implement a secure bootloader for an unmanned aerial vehicle (UAV). The system must allow users to securely update and boot custom applications without compromising system integrity or leaking sensitive intellectual property.”

This lab replicates that setup on your own machine. The UAV, the ground server, and the attacker all talk to each other over UDP on `127.0.0.1:9000`:

| Role | File | How you run it |
|------|------|----------------|
| UAV | [`src/uav/uav.py`](src/uav/uav.py) | `uv run python -m uav.uav --part N` (leave it running) |
| Ground server | [`src/ground/ground.py`](src/ground/ground.py) | `import ground` in a Python console |
| Attacker | [`src/attacker.py`](src/attacker.py) | `import attacker` in a Python console |

All of these are run from the `src` folder. For example, the ground server looks like this:
```
cd src
uv run python
>>> import ground
>>> ground.update_firmware(2, "LEGITIMATE FLIGHT SOFTWARE")
```

The only file you need to edit is [`src/uav/security.py`](src/uav/security.py).

## Checking your work
Each part has a set of tests. Run them from the repo root (the folder containing `pyproject.toml`), not from `src`:
```
uv run pytest tests/test_part1.py
uv run pytest tests/test_part2.py
uv run pytest tests/test_part3.py
uv run pytest tests/test_part4.py
uv run pytest tests/test_part5.py
```

Before you write any code, most tests will fail. That's expected: the UAV starts out accepting everything. Your goal is to get every test in a part passing.

Some tests are named `test_attacker_...` or `test_replayed_...`. These check that the attack in that part *works*, so they should pass. They show why the next part is needed.

## Part 1: Integrity with Hashes
Let's try updating the UAV firmware.

To start the UAV, do the following:
```
cd src
uv run python -m uav.uav --part 1
```

The `--part` flag tells the UAV which security check to use. You will restart the UAV with a new part number as you move through the lab.

To use the ground server to interact with the UAV, open a second terminal and start a Python console from the `src` folder:
```
cd src
uv run python
```

Then, send a firmware update with no protection at all:
```python
import ground
ground.update_firmware(2, "LEGITIMATE FLIGHT SOFTWARE")
```

Each helper prints the message it sent and returns it. The message looks like this:
```python
{
    "type": "UPDATE",
    "firmware": {
        "version": 2,
        "code": "LEGITIMATE FLIGHT SOFTWARE",
    },
    "signature": "<blank for now>"
}
```

At this point, there is no security implemented on the UAV, so it installs v2 even though nothing proves the update is genuine. The message could have been modified in transit, and the UAV would still accept it. For message integrity, the UAV should only accept messages whose `"signature"` field holds a valid hash digest.

The ground server computes the hash like this (see `update_firmware_with_hash()` in [`ground.py`](src/ground/ground.py)):
1. Build the message *without* the `"signature"` field.
2. Turn it into bytes with `encode_message()` from [`protocol.py`](src/common/protocol.py).
3. Take the SHA256 hex digest of those bytes and add it as `"signature"`, the last field.

Implement **SHA256** hash verification in `verify_firmware_hash()` in [`security.py`](src/uav/security.py):
- Get the received hash with `message.get("signature")`.
- Hash only the `"type"` and `"firmware"` fields, not the signature itself. The provided helper `unsigned_bytes(message)` gives you exactly the bytes the ground server hashed.
- Compute the expected digest with `hashlib.sha256(...).hexdigest()`.
- Compare the two with `hmac.compare_digest()` rather than `==`, so the comparison takes the same time whether or not the hashes match (this avoids timing attacks).
- The field is called `"signature"`, but in this part it only holds a hash. Real signatures come in Part 2a.
- You only need to modify `verify_firmware_hash()`.

When you're done, restart the UAV (stop it with Ctrl+C and run it again) so it picks up your changes. Then try both kinds of update from the ground console:
```python
ground.update_firmware(3, "LEGITIMATE FLIGHT SOFTWARE")            # no hash: should be rejected
ground.update_firmware_with_hash(3, "LEGITIMATE FLIGHT SOFTWARE")  # correct hash: should be accepted
```

Check your work with `uv run pytest tests/test_part1.py` from the repo root.

## Part 2a: Authenticity with Signatures
A hash needs no secret: anyone, including an attacker, can compute a valid hash for their own firmware, and the Part 1 UAV accepts it (that's what `test_attacker_who_recomputes_hash_is_accepted` shows). This is a problem: we only want to accept updates from the ground server, not the attacker! We will use Ed25519 signatures for authentication. The ground server signs with a private key that only it knows, and the UAV verifies with the matching public key.

Let's first create this keypair. From the `src` folder, run `uv run python generate_keys.py`. This will generate (at the repo root):
```
keys/
├── firmware.key
├── firmware_password.txt
├── ground_private.pem
└── ground_public.pem
```

(`firmware.key` and `firmware_password.txt` are for Parts 4 and 5; ignore them for now.)

The private key belongs to the ground server:
```
ground_private.pem
```
The public key is distributed to the UAV:
```
ground_public.pem
```

The functions to load these keys on the ground and UAV side have been written and are in [`protocol.py`](src/common/protocol.py).

The ground server signs the same bytes you hashed in Part 1 (the message without `"signature"`, encoded with `encode_message()`), then stores the signature as a hex string in `"signature"`.

Implement **Ed25519 signature** verification in `verify_firmware_signature()` in [`security.py`](src/uav/security.py):
- Get the signature with `message.get("signature")`. It arrives as a hex string, but `verify()` expects bytes, so convert it with `bytes.fromhex()`.
- Get the signed data with `unsigned_bytes(message)`, just like in Part 1.
- Use `load_public_key()` to load the ground server's public key from `keys/ground_public.pem`.
- Call `public_key.verify(signature, data)`. Note that it doesn't return `True`/`False`: it returns `None` on success and raises `InvalidSignature` on failure. Catch `InvalidSignature` and return `False`. See the [`cryptography` Ed25519 docs](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).
- You only need to modify `verify_firmware_signature()`.

Restart the UAV in Part 2 mode so it checks signatures instead of hashes:
```
uv run python -m uav.uav --part 2
```

Then try both kinds of update from the ground console:
```python
ground.update_firmware_with_hash(4, "LEGITIMATE FLIGHT SOFTWARE")  # hash only: should be rejected now
ground.update_firmware_signed(4, "LEGITIMATE FLIGHT SOFTWARE")     # signed: should be accepted
```

Check your work with `uv run pytest tests/test_part2.py` from the repo root.

## Part 2b: Replay Attack
Hmmm, is there anything the attacker can do now? Now that the UAV knows if the update came from the ground server, there must be nothing the attacker can do, right?...

You'll need three terminals, all in the `src` folder: the UAV, the ground console, and an attacker console. Your signature check from Part 2a must be working, and the UAV must be running with `--part 2`.

Start the attacker console the same way as the ground console:
```
cd src
uv run python
```
```python
import attacker
```

[`attacker.py`](src/attacker.py) has the same helpers as the ground server. The difference is the key: the attacker doesn't have `ground_private.pem`, so `attacker.update_firmware_signed()` signs with a brand-new key of its own. Try forging an update:
```python
attacker.update_firmware_signed(5, "MALICIOUS FLIGHT SOFTWARE")
```
The UAV rejects it, because the signature doesn't match the ground server's public key. So far, so good.

What if the attacker can "sniff the lines" and see the communication between the ground server and UAV? (like Eve in the classic Alice and Bob scenario). Then, the attacker can execute what is known as a replay attack. Let's try this now!

1. Open Wireshark and start capturing on the loopback interface (`Loopback: lo0` on macOS, `Loopback` or `lo` on Windows/Linux). Type `udp.port == 9000` in the filter bar and press Enter, so you only see UAV traffic.
2. From the ground console, send a signed update:
   ```python
   ground.update_firmware_signed(5, "LEGITIMATE FLIGHT SOFTWARE")
   ```
   One packet appears in Wireshark.
3. Click the packet. In the details pane, right-click the **Data** line and choose **Copy → …as Printable Text**. You should get JSON starting with `{"type":"UPDATE"`.
4. Back in the ground console, send a newer update. The UAV installs v6:
   ```python
   ground.update_firmware_signed(6, "LEGITIMATE FLIGHT SOFTWARE")
   ```
5. In the attacker console, save the captured JSON (paste it between the single quotes) and replay it:
   ```python
   captured = '{"type":"UPDATE","firmware":{"version":5, ...},"signature":"..."}'
   attacker.replay(captured)
   ```
6. Watch the UAV: it prints `Firmware authenticated` and installs **v5** again. The attacker just rolled your firmware back to an older version without knowing the private key. Yikes.

**Try this too:** change `"version":5` to `"version":7` and replay it again:
```python
attacker.replay(captured.replace('"version":5', '"version":7'))
```
This time the UAV rejects it. The signature still protects the *contents* of the message; it just can't tell an old message from a new one.

Here, we ran a replay attack, where we replayed a valid update that we saw from the ground server. If we don't protect against this attack, an attacker can roll our firmware back to any older version the ground server ever signed, including one with a known vulnerability. On a real UAV, the same trick would work on any signed command the ground server has sent before.

The test `test_replayed_update_is_accepted` in [`tests/test_part2.py`](tests/test_part2.py) runs this same attack, so it should pass.

## Part 3: Anti-Replay
The signature proves *who* sent an update, but not *when*. To stop replays, the UAV needs to know how "fresh" an update is so it can spot a stale one. One classic and simple way to do this is a monotonically increasing counter. Firmware updates already carry one: the `version` field. The UAV remembers the newest version it has accepted and rejects anything that isn't newer.

This works only because `version` is covered by the signature. If the attacker bumps the version of a captured update (like the `"version":7` trick in Part 2b), the signature no longer matches and the update is rejected before the counter is even checked.

In Part 3 mode, the UAV runs your Part 2a signature check first and then calls `verify_firmware_counter()`. An update installs only if both return `True`.

Implement the anti-rollback check in `verify_firmware_counter()` in [`security.py`](src/uav/security.py):
- `self.highest_version` (set in `__init__`) holds the newest version accepted so far. It starts at `1`, the version the UAV ships with.
- Read the incoming version from `message["firmware"]["version"]`.
- Reject it unless it is **strictly** newer than `self.highest_version`. Replaying the currently installed version should fail too.
- If you accept it, update `self.highest_version` before returning `True`.
- You only need to modify `verify_firmware_counter()`. Your Part 2a signature check must already work.

Restart the UAV in Part 3 mode:
```
uv run python -m uav.uav --part 3
```

Then repeat the Part 2b attack with the UAV, ground, and attacker consoles. Capture the v5 packet in Wireshark exactly as in Part 2b, and save it as `captured` in the attacker console:
```python
ground.update_firmware_signed(5, "LEGITIMATE FLIGHT SOFTWARE")  # capture this one in Wireshark
ground.update_firmware_signed(6, "LEGITIMATE FLIGHT SOFTWARE")  # accepted: 6 > 5
attacker.replay(captured)                                      # v5 again: should be rejected now
```

The UAV prints `Firmware rejected` and stays on v6. Your Part 2a signature check still runs too, so `attacker.update_firmware_signed(99, ...)` is rejected even though 99 is newer.

Check your work with `uv run pytest tests/test_part3.py` from the repo root. The Part 2 test `test_replayed_update_is_accepted` still passes, because it runs the UAV in Part 2 mode, which has no counter.

Things to think about:
- Restarting the UAV resets `highest_version` to 1, so an old update becomes valid again. On a real device, where would the counter need to live so it survives a reboot?
- What happens if the ground server ever signs a huge version number by mistake (say `2**31`)?
- A counter needs the receiver to remember state. What alternatives (timestamps, challenge-response nonces) avoid that, and what do they need instead?

## Part 4: Confidentiality with AEAD
So far, everything we've added protects *integrity* and *authenticity*. Go back to Wireshark and look at any update packet: the firmware `code` is sitting there in plaintext. The eCTF scenario asks us to update the UAV "without leaking sensitive intellectual property", so anyone sniffing the link shouldn't be able to read the firmware.

We'll encrypt the code with **ChaCha20-Poly1305**, an AEAD cipher (Authenticated Encryption with Associated Data). It does two jobs at once:
- **Encryption:** ChaCha20 turns the code into ciphertext that only someone with the key can read.
- **Authentication:** Poly1305 adds a 16-byte tag. If even one bit of the ciphertext changes, decryption fails instead of returning garbage.
- **Associated data (AD):** extra bytes that are authenticated by the tag but *not* encrypted. We use the firmware version, so it stays readable (the UAV needs it for the Part 3 counter) but a ciphertext can't be moved into a message with a different version.

Unlike Ed25519, ChaCha20-Poly1305 is *symmetric*: the ground server and the UAV share the same secret key. `generate_keys.py` already created it in Part 2a:
```
keys/
├── firmware.key        # shared by the ground server and the UAV
├── firmware_password.txt
├── ground_private.pem
└── ground_public.pem
```
If you don't have `keys/firmware.key`, run `uv run python generate_keys.py` again from the `src` folder. This also makes a new Ed25519 key pair, so restart the UAV afterwards.

The ground server builds an encrypted update like this (see `update_firmware_encrypted()` in [`ground.py`](src/ground/ground.py)):
1. Pick a random 12-byte nonce. A nonce must **never** be reused with the same key.
2. Encrypt the code: `ChaCha20Poly1305(key).encrypt(nonce, code.encode(), str(version).encode())`. The last argument is the associated data.
3. Put the nonce and ciphertext (with the tag on the end) in `"firmware"` as hex, then sign the whole message as in Part 2a.

An encrypted update looks like this:
```python
{
    "type": "UPDATE",
    "firmware": {
        "version": 7,
        "nonce": "<12 bytes as hex>",
        "code": "<ciphertext + tag as hex>",
    },
    "signature": "<hex>"
}
```

In Part 4 mode, the UAV checks your Part 2a signature first, then calls `decrypt_firmware()`, then your Part 3 counter. It installs the decrypted code only if all three succeed.

Implement **ChaCha20-Poly1305** decryption in `decrypt_firmware()` in [`security.py`](src/uav/security.py):
- Get the nonce and ciphertext from `message["firmware"]["nonce"]` and `message["firmware"]["code"]`, and convert both from hex with `bytes.fromhex()`.
- Use `load_firmware_key()` to load the shared key from `keys/firmware.key`. `decrypt_firmware()` also takes an optional `key` argument: only load the key when `key` is `None`. Part 5 uses this to pass in a key derived from a password.
- Call `ChaCha20Poly1305(key).decrypt(nonce, ciphertext, associated_data)`, where the associated data is the version, exactly as the ground server encoded it: `str(version).encode()`. See the [`cryptography` AEAD docs](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305).
- Like `verify()`, `decrypt()` raises on failure instead of returning `False`: it raises `InvalidTag`. Catch it and return `None`.
- On success, return the code as a string with `.decode()`.
- You only need to modify `decrypt_firmware()`. Your Part 2a and Part 3 checks must already work.

Restart the UAV in Part 4 mode:
```
uv run python -m uav.uav --part 4
```

With Wireshark capturing as in Part 2b, compare the two kinds of signed update from the ground console:
```python
ground.update_firmware_signed(7, "LEGITIMATE FLIGHT SOFTWARE")     # plaintext: readable in Wireshark, rejected by the UAV
ground.update_firmware_encrypted(7, "LEGITIMATE FLIGHT SOFTWARE")  # encrypted: unreadable in Wireshark, installed by the UAV
```
The UAV rejects the plaintext update, then prints `Installing firmware v7` for the encrypted one. In Wireshark, the `"code"` field of the encrypted update is now just hex.

The attacker has neither key, so `attacker.update_firmware_encrypted(8, "MALICIOUS FLIGHT SOFTWARE")` is rejected. Replaying a captured encrypted update still fails because of your Part 3 counter: encryption hides the firmware, but it doesn't stop replays on its own.

Check your work with `uv run pytest tests/test_part4.py` from the repo root.

Things to think about:
- The whole message is signed *and* the ciphertext has a Poly1305 tag. If the signature already protects integrity, what does the tag add? (Hint: who else holds `firmware.key`?)
- What goes wrong if the ground server reuses a nonce for two different firmware images under the same key?
- Every UAV in a fleet shares one `firmware.key`. What happens if an attacker pulls it out of a single captured UAV? How could you limit the damage?
- The version and the length of the firmware are still visible. Could that leak anything useful to an attacker?

## Part 5: Keys from Passwords with PBKDF2
In Part 4, `firmware.key` was 32 random bytes. Real keys often start as something a person can type and remember instead: an operator password, a deployment PIN, a build secret. A password can't be used as a ChaCha20 key directly. It's the wrong length, and it has far less randomness than 32 random bytes.

The obvious fix, `sha256(password)`, gives you 32 bytes, but it's a bad key. SHA256 is designed to be *fast*, so an attacker who captures an encrypted update can try billions of guessed passwords per second until one decrypts it. A **key derivation function** for passwords is designed to be *slow* instead. We'll use **PBKDF2-HMAC-SHA256**, which takes three inputs:
- **Password:** the secret.
- **Salt:** random bytes, new for every update. The salt does **not** need to be secret, so it is sent in plaintext next to the ciphertext. It makes sure the same password gives a different key every time, so an attacker can't precompute a table of `password → key` and reuse it across messages.
- **Iterations:** how many times HMAC-SHA256 is applied internally. This is the work factor. The ground server uses 600,000 (OWASP's current recommendation), so every guess costs an attacker 600,000 times as much work as a plain hash.

`generate_keys.py` already created a random password shared by the ground server and the UAV:
```
keys/
├── firmware.key
├── firmware_password.txt   # Part 5: shared by the ground server and the UAV
├── ground_private.pem
└── ground_public.pem
```
If you don't have `keys/firmware_password.txt`, run `uv run python generate_keys.py` again from the `src` folder and restart the UAV.

The ground server builds a password-based update like this (see `update_firmware_password()` in [`ground.py`](src/ground/ground.py)):
1. Pick a random 16-byte salt.
2. Derive a 32-byte key from the password with PBKDF2-HMAC-SHA256, using that salt and 600,000 iterations.
3. Encrypt the code with that key exactly as in Part 4.
4. Put the salt (hex) and the iteration count in `"firmware"`, then sign the whole message.

A password-based update looks like this:
```python
{
    "type": "UPDATE",
    "firmware": {
        "version": 8,
        "salt": "<16 bytes as hex>",
        "iterations": 600000,
        "nonce": "<12 bytes as hex>",
        "code": "<ciphertext + tag as hex>",
    },
    "signature": "<hex>"
}
```

In Part 5 mode, the UAV runs the same steps as Part 4: signature, then decryption, then the counter. The only difference is that it calls `decrypt_firmware_password()`, which derives the key first and then hands it to your Part 4 `decrypt_firmware()`.

Implement **PBKDF2** key derivation in [`security.py`](src/uav/security.py) in two methods.

`derive_firmware_key(password, salt, iterations)`:
- Create a `PBKDF2HMAC` with `algorithm=hashes.SHA256()`, `length=32` (ChaCha20 needs a 256-bit key), and the given `salt` and `iterations`.
- Return `.derive(password.encode())`. `derive()` takes bytes, not a string.
- A `PBKDF2HMAC` object can only derive **once**: calling `derive()` twice raises `AlreadyFinalized`. Create a new one on every call. See the [`cryptography` PBKDF2 docs](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC).

`decrypt_firmware_password(message)`:
- Get the salt and iteration count from `message["firmware"]`, and convert the salt from hex with `bytes.fromhex()`.
- Return `None` if the iteration count is below `self.min_iterations` (set in `__init__`). The signature already proves the ground server sent it, but the UAV should still refuse a weakened work factor, for example from a misconfigured or compromised build tool. Compare against `self.min_iterations` rather than writing `600000`, because the tests lower it to stay fast.
- Load the password with `load_firmware_password()` and derive the key with `self.derive_firmware_key()`.
- Return `self.decrypt_firmware(message, key)`. When you pass `key`, your Part 4 code should use it instead of loading `firmware.key`.
- Your Part 2a, 3 and 4 code must already work.

Restart the UAV in Part 5 mode:
```
uv run python -m uav.uav --part 5
```

Then send updates from the ground console:
```python
ground.update_firmware_password(8, "LEGITIMATE FLIGHT SOFTWARE")                   # accepted
ground.update_firmware_password(9, "LEGITIMATE FLIGHT SOFTWARE", iterations=1000)  # too few iterations: rejected
ground.update_firmware_password(9, "LEGITIMATE FLIGHT SOFTWARE", password="oops")  # wrong password: rejected
```
You should notice a short pause on each accepted update. That pause is the 600,000 iterations, and it's the point: the UAV pays it once per update, but an attacker guessing passwords pays it for every single guess.

Check your work with `uv run pytest tests/test_part5.py` from the repo root.

Things to think about:
- The salt is sent in plaintext, and anyone on the link can read it in Wireshark. Why doesn't that help an attacker?
- PBKDF2 makes every guess slow, but a guess is still a guess. If the password were `dragon`, how much would 600,000 iterations really help?
- The UAV stores `firmware_password.txt` right next to its code. Is that any safer than storing `firmware.key`? Where does a password KDF actually help: on a device, or with a human typing a password?
- PBKDF2 needs very little memory, so GPUs and custom hardware can run many guesses in parallel. How do memory-hard KDFs like scrypt and Argon2 change that?
- How is a password KDF like PBKDF2 different from a KDF like HKDF, which expands an already-random key into several keys?
