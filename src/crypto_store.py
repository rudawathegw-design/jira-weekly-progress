"""
crypto_store.py
Encrypted-at-rest JSON store for confidential data files.

Same scheme as build_site.encrypt_payload so the browser's decryptBlob() can
read anything written here: AES-GCM with a PBKDF2-SHA256(200k) key from
SITE_PASSWORD. On disk a file looks like  {"salt","nonce","ct","iter"}  (all
base64) — opaque without the password.

Migration-friendly:
  load_store(path) reads  path + ".enc"  if present, else falls back to the
  legacy plaintext  path  (so the first encrypted run still sees old data).
  save_store(path, data) always writes the encrypted  path + ".enc"  and
  deletes the plaintext  path  if it still exists.
"""

import os
import json
import base64
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000   # OWASP 2023 floor for PBKDF2-SHA256


def _password():
    pw = os.environ.get("SITE_PASSWORD", "")
    if not pw:
        raise RuntimeError("SITE_PASSWORD env var required for encrypted store.")
    return pw


def encrypt_payload(plaintext: str, password: str) -> dict:
    """AES-GCM encrypt; key = PBKDF2-SHA256(password, salt, 200k iters)."""
    salt  = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=PBKDF2_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return {
        "salt":  base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct":    base64.b64encode(ct).decode(),
        "iter":  PBKDF2_ITERATIONS,
    }


def decrypt_payload(blob: dict, password: str) -> str:
    """Inverse of encrypt_payload."""
    salt  = base64.b64decode(blob["salt"])
    nonce = base64.b64decode(blob["nonce"])
    ct    = base64.b64decode(blob["ct"])
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=int(blob.get("iter", PBKDF2_ITERATIONS)))
    key = kdf.derive(password.encode("utf-8"))
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


def load_store(path, default=None):
    """Read JSON from path+'.enc' (decrypting), else legacy plaintext path."""
    enc_path = path + ".enc"
    if os.path.exists(enc_path):
        try:
            with open(enc_path, "r", encoding="utf-8") as f:
                blob = json.load(f)
            return json.loads(decrypt_payload(blob, _password()))
        except Exception as e:
            raise RuntimeError(f"Failed to decrypt {enc_path}: {e}")
    if os.path.exists(path):           # legacy plaintext (pre-migration)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return default
    return default


def save_store(path, data):
    """Write data as encrypted path+'.enc'; remove any plaintext path."""
    enc_path = path + ".enc"
    blob = encrypt_payload(json.dumps(data, ensure_ascii=False, default=str), _password())
    with open(enc_path, "w", encoding="utf-8") as f:
        json.dump(blob, f)
        f.write("\n")
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass
