import json
import os
import struct
import sys
from pathlib import Path

try:
    import sqlite3
except ImportError:
    sqlite3 = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as _exc:
    sys.exit(f"missing dependency '{_exc.name}'. run: pip install -r requirements.txt")

VAULT_KEY = b"vault"

def _read_leveldb_dir(directory):
    results = []
    for path in Path(directory).rglob("*.ldb"):
        try:
            with open(path, "rb") as f:
                data = f.read()
            if b'"vault"' in data:
                start = data.find(b'{')
                end = data.rfind(b'}')
                if start != -1 and end != -1:
                    try:
                        blob = json.loads(data[start:end+1])
                        results.append(blob)
                    except json.JSONDecodeError:
                        pass
                # sometimes the value is raw json after a length prefix
                idx = data.find(b'"vault"')
                if idx != -1:
                    # scan backward for a json start
                    bstart = data.rfind(b'{', 0, idx)
                    if bstart != -1:
                        bend = data.find(b'\x00', idx)
                        if bend == -1:
                            bend = len(data)
                        try:
                            blob = json.loads(data[bstart:bend])
                            results.append(blob)
                        except json.JSONDecodeError:
                            pass
        except Exception:
            continue
    return results

def _read_sqlite_logindb(directory):
    if sqlite3 is None:
        return []
    db_path = Path(directory) / "logind"
    if not db_path.exists():
        return []
    results = []
    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM ItemTable")
        for row in cur:
            key, value = row
            if key == VAULT_KEY or (isinstance(value, bytes) and b'"vault"' in value):
                try:
                    results.append(json.loads(value))
                except Exception:
                    pass
        conn.close()
    except Exception:
        pass
    return results

def _extract_vault_blob(raw):
    if isinstance(raw, dict):
        if "vault" in raw:
            raw = raw["vault"]
        elif "data" in raw:
            raw = raw["data"]
        else:
            return None
    if isinstance(raw, str):
        return raw
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="ignore")
    return None

def find_vault_data(directory):
    directory = Path(directory)
    blobs = []

    blobs.extend(_read_leveldb_dir(directory))
    if not blobs:
        blobs.extend(_read_sqlite_logindb(directory))

    for blob in blobs:
        vault_str = _extract_vault_blob(blob)
        if not vault_str:
            continue
        try:
            vault = json.loads(vault_str)
            if "data" in vault and "salt" in vault:
                return vault
            if "iv" in vault or "cipher" in vault:
                return vault
            if "keyMetadata" in vault:
                return vault
        except Exception:
            continue

    return None

def _safe_b64decode(s):
    import base64
    if isinstance(s, bytes):
        return base64.b64decode(s)
    s = s.strip()
    return base64.b64decode(s + "=" * (-len(s) % 4))

def _derive_key(password, salt_b64, n=131072, r=8, p=1, dklen=32):
    salt = _safe_b64decode(salt_b64)
    kdf = Scrypt(
        salt=salt,
        length=dklen,
        n=n,
        r=r,
        p=p,
    )
    return kdf.derive(password.encode("utf-8"))

def _parse_v3(vault, password):
    meta = vault.get("keyMetadata", {})
    params = meta.get("params", {})
    if not params:
        return None
    salt_b64 = params.get("salt")
    iv_b64 = vault.get("iv")
    data_b64 = vault.get("data")
    if not salt_b64 or not iv_b64 or not data_b64:
        return None
    try:
        key = _derive_key(password, salt_b64,
                          n=params.get("n", 131072),
                          r=params.get("r", 8),
                          p=params.get("p", 1))
        ciphertext = _safe_b64decode(data_b64)
        iv = _safe_b64decode(iv_b64)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        return None

def decrypt_vault(vault, password):
    if "keyMetadata" in vault:
        return _parse_v3(vault, password)

    data = vault.get("data")
    salt = vault.get("salt")
    iv_b64 = vault.get("iv")

    if data is None or salt is None:
        return None

    try:
        key = _derive_key(password, salt)
    except Exception:
        return None

    try:
        ciphertext = _safe_b64decode(data)
        iv = _safe_b64decode(iv_b64)
    except Exception:
        return None

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        return None
