#!/usr/bin/env python3
"""

vox_crypt decryptor

"""

import sys
import base64
import argparse
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


def parse_snapshots(file_path):
   
    snapshots = []
    current = {}
    mode = None  # None, 'priv', 'pub'

    with open(file_path, "r", encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f]

    for line in lines:
        if line.startswith("=== Encryptor snapshot ==="):
            if current:
                snapshots.append(current)
            current = {}
            mode = None
        elif line.startswith("----- RSA PRIVATE KEY (PEM) -----"):
            current["rsa_private_pem"] = ""
            mode = "priv"
        elif line.startswith("----- RSA PUBLIC KEY (PEM) -----"):
            current["rsa_public_pem"] = ""
            mode = "pub"
        elif ":" in line and not line.startswith("-----"):
            # key: value lines
            mode = None
            k, v = line.split(":", 1)
            current[k.strip()] = v.strip()
        else:
            # continuation lines for PEM blocks or ignored lines
            if mode == "priv":
                current["rsa_private_pem"] += line + "\n"
            elif mode == "pub":
                current["rsa_public_pem"] += line + "\n"
            else:
                # ignore other non-key lines
                pass

    if current:
        snapshots.append(current)
    return snapshots


def decrypt_single_snapshot(snap):

    rsa_priv_pem = snap.get("rsa_private_pem", "").strip()
    # Note: some snapshots may not include a private key; RSA.import_key will raise if invalid/empty.
    if not rsa_priv_pem:
        raise ValueError("No RSA private key found in snapshot.")

    rsa_priv_key = RSA.import_key(rsa_priv_pem.encode())

    rsa_enc_session_key_b64 = snap.get("rsa_enc_session_key_b64", "")
    nonce_b64 = snap.get("aes_nonce_b64", "")
    tag_b64 = snap.get("aes_tag_b64", "")
    ciphertext_b64 = snap.get("ciphertext_base64", "")

    # In the original code the decryptor expects 'aes_base_key_hex' to be audio_fingerprint.
    aes_base_key_hex = snap.get("aes_base_key_hex", "")
    audio_fingerprint = bytes.fromhex(aes_base_key_hex) if aes_base_key_hex else None

    # Determine AES key:
    if not rsa_enc_session_key_b64 or "fallback" in rsa_enc_session_key_b64.lower() or "failed" in rsa_enc_session_key_b64.lower():
        # fallback to final_aes_key_hex if provided
        final_aes_key_hex = snap.get("final_aes_key_hex", "")
        if not final_aes_key_hex:
            raise ValueError("No RSA-encrypted session key and no final_aes_key_hex available.")
        key = bytes.fromhex(final_aes_key_hex)
    else:
        # RSA-OAEP decrypt session key
        try:
            enc_session_key = base64.b64decode(rsa_enc_session_key_b64)
        except Exception as ex:
            raise ValueError(f"Invalid base64 for rsa_enc_session_key_b64: {ex}")
        cipher_rsa = PKCS1_OAEP.new(rsa_priv_key, hashAlgo=SHA256)
        try:
            key = cipher_rsa.decrypt(enc_session_key)
        except Exception as ex:
            raise ValueError(f"RSA-OAEP session key decryption failed: {ex}")

    # ciphertext, nonce, tag must be base64 decoded (unless ciphertext was stored as raw base64 of plaintext fallback)
    try:
        nonce = base64.b64decode(nonce_b64) if nonce_b64 else b""
    except Exception as ex:
        raise ValueError(f"Invalid base64 for nonce: {ex}")
    try:
        tag = base64.b64decode(tag_b64) if tag_b64 else b""
    except Exception as ex:
        raise ValueError(f"Invalid base64 for tag: {ex}")
    try:
        ciphertext = base64.b64decode(ciphertext_b64) if ciphertext_b64 else b""
    except Exception as ex:
        raise ValueError(f"Invalid base64 for ciphertext: {ex}")

    # If tag/nonce empty, treat as error (GCM expected). If ciphertext was plaintext base64 fallback, decrypt/verify will fail;
    # but we try decrypt_and_verify and propagate errors to caller.
    try:
        if nonce and tag:
            cipher_aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
            if audio_fingerprint:
                cipher_aes.update(audio_fingerprint)
            plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()
        else:
            # No GCM metadata: attempt to interpret ciphertext as raw base64-encoded plaintext (fallback from encryptor)
            # If ciphertext is actually plain text base64 then decoding already returned bytes of original plaintext.
            plaintext = ciphertext.decode()
    except Exception as ex:
        raise ValueError(f"AES decryption/verification failed: {ex}")

    return plaintext.strip()


def merge_snapshots(parts):
    if not parts:
        return ""
    merged = parts[0]
    for part in parts[1:]:
        merged += "\n" + part
    return merged


def main():
    parser = argparse.ArgumentParser(description="Decrypt snapshot TXT from encryptor.")
    parser.add_argument("input_file", help="Path ke file snapshot TXT")
    parser.add_argument("--first", action="store_true", help="Ambil snapshot pertama saja")
    parser.add_argument("--last", action="store_true", help="Ambil snapshot terakhir saja")
    parser.add_argument("--all", action="store_true", help="Gabungkan semua snapshot (hapus exact-duplicates)")
    args = parser.parse_args()

    snapshots = parse_snapshots(args.input_file)
    if not snapshots:
        print("No snapshots found in file.")
        sys.exit(1)

    result = ""

    if args.all:
        parts = []
        seen = set()
        for idx, snap in enumerate(snapshots, 1):
            try:
                pt = decrypt_single_snapshot(snap)
                # deduplicate exact plaintexts while preserving order
                if pt not in seen:
                    seen.add(pt)
                    parts.append(pt)
            except Exception as ex:
                print(f"[!] Snapshot #{idx} decryption failed:", ex)
        # join unique parts preserving order; no aggressive overlap removal
        result = "\n\n".join(parts)
    elif args.last:
        try:
            result = decrypt_single_snapshot(snapshots[-1])
        except Exception as ex:
            print(f"[!] Last snapshot decryption failed:", ex)
            sys.exit(1)
    else:  # default atau --first
        try:
            result = decrypt_single_snapshot(snapshots[0])
        except Exception as ex:
            print(f"[!] First snapshot decryption failed:", ex)
            sys.exit(1)

    print("=== Decryption Result ===")
    print(result)


if __name__ == "__main__":
    main()
