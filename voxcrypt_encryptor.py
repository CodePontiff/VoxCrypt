#!/usr/bin/env python3
"""
encryptor_oaep_gcm_append.py

- Seed audio -> RSA keypair (derived from audio primes) and aes_base_key = SHA256(seed_audio)
- Live audio frames produce salt -> final_aes_key = SHA256(aes_base_key + salt)
- RSA-OAEP(SHA256) encrypts AES session key (hybrid encryption)
- AES-256-GCM encrypts plaintext using the AES session key and audio_fingerprint as AAD
- Append snapshot TXT if -o given
"""
import argparse
import sys
import select
import time
import math
import hashlib
import base64
import numpy as np
import sounddevice as sd
import matplotlib.pyplot as plt
from matplotlib.collections import LineCollection
from matplotlib.colors import ListedColormap
import matplotlib as mpl
from sympy import nextprime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import inverse
import os

# ========== Configuration ==========
SAMPLE_RATE = 44100
SEED_CHUNK = 1024
LIVE_CHUNK = 1024
DISPLAY_LEN = 512
KEY_BITS_PER_PRIME = 256
RSA_E = 65537
ENCRYPT_INTERVAL = 1.0
NEON_COLORS = ['#ff0080', '#bf00bf', '#8000ff', '#4000ff', '#00bfff', '#00ffff']

# ========== Helpers ==========
def record_until_enter(fs=SAMPLE_RATE, chunk=SEED_CHUNK):
    print("RECORD MODE: Start speaking. Press ENTER in this terminal to stop recording seed for RSA.")
    audio_chunks = []
    stream = sd.InputStream(samplerate=fs, channels=1, dtype='int16', blocksize=chunk)
    stream.start()
    try:
        while True:
            data, _ = stream.read(chunk)
            audio_chunks.append(data.copy().flatten())
            if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                _ = sys.stdin.readline()
                break
    except KeyboardInterrupt:
        pass
    finally:
        stream.stop()
    if len(audio_chunks) == 0:
        return np.array([], dtype='int16')
    return np.concatenate(audio_chunks).astype('int16')

def make_seed_from_samples(samples, key_bits=KEY_BITS_PER_PRIME):
    mean = float(np.mean(samples)) if samples.size > 0 else 0.0
    rms = float(np.sqrt(np.mean(samples.astype(np.float64)**2))) if samples.size > 0 else 0.0
    trig_val = abs(math.sin(mean) * math.cos(rms))
    h = hashlib.sha512(samples.tobytes()).digest()
    h_int = int.from_bytes(h, 'big')
    scale = (1 << (key_bits - 16))
    trig_int = int(trig_val * scale)
    seed = (h_int ^ (trig_int << (len(h) * 8 // 4)))
    seed |= (1 << (key_bits - 1))
    return seed

def generate_primes_from_audio(audio, bits=KEY_BITS_PER_PRIME):
    L = len(audio)
    a1 = audio[0: max(1, L // 8)]
    a2 = audio[L // 2 : L // 2 + max(1, L // 8)]
    seed1 = make_seed_from_samples(a1, bits)
    seed2 = make_seed_from_samples(a2, bits) ^ 0xA5A5A5A5A5A5A5A5
    seed1 |= (1 << (bits - 1))
    seed2 |= (1 << (bits - 1))
    p = nextprime(seed1)
    q = nextprime(seed2)
    if p == q:
        q = nextprime(seed2 + 1234567)
    return p, q

def prepare_display_data(audio_int16, target_len=DISPLAY_LEN):
    if audio_int16 is None or len(audio_int16) == 0:
        x_new = np.linspace(0, 1, target_len)
        return x_new, np.zeros(target_len)
    display = audio_int16.astype(np.float32) / 32768.0
    window_size = 5
    if len(display) >= window_size:
        kernel = np.ones(window_size) / window_size
        display = np.convolve(display, kernel, mode='same')
    x_orig = np.linspace(0, 1, len(display))
    x_new = np.linspace(0, 1, target_len)
    display = np.interp(x_new, x_orig, display)
    display = display * 0.5
    return x_new, display

def write_snapshot_txt(path, fields):
    lines = []
    lines.append("=== Encryptor snapshot ===")
    lines.append(f"timestamp_utc: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}")
    lines.append("")
    if fields.get("rsa_private_pem"):
        lines.append("----- RSA PRIVATE KEY (PEM) -----")
        lines.append(fields["rsa_private_pem"].strip())
        lines.append("")
    if fields.get("rsa_public_pem"):
        lines.append("----- RSA PUBLIC KEY (PEM) -----")
        lines.append(fields["rsa_public_pem"].strip())
        lines.append("")
    lines.append("----- KEYS & CT (hex/base64) -----")
    lines.append(f"aes_base_key_hex: {fields.get('aes_base_key_hex','')}")
    lines.append(f"rsa_enc_session_key_b64: {fields.get('rsa_enc_session_key_b64','')}")
    lines.append(f"rsa_enc_plain_b64: {fields.get('rsa_enc_plain_b64','')}")
    lines.append(f"salt_hex: {fields.get('salt_hex','')}")
    lines.append(f"final_aes_key_hex: {fields.get('final_aes_key_hex','')}")
    lines.append(f"aes_nonce_b64: {fields.get('aes_nonce_b64','')}")
    lines.append(f"aes_tag_b64: {fields.get('aes_tag_b64','')}")
    lines.append(f"ciphertext_base64: {fields.get('ciphertext_base64','')}")
    lines.append("")
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[APPENDED] Snapshot written to {path}")

# ========== Main ==========
latest_frame = np.zeros(LIVE_CHUNK, dtype=np.int16)

def live_callback(indata, frames, time_info, status):
    global latest_frame
    latest_frame = indata[:, 0].copy()

def main():
    parser = argparse.ArgumentParser(description="Encryptor: RSA-OAEP (session key) + AES-GCM; audio-seeded RSA and AES base.")
    parser.add_argument("-o", "--output", help="Output TXT filename to append keys & ciphertext", type=str)
    parser.add_argument("--save-private", help="Save generated RSA private key PEM to file", type=str)
    parser.add_argument("-i", "--input", help="Plaintext from argument", type=str)
    parser.add_argument("-I", "--input-file", help="File containing plaintext", type=str)
    args = parser.parse_args()

    user_plaintexts = None
    if args.input is not None:
        user_plaintexts = [args.input]
    elif args.input_file is not None:
        try:
            with open(args.input_file, "r", encoding="utf-8") as f:
                content = f.read()
            if not content:
                print(f"Input file {args.input_file} is empty. Exiting.")
                return
            CHUNK_SIZE = 2048
            chunks = [content[i:i+CHUNK_SIZE] for i in range(0, len(content), CHUNK_SIZE)]
            user_plaintexts = chunks
            if not user_plaintexts:
                print(f"Input file {args.input_file} contains no data. Exiting.")
                return
        except Exception as ex:
            print(f"Failed to read input file {args.input_file}:", ex)
            return

    if user_plaintexts is None:
        user_plaintexts = [input("Masukkan pesan rahasia yang akan dienkripsi: ")]

    input("Ready? Press ENTER to start recording RSA/AES seed from microphone. Press ENTER again to stop.")
    print("Recording... speak into mic, then press ENTER to finish seed recording.")
    seed_audio = record_until_enter(SAMPLE_RATE, SEED_CHUNK)
    if seed_audio.size == 0:
        print("No seed audio captured. Exiting.")
        return

    print("Generating RSA primes from audio seed...")
    p, q = generate_primes_from_audio(seed_audio, bits=KEY_BITS_PER_PRIME)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    d = inverse(RSA_E, phi_n)
    try:
        priv_pem = RSA.construct((n, RSA_E, d, p, q)).export_key()
        pub_pem = RSA.construct((n, RSA_E)).publickey().export_key()
    except Exception as ex:
        print("RSA construct/export failed:", ex)
        priv_pem = None
        pub_pem = None

    print(f"Generated RSA modulus n with bit-length: {n.bit_length()}")

    aes_base_key = hashlib.sha256(seed_audio.tobytes()).digest()
    audio_fingerprint = hashlib.sha256(seed_audio.tobytes()).digest()

    if args.save_private and priv_pem is not None:
        with open(args.save_private, "wb") as f:
            f.write(priv_pem)
        print(f"[SAVED] RSA private key -> {args.save_private}")

    stream = sd.InputStream(samplerate=SAMPLE_RATE, channels=1, dtype='int16',
                            blocksize=LIVE_CHUNK, callback=live_callback)
    stream.start()

    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(10, 3), facecolor='#0b0b0b')
    ax.set_facecolor('#0b0b0b')
    ax.axis('off')
    ax.set_xlim(0, 2 * np.pi)
    ax.set_ylim(-1.2, 1.2)

    segments_collection = None
    glow_line, = ax.plot([], [], linewidth=12, alpha=0.06, color='white')
    main_line, = ax.plot([], [], linewidth=2, alpha=1.0, color='white')
    info_txt = ax.text(0.01, 0.03, "", transform=ax.transAxes, fontsize=10, color='#f6f6f6',
                       bbox=dict(facecolor='black', alpha=0.4, pad=4))

    last_encrypt_time = 0.0
    last_b64 = ""
    last_snapshot = None
    current_plain_idx = 0

    def update(_frame_idx):
        nonlocal segments_collection, glow_line, main_line, last_encrypt_time, last_b64, last_snapshot, current_plain_idx

        y_raw = latest_frame
        if y_raw is None:
            y_raw = np.zeros(LIVE_CHUNK, dtype=np.int16)
        x_disp, y_disp = prepare_display_data(y_raw, target_len=DISPLAY_LEN)
        x_vals = x_disp * (2 * np.pi)

        points = np.array([x_vals, y_disp]).T.reshape(-1, 1, 2)
        segments = np.concatenate([points[:-1], points[1:]], axis=1)
        if segments_collection is not None:
            segments_collection.remove()

        norm = mpl.colors.Normalize(vmin=0, vmax=DISPLAY_LEN)
        cmap = ListedColormap(NEON_COLORS)
        segments_collection = LineCollection(segments, cmap=cmap, norm=norm, linewidths=3, alpha=1.0)
        segments_collection.set_array(np.linspace(0, DISPLAY_LEN, len(segments)))
        ax.add_collection(segments_collection)

        glow_line.set_data(x_vals, y_disp)
        main_line.set_data(x_vals, y_disp)
        info_txt.set_text(("Last CT (base64):\n" + (last_b64[:60] + '...' if last_b64 else '(none)')))

        now = time.time()
        if (now - last_encrypt_time) >= ENCRYPT_INTERVAL:
            last_encrypt_time = now
            try:
                salt = hashlib.sha256(y_raw.tobytes()).digest()
                final_aes_key = hashlib.sha256(aes_base_key + salt).digest()

                current_plaintext = user_plaintexts[current_plain_idx]
                current_plain_idx = (current_plain_idx + 1) % len(user_plaintexts)

                rsa_enc_session_key_b64 = ""
                rsa_enc_plain_b64 = ""
                nonce_b64 = ""
                tag_b64 = ""
                ciphertext = b""
                # attempt hybrid RSA+AES (preferred)
                try:
                    if pub_pem is None:
                        raise RuntimeError("No public key available for OAEP encrypt.")
                    # 1) generate session key
                    session_key = os.urandom(32)
                    # 2) RSA-OAEP encrypt session key
                    pub_obj = RSA.import_key(pub_pem)
                    oaep = PKCS1_OAEP.new(pub_obj, hashAlgo=SHA256)
                    rsa_ct_key = oaep.encrypt(session_key)
                    rsa_enc_session_key_b64 = base64.b64encode(rsa_ct_key).decode()
                    # 3) AES-GCM encrypt plaintext with session_key and audio_fingerprint as AAD
                    nonce = os.urandom(12)
                    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
                    cipher.update(audio_fingerprint)
                    ciphertext, tag = cipher.encrypt_and_digest(current_plaintext.encode())
                    last_b64 = base64.b64encode(ciphertext).decode()
                    nonce_b64 = base64.b64encode(nonce).decode()
                    tag_b64 = base64.b64encode(tag).decode()
                    rsa_enc_plain_b64 = "(n/a - hybrid mode)"
                except Exception as ex_hybrid:
                    # hybrid failed; fallback to encrypt with final_aes_key (deterministic per-frame)
                    try:
                        # use final_aes_key for AES-GCM
                        nonce = os.urandom(12)
                        cipher = AES.new(final_aes_key, AES.MODE_GCM, nonce=nonce)
                        cipher.update(audio_fingerprint)
                        ciphertext, tag = cipher.encrypt_and_digest(current_plaintext.encode())
                        last_b64 = base64.b64encode(ciphertext).decode()
                        nonce_b64 = base64.b64encode(nonce).decode()
                        tag_b64 = base64.b64encode(tag).decode()
                        rsa_enc_session_key_b64 = "(fallback)"
                        rsa_enc_plain_b64 = "(fallback - encrypted with final_aes_key)"
                    except Exception as ex_fallback:
                        # everything failed: as last resort store plaintext base64 so snapshot isn't empty
                        try:
                            last_b64 = base64.b64encode(current_plaintext.encode()).decode()
                        except Exception:
                            last_b64 = ""
                        rsa_enc_session_key_b64 = "(failed)"
                        rsa_enc_plain_b64 = "(failed)"
                        nonce_b64 = ""
                        tag_b64 = ""

                # debug prints (kept)
                print("\n=== DEBUG KEYS ===")
                if priv_pem is not None:
                    try:
                        print("rsa_private_pem:\n", priv_pem.decode())
                    except Exception:
                        print("rsa_private_pem: (binary)")
                else:
                    print("rsa_private_pem: (not available)")
                print("generated sound seed:", seed_audio)
                print("rsa_public_pem:\n", pub_pem.decode() if pub_pem is not None else "(none)")
                print("aes_base_key_hex:", aes_base_key.hex())
                print("rsa_enc_session_key_b64:", rsa_enc_session_key_b64)
                print("rsa_enc_plain_b64:", rsa_enc_plain_b64)
                print("salt_hex:", salt.hex())
                print("final_aes_key_hex:", final_aes_key.hex())
                print("aes_nonce_b64:", nonce_b64)
                print("aes_tag_b64:", tag_b64)
                print("==================\n")

                print(f"[{time.strftime('%H:%M:%S')}] Ciphertext (Base64): {last_b64}")

                if args.output:
                    out_fields = {
                        "rsa_private_pem": priv_pem.decode() if isinstance(priv_pem, (bytes, bytearray)) else str(priv_pem),
                        "rsa_public_pem": pub_pem.decode() if isinstance(pub_pem, (bytes, bytearray)) else str(pub_pem),
                        "aes_base_key_hex": aes_base_key.hex(),
                        "rsa_enc_session_key_b64": rsa_enc_session_key_b64,
                        "rsa_enc_plain_b64": rsa_enc_plain_b64,
                        "salt_hex": salt.hex(),
                        "final_aes_key_hex": final_aes_key.hex(),
                        "aes_nonce_b64": nonce_b64,
                        "aes_tag_b64": tag_b64,
                        "ciphertext_base64": last_b64
                    }
                    write_snapshot_txt(args.output, out_fields)
                    last_snapshot = args.output

            except Exception as ex:
                print("Encryption error:", ex, file=sys.stderr)

        return [segments_collection, glow_line, main_line, info_txt]

    from matplotlib.animation import FuncAnimation
    ani = FuncAnimation(fig, update, interval=30, blit=True)

    print("Showing synthwave waveform window. Close the window to finish.")
    plt.show()

    stream.stop()
    stream.close()
    print("Done. Last snapshot file:", last_snapshot if last_snapshot else "(none)")

if __name__ == "__main__":
    main()
