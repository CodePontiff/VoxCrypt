#!/usr/bin/env python3
"""
VOXCRYPT - Secure Live Audio Encryption Tool

Features:
- Voice-seeded RSA key generation
- Real-time AES encryption with audio-derived salts
- Cyberpunk visualization
- Supports text/files/binary data
- Finalize with Enter key or window close
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
from matplotlib.animation import FuncAnimation
import matplotlib as mpl
from sympy import nextprime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import inverse
import os
import json
from mimetypes import guess_type

# ========== CYBERPUNK VISUAL CONFIG ==========
CYBER_COLORS = {
    'pink': '#ff00ff',
    'blue': '#00ffff',
    'purple': '#9d00ff',
    'cyan': '#00ffcc',
    'yellow': '#fff000'
}

WAVE_GRADIENT = [
    '#ff00ff', '#ff00a2', '#9d00ff',
    '#00ffff', '#00ffcc', '#00a2ff'
]

BG_COLOR = '#0a0a12'
GRID_COLOR = '#1a1a2a55'
TEXT_COLOR = '#e0e0ff'
GLOW_ALPHA = 0.15

# ========== CRYPTO CONFIG ==========
SAMPLE_RATE = 44100
SEED_CHUNK = 1024
LIVE_CHUNK = 1024
DISPLAY_LEN = 1024
KEY_BITS = 256
RSA_E = 65537
SMOOTHING = 15
MIN_RMS = 0.01
MIN_PEAK = 0.04

# ========== GLOBAL STATE ==========
latest_frame = np.zeros(LIVE_CHUNK, dtype=np.int16)
current_aes_key = None
current_salt = None
current_salt_src = "(none)"
encryption_done = False
chunk_obj = None
last_ciphertext_b64 = ""
last_salt_hex = ""
user_finalized = False
window_closed = False
base_name = "message"
fig = None
ax = None

def get_file_type(filename):
    """Determine file type based on extension"""
    if not filename:
        return "text"
    ext = os.path.splitext(filename)[1].lower()
    if ext in ['.txt', '.json', '.csv', '.xml', '.html']:
        return 'text'
    elif ext in ['.png', '.jpg', '.jpeg', '.bmp', '.gif']:
        return 'image'
    elif ext in ['.pdf', '.docx', '.xlsx', '.pptx']:
        return 'document'
    return 'binary'

def read_file_content(filepath):
    """Read file content based on its type"""
    filetype = get_file_type(filepath)
    if filetype == 'text':
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read().encode('utf-8')
    else:
        with open(filepath, 'rb') as f:
            return f.read()

def record_until_enter(fs=SAMPLE_RATE, chunk=SEED_CHUNK):
    """Record microphone until ENTER is pressed"""
    print("\n»» INITIALIZING AUDIO CAPTURE ««")
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
    finally:
        stream.stop()
    return np.concatenate(audio_chunks).astype('int16') if audio_chunks else np.array([], dtype='int16')

def make_seed_from_samples(samples, key_bits=KEY_BITS):
    """Generate cryptographic seed from audio"""
    mean = float(np.mean(samples)) if samples.size > 0 else 0.0
    rms = float(np.sqrt(np.mean(samples.astype(np.float64)**2))) if samples.size > 0 else 0.0
    trig_val = abs(math.sin(mean) * math.cos(rms))
    h = hashlib.sha512(samples.tobytes()).digest()
    h_int = int.from_bytes(h, 'big')
    scale = (1 << (key_bits - 16))
    trig_int = int(trig_val * scale)
    return (h_int ^ (trig_int << (len(h) * 8 // 4))) | (1 << (key_bits - 1))

def generate_primes_from_audio(audio, bits=KEY_BITS):
    """Generate RSA primes from audio features"""
    L = len(audio)
    a1 = audio[0: max(1, L // 8)]
    a2 = audio[L // 2 : L // 2 + max(1, L // 8)]
    seed1 = make_seed_from_samples(a1, bits)
    seed2 = make_seed_from_samples(a2, bits) ^ 0xA5A5A5A5A5A5A5A5
    seed1 |= (1 << (bits - 1))
    seed2 |= (1 << (bits - 1))
    p, q = nextprime(seed1), nextprime(seed2)
    return (p, q) if p != q else (p, nextprime(seed2 + 1234567))

def encrypt_metadata(metadata, rsa_key):
    """Encrypt metadata using RSA-derived AES key"""
    key_material = rsa_key.export_key('DER')
    aes_key = hashlib.sha256(key_material).digest()
    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(metadata).encode('utf-8'))
    return {
        'nonce': nonce,
        'tag': tag,
        'ciphertext': ciphertext
    }

def setup_cyberpunk_display():
    """Initialize cyberpunk-styled plot"""
    global fig, ax
    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(12, 4), facecolor=BG_COLOR)
    ax.set_facecolor(BG_COLOR)
    ax.grid(color=GRID_COLOR, linestyle='--', alpha=0.7)
    ax.tick_params(colors=TEXT_COLOR)
    
    for spine in ax.spines.values():
        spine.set_edgecolor(CYBER_COLORS['purple'])
        spine.set_linewidth(1.5)
        spine.set_alpha(0.8)
    
    ax.set_xlim(0, 2 * np.pi)
    ax.set_ylim(-1.5, 1.5)
    
    for y in [-1, 0, 1]:
        ax.axhline(y, color=CYBER_COLORS['blue'], linestyle=':', alpha=0.2)
    
    return fig, ax

def colorize_waveform(y_values):
    """Assign cyberpunk colors based on amplitude"""
    colors = []
    for y in y_values:
        if y > 0.8: colors.append(WAVE_GRADIENT[0])
        elif y > 0.5: colors.append(WAVE_GRADIENT[1])
        elif y > 0.2: colors.append(WAVE_GRADIENT[2])
        elif y > -0.2: colors.append(WAVE_GRADIENT[3])
        elif y > -0.5: colors.append(WAVE_GRADIENT[4])
        else: colors.append(WAVE_GRADIENT[5])
    return colors

def prepare_display_data(audio_int16, target_len=DISPLAY_LEN):
    """Prepare audio data for visualization"""
    if not audio_int16.size:
        return np.linspace(0, 1, target_len), np.zeros(target_len)
    
    display = audio_int16.astype(np.float32) / 32768.0
    if len(display) >= SMOOTHING:
        kernel = np.ones(SMOOTHING) / SMOOTHING
        display = np.convolve(display, kernel, mode='same')
    x_new = np.linspace(0, 1, target_len)
    return x_new, np.interp(x_new, np.linspace(0, 1, len(display)), display) * 0.8

def frame_has_voice(frame_i16: np.ndarray) -> bool:
    """Detect if audio frame contains voice"""
    if frame_i16.size == 0:
        return False
    f = frame_i16.astype(np.float32) / 32768.0
    return (np.sqrt(np.mean(f * f)) >= MIN_RMS) or (np.max(np.abs(f)) >= MIN_PEAK)

def live_callback(indata, frames, time_info, status):
    """Live audio callback for continuous key updates"""
    global latest_frame, current_aes_key, current_salt, current_salt_src, user_finalized
    
    latest_frame = indata[:, 0].copy()
    
    if frame_has_voice(latest_frame):
        current_salt = hashlib.sha256(latest_frame.tobytes()).digest()
        current_salt_src = "mic-voice"
    else:
        current_salt = b""
        current_salt_src = "rsa-static"
    
    if hasattr(live_callback, 'rsa_static_key'):
        current_aes_key = hashlib.sha256(live_callback.rsa_static_key + current_salt).digest() if current_salt else live_callback.rsa_static_key

def on_close(event):
    """Handle encryption finalization and window closing"""
    global chunk_obj, encryption_done, last_ciphertext_b64, last_salt_hex, window_closed
    
    if not encryption_done:
        try:
            if args.input:
                data = args.input.encode('utf-8')
            elif args.input_file:
                data = read_file_content(args.input_file)
            else:
                raise ValueError("No input provided")

            session_key = os.urandom(32)
            oaep = PKCS1_OAEP.new(rsa_pub_obj, hashAlgo=SHA256)
            rsa_ct_key = oaep.encrypt(session_key)
            nonce = os.urandom(12)
            cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            cipher.update(audio_fingerprint)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            last_ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
            last_salt_hex = current_salt.hex() if current_salt else "static_key"
            
            chunk_obj = {
                "mode": "hybrid",
                "salt_src": current_salt_src,
                "rsa_enc_session_key": rsa_ct_key.hex(),
                "aes_nonce": nonce.hex(),
                "aes_tag": tag.hex(),
                "ciphertext": ciphertext.hex()
            }
            
            print("\n▓▓▓ ENCRYPTION SUMMARY ▓▓▓")
            print(f"» SALT: {last_salt_hex[:16]}...")
            print(f"» CIPHERTEXT: {last_ciphertext_b64[:64]}...")
            print(f"» KEY SOURCE: {current_salt_src}")
            print(f"» OUTPUT FILE: {base_name}.vxc")
            
            encryption_done = True
        except Exception as ex:
            print(f"[!] ENCRYPTION FAILED: {ex}")
    
    window_closed = True
    plt.close()

def update_cyber_visual(_frame_idx):
    """Update the cyberpunk visualization"""
    global user_finalized
    
    # Check for Enter key press
    if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
        _ = sys.stdin.readline()
        user_finalized = True
        on_close(None)
        return []
    
    x_disp, y_disp = prepare_display_data(latest_frame, DISPLAY_LEN)
    x_vals = x_disp * (2 * np.pi)
    
    segments = np.array([x_vals, y_disp]).T.reshape(-1, 1, 2)
    segments = np.concatenate([segments[:-1], segments[1:]], axis=1)
    
    if hasattr(update_cyber_visual, 'segments'):
        update_cyber_visual.segments.remove()
    
    colors = colorize_waveform(y_disp)
    
    update_cyber_visual.segments = LineCollection(
        segments,
        colors=colors,
        linewidths=3,
        alpha=0.9,
        linestyle='-',
        antialiased=True
    )
    
    update_cyber_visual.glow.set_data(x_vals, y_disp)
    ax.add_collection(update_cyber_visual.segments)
    
    status = [
        f"▓▓▓ ENCRYPTION PROTOCOL ACTIVE ▓▓▓",
        f"» SALT: {current_salt.hex()[:12]}..." if current_salt else "» SALT: [SYSTEM DEFAULT]",
        f"» KEY SOURCE: {current_salt_src.upper()}",
        f"» STATUS: {'RECORDING...' if not encryption_done else 'ENCRYPTION COMPLETE'}"
    ]
    
    if encryption_done:
        status.extend([
            "",
            "▓▓▓ MISSION SUMMARY ▓▓▓",
            f"» CIPHERTEXT: {last_ciphertext_b64[:24]}...",
            f"» OUTPUT: {base_name}.vxc"
        ])
    
    info_txt.set_text("\n".join(status))
    
    return [update_cyber_visual.segments, update_cyber_visual.glow, info_txt]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="▓ VOXCRYPT CYBERPUNK ENCRYPTOR ▓")
    parser.add_argument("-i", "--input", help="Input text", type=str)
    parser.add_argument("-I", "--input-file", help="Input file", type=str)
    parser.add_argument("-k", "--key", help="Key output file", type=str, default="key.pem")
    args = parser.parse_args()

    if not args.input and not args.input_file:
        print("[!] ERROR: No input specified")
        sys.exit(1)

    if args.input_file and not os.path.exists(args.input_file):
        print(f"[!] ERROR: File not found - {args.input_file}")
        sys.exit(1)

    base_name = os.path.splitext(os.path.basename(args.input_file))[0] if args.input_file else "message"

    print("▓▓▓ PRESS ENTER TO BEGIN AUDIO CAPTURE ▓▓▓")
    input()
    seed_audio = record_until_enter()
    if seed_audio.size == 0:
        print("[!] ERROR: No audio captured")
        sys.exit(1)

    p, q = generate_primes_from_audio(seed_audio)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    d = inverse(RSA_E, phi_n)
    rsa_key = RSA.construct((n, RSA_E, d, p, q))
    pub_pem = rsa_key.publickey().export_key()
    priv_pem = rsa_key.export_key()
    rsa_pub_obj = RSA.import_key(pub_pem)

    try:
        with open(args.key, "wb") as f:
            f.write(priv_pem)
        print(f"» KEY SAVED: {args.key}")
    except Exception as e:
        print(f"[!] ERROR SAVING KEY: {e}")
        sys.exit(1)

    audio_fingerprint = hashlib.sha256(seed_audio.tobytes()).digest()
    live_callback.rsa_static_key = hashlib.sha256(n.to_bytes((n.bit_length() + 7) // 8, "big")).digest()

    fig, ax = setup_cyberpunk_display()
    update_cyber_visual.glow, = ax.plot([], [], 
        color=CYBER_COLORS['blue'],
        linewidth=18,
        alpha=GLOW_ALPHA
    )
    
    info_txt = ax.text(
        0.02, 0.95,
        "INITIALIZING ENCRYPTION SEQUENCE...",
        transform=ax.transAxes,
        fontsize=10,
        fontfamily='monospace',
        color=CYBER_COLORS['cyan'],
        verticalalignment='top'
    )
    
    fig.suptitle(
        '»» VOXCRYPT ENCRYPTOR TERMINAL ««',
        color=CYBER_COLORS['pink'],
        fontsize=14,
        fontweight='bold',
        fontfamily='monospace'
    )
    
    fig.canvas.mpl_connect('close_event', on_close)

    stream = None
    try:
        stream = sd.InputStream(
            samplerate=SAMPLE_RATE, 
            channels=1, 
            dtype='int16',
            blocksize=LIVE_CHUNK, 
            callback=live_callback
        )
        stream.start()

        ani = FuncAnimation(
            fig, 
            update_cyber_visual, 
            interval=20, 
            blit=True,
            cache_frame_data=False
        )
        
        print("\n▓▓▓ LIVE ENCRYPTION ACTIVE - PRESS ENTER TO FINALIZE ▓▓▓")
        plt.show()
        
    except Exception as e:
        print(f"[!] VISUALIZATION ERROR: {e}")
    finally:
        if stream is not None:
            try:
                stream.stop()
                stream.close()
            except Exception as e:
                print(f"[!] ERROR STOPPING AUDIO: {e}")

    if chunk_obj:
        try:
            encrypted_metadata = encrypt_metadata({
                "aad_scheme": "audio_fingerprint_plus_salt",
                "aad_base_hex": audio_fingerprint.hex(),
                "chunk_cipher": "AES-256-GCM",
                "cipher_chunks": [chunk_obj]
            }, rsa_key)

            public_metadata = {
                "vxc_version": 3,
                "rsa_public_pem": pub_pem.decode(),
                "file_metadata": {
                    "original_name": os.path.basename(args.input_file) if args.input_file else "message.txt",
                    "file_type": get_file_type(args.input_file) if args.input_file else "text",
                    "mime_type": guess_type(args.input_file)[0] if args.input_file else "text/plain"
                }
            }

            with open(f"{base_name}.vxc", "wb") as f:
                f.write(b'VXC3')
                f.write(encrypted_metadata['nonce'])
                f.write(encrypted_metadata['tag'])
                f.write(encrypted_metadata['ciphertext'])
                f.write(b'\x00\x00\x00\x00')
                public_json = json.dumps(public_metadata).encode('utf-8')
                f.write(len(public_json).to_bytes(4, 'big'))
                f.write(public_json)

            print("\n▓▓▓ OPERATION COMPLETE ▓▓▓")
            print(f"» ENCRYPTED OUTPUT: {base_name}.vxc")
            print(f"» KEY FILE: {args.key}")
            print(f"» FILE SIZE: {os.path.getsize(f'{base_name}.vxc')} bytes")
            print("▓▓▓ END TRANSMISSION ▓▓▓")
            
        except Exception as e:
            print(f"[!] OUTPUT ERROR: {e}")
