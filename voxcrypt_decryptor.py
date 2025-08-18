#!/usr/bin/env python3
"""
VoxCrypt Decryptor - Secure Live Audio Decryption Tool
"""
import argparse
import json
import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

def decrypt_metadata(encrypted_data, rsa_key):
    """Decrypt metadata with additional validation"""
    try:
        key_material = rsa_key.export_key('DER')
        aes_key = hashlib.sha256(key_material).digest()
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=encrypted_data['nonce'])
        
        # Split ciphertext and tag if needed
        if isinstance(encrypted_data['ciphertext'], str):
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            tag = base64.b64decode(encrypted_data['tag'])
        else:
            ciphertext = encrypted_data['ciphertext']
            tag = encrypted_data['tag']
            
        return json.loads(cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8'))
    except ValueError as e:
        print(f"[!] Metadata integrity check failed: {e}")
        return None
    except Exception as e:
        print(f"[!] Metadata decryption error: {e}")
        return None

def decrypt_content(encrypted_chunk, rsa_key, aad_hex=None):
    """Decrypt content with enhanced error handling"""
    try:
        # Convert hex strings to bytes if needed
        def to_bytes(data):
            if isinstance(data, str):
                return bytes.fromhex(data)
            return data
            
        # RSA decrypt session key
        cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        enc_session_key = to_bytes(encrypted_chunk['rsa_enc_session_key'])
        session_key = cipher_rsa.decrypt(enc_session_key)
        
        # AES decrypt content
        cipher_aes = AES.new(
            session_key,
            AES.MODE_GCM,
            nonce=to_bytes(encrypted_chunk['aes_nonce'])
        )
        
        # Add Additional Authenticated Data if present
        if aad_hex:
            cipher_aes.update(to_bytes(aad_hex))
            
        ciphertext = to_bytes(encrypted_chunk['ciphertext'])
        tag = to_bytes(encrypted_chunk['aes_tag'])
        
        # Verify and decrypt
        decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)
        
        # Handle padding if needed (for CBC mode fallback)
        if encrypted_chunk.get('mode') == 'cbc':
            decrypted = unpad(decrypted, AES.block_size)
            
        return decrypted
        
    except ValueError as e:
        print("\n[!] Critical: MAC Verification Failed")
        print("Possible causes:")
        print("- Incorrect private key")
        print("- Corrupted ciphertext")
        print("- Tampered data")
        print("- Incorrect AAD (Additional Authenticated Data)")
        print(f"\nTechnical details: {e}")
        return None
        
    except Exception as e:
        print(f"[!] Decryption error: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Enhanced Secure VoxCrypt Decryptor")
    parser.add_argument("-i", "--input", help="Input .vxc file", required=True)
    parser.add_argument("-k", "--key", help="RSA private key file", required=True)
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--force", help="Attempt decryption even with errors", action="store_true")
    args = parser.parse_args()

    # Key loading with validation
    try:
        with open(args.key, 'rb') as f:
            key_content = f.read()
            rsa_key = RSA.import_key(key_content)
    except Exception as e:
        print(f"[!] Key loading failed: {e}")
        return

    # File reading with structure validation
    try:
        with open(args.input, 'rb') as f:
            magic = f.read(4)
            if magic != b'VXC3':
                print(f"[!] Invalid file format (got {magic}, expected VXC3)")
                if not args.force:
                    return
                
            nonce = f.read(12)
            tag = f.read(16)
            remaining = f.read()
            
            parts = remaining.split(b'\x00\x00\x00\x00')
            if len(parts) < 2:
                print("[!] File structure invalid")
                if not args.force:
                    return
                
            public_len = int.from_bytes(parts[1][:4], 'big')
            public_metadata = json.loads(parts[1][4:4+public_len].decode('utf-8'))
            
            encrypted_metadata = {
                'nonce': nonce,
                'tag': tag,
                'ciphertext': parts[0]
            }
    except Exception as e:
        print(f"[!] File reading failed: {e}")
        return

    # Metadata decryption
    metadata = decrypt_metadata(encrypted_metadata, rsa_key)
    if not metadata:
        print("[!] Metadata decryption failed - cannot proceed")
        return

    # Content decryption
    if not metadata.get('cipher_chunks'):
        print("[!] No encrypted chunks found")
        return
        
    decrypted = decrypt_content(
        metadata['cipher_chunks'][0],
        rsa_key,
        metadata.get('aad_base_hex')
    )
    
    if not decrypted:
        print("[!] Content decryption failed")
        return

    # Output handling
    output_path = args.output
    if not output_path:
        original_name = public_metadata['file_metadata']['original_name']
        output_path = f"decrypted_{original_name}"

    try:
        file_type = public_metadata['file_metadata']['file_type']
        mode = 'wb' if file_type != 'text' else 'w'
        content = decrypted if file_type != 'text' else decrypted.decode('utf-8')
        
        with open(output_path, mode) as f:
            f.write(content)
            
        print(f"[+] Successfully decrypted to {output_path}")
        print(f"    File type: {file_type}")
        print(f"    Original name: {public_metadata['file_metadata']['original_name']}")
        
    except Exception as e:
        print(f"[!] Output write failed: {e}")

if __name__ == "__main__":
    main()
