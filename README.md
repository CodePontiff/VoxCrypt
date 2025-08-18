
---

#🎤 VOXCRYPT

Secure Hybrid Encryption Powered by Voice Biometrics

VOXCRYPT is an advanced cryptographic system that fuses real-time audio processing. The system generates RSA-2048 keys from voice entropy and implements AES-256-GCM with dynamic salt values derived from live microphone input.

## 🔐 Core Cryptographic Process
```

1.Voice-Seeded Key Generation

2.Records 1024-sample audio chunks to create prime numbers

3.Uses SHA-512 hashing of audio frames with trigonometric mixing

4.Implements RSA with 65537 exponent and provable primes

5.Continuous Key Reinforcement

6.Live audio input modifies AES-GCM salt values

7.Voice-activated mode increases entropy during speech

8.Silent periods fall back to static RSA-derived keys

9.Secure Container Format

10.Combines encrypted payload with public metadata

11.Uses dual-layer encryption (RSA-OAEP + AES-GCM)

12.Includes audio fingerprint in AAD for tamper detection
```

## 🌐 Operational Features

    Universal Input Support (text/files/binary)

    Cyberpunk Visualization with real-time waveform analysis

    Self-contained Packages (.vxc container + .pem key)

    Cross-platform Python implementation

## ⚠️ Recommended Use Cases

    Secure voice memo encryption

    Experimental cryptography research

    Audio-based key generation studies

    Cybersecurity education demonstrations

---

## 🌟 Features

- 🎙️ **Voice-Activated Key Generation** - Uses microphone input to seed cryptographic keys
- 🔐 **Hybrid Encryption** - Combines RSA-2048 and AES-256-GCM for maximum security
- 🖥 **Cyberpunk Visualization** - Real-time audio waveform with neon color gradients
- 📁 **Universal File Support** - Encrypts text, images, documents, and binary files
- 🎚️ **Live Audio Processing** - Continuously updates encryption parameters based on ambient sound
- 📦 **Self-Contained Packages** - Generates both `.vxc` encrypted files and `.pem` key files

## 🚀 Installation:
```
git clone https://github.com/CodePontiff/VoxCrypt/VoxCrypt.git
cd VoxCrypt
```
---
## 🎯 Usage
Basic Text Encryption:
```
python voxcrypt_encyptor.py -I secret_document.pdf -k mykey.pem
python voxcrypt_decryptor.py -i secret_document.vxc -k mykey.pem -o secret_document_decrypted.pdf

python voxcrypt_encryptor.py -i "test_123" -k text_key.pem
python voxcrypt_decryptor.py -i message.vxc -k text.pem -o text.txt
```
---

## During Operation:
```

1.Press ENTER to begin audio capture for key generation

2.Speak or make noise to create entropy

3.Close the visualization window to finalize encryption
```

## 📦 Output Files:
```
.vxc - Encrypted container (contains both ciphertext and public metadata)

.pem - Private key file (keep this secure!)
```

## ⚠️ Security Notes:
```

1.The audio seed is used only during initial key generation

2.Always destroy key files after use for sensitive material

3.For maximum security, use in a quiet environment
```

## 🛡️ Threat Model

Protects against:
```

1.Passive eavesdropping

2.Brute force attacks

3.Known plaintext attacks
```

Does not protect against:
```

1.Physical key compromise

2.Live memory analysis

3.Side-channel attacks on microphone
```
