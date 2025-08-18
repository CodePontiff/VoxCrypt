# 🎤 VOXCRYPT
**Secure Hybrid Encryption Powered by Voice Biometrics**

VOXCRYPT is an experimental cryptographic system that fuses **real-time audio processing** with **hybrid encryption**.  
It generates **RSA-2048 keys** from voice entropy and implements **AES-256-GCM** with dynamic salt values derived from live microphone input.

---

## 🔐 Core Cryptographic Process
1. **Voice-Seeded Key Generation**
   - Records 1024-sample audio chunks to create prime numbers  
   - Uses SHA-512 hashing of audio frames with trigonometric mixing  
   - Implements RSA with 65537 exponent and provable primes  

2. **Continuous Key Reinforcement**
   - Live audio input modifies AES-GCM salt values  
   - Voice-activated mode increases entropy during speech  
   - Silent periods fall back to static RSA-derived keys  

3. **Secure Container Format**
   - Combines encrypted payload with public metadata  
   - Uses dual-layer encryption (RSA-OAEP + AES-GCM)  
   - Includes audio fingerprint in AAD for tamper detection  

---

## 🌐 Operational Features
- ✅ Universal input support (text, files, binary)  
- 🎛 Cyberpunk visualization with real-time waveform analysis  
- 📦 Self-contained packages (`.vxc` container + `.pem` key)  

---

## 🌟 Features
- 🎙 **Voice-Activated Key Generation** → Microphone input as entropy source  
- 🔐 **Hybrid Encryption** → RSA-2048 + AES-256-GCM  
- 🖥 **Cyberpunk Visualization** → Neon gradient waveform display  
- 📁 **Universal File Support** → Text, images, documents, audio, binary  
- 🎚 **Live Audio Processing** → Continuously updates encryption parameters  
- 📦 **Self-Contained Packages** → Generates both `.vxc` encrypted files and `.pem` keys  

---

## 🚀 Installation
```
git clone https://github.com/CodePontiff/VoxCrypt.git
cd VoxCrypt
pip install -r requirements.txt

🔧 Options:

Encryptor

-i, --input         -> Input text
-I, --input-file    -> Input file (.png, .jpg, .mp3, .pdf, .txt, etc)
-k, --key           -> Key output file, example: -k key.pem
--replace-original  -> Replace original file with encrypted version (files only)

Decryptor

-i, --input   -> Input .vxc file (encrypted file)
-k, --key     -> Key file produced during encryption
-o, --output  -> Output of decryption, example: -o image.jpg
--force       -> Force decryption attempt, even with errors
```

🎯 Usage

Basic File Encryption

python voxcrypt_encryptor.py -I secret_document.pdf -k mykey.pem
python voxcrypt_decryptor.py -i secret_document.vxc -k mykey.pem -o secret_document_decrypted.pdf

Basic Text Encryption

python voxcrypt_encryptor.py -i "test_123" -k text_key.pem
python voxcrypt_decryptor.py -i message.vxc -k text.pem -o text.txt

🎙 During Operation

    1.Press ENTER to begin audio capture for key generation

    2.Speak or make noise to create entropy

    3.Press Enter to finalize encryption

📦 Output Files

    .vxc → Encrypted container (ciphertext + metadata)

    .pem → Private key file (⚠️ keep this secure!)

⚠️ Security Notes

    Audio seed is used only during initial key generation

    Always destroy key files after use for sensitive material

    For maximum security, use in a quiet environment

🛡 Threat Model

Protects against:

    1.Passive eavesdropping

    2.Brute force attacks

    3.Known plaintext attacks

Does not protect against:

    1.Physical key compromise

    2.Live memory analysis

    3.Side-channel microphone attacks

📷 Screenshot

Sounds On:

<img width="1191" height="615" alt="image" src="https://github.com/user-attachments/assets/027539a0-0b4e-47e9-b76b-e8ff04e4eb79" />

Sounds Off:

<img width="1203" height="647" alt="image" src="https://github.com/user-attachments/assets/ff691f27-4cc6-4305-b5de-a53d25d0638b" />




