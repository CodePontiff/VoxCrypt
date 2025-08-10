Alright — here’s the complete **`README.md`** ready for GitHub, with the short intro at the top and the full English documentation after it.

---

# 🎤 Audio-Seeded RSA + AES-GCM Encryptor/Decryptor

**Audio-Seeded RSA + AES-GCM** is an experimental encryption tool that combines cryptography with real-time audio processing.
The RSA keypair is generated entirely from your voice, recorded through the microphone, while AES-256-GCM encryption uses continuously updated salt values derived from live audio input.

The program also features a **neon-style waveform display** of your voice in real time, and can save encryption “snapshots” containing the keys and ciphertext for later decryption.
It’s designed for demonstration, research, and educational purposes in the fields of audio signal processing and cryptography.

---

## ⚙️ Features & Options

### **Encryptor (`encryptor_oaep_gcm_append.py`)**

| Option                    | Description                                                             |
| ------------------------- | ----------------------------------------------------------------------- |
| `-i "text"`               | Encrypts the given text directly                                        |
| `-I file.txt`             | Encrypts a text file (automatically split into 2048-character chunks)   |
| `-o output.txt`           | Saves encryption snapshot (RSA key, AES key, nonce, ciphertext) to file |
| `--save-private file.pem` | Saves the generated RSA private key to a file                           |
| `--silent`                | Disables debug prints in CLI (still writes output to snapshot file)     |

🔹 *Note*: The RSA key is generated from the initial recorded seed audio. The AES salt is updated continuously from live microphone input during encryption.

---

### **Decryptor (`decryptor.py`)**

| Option       | Description                                                   |
| ------------ | ------------------------------------------------------------- |
| `input_file` | Snapshot file to decrypt                                      |
| `--first`    | Decrypts only the first snapshot                              |
| `--last`     | Decrypts only the last snapshot                               |
| `--all`      | Merges all snapshots into one output, removing duplicate text |

---

## 📦 Required Libraries

You can create a `requirements.txt` file:

```txt
numpy
sounddevice
matplotlib
sympy
pycryptodome
```

Install them all at once:

```bash
pip install -r requirements.txt
```

Or install individually:

```bash
pip install numpy sounddevice matplotlib sympy pycryptodome
```

---

## ▶️ Usage Examples

### **Encrypt from direct text**

```bash
python voxcrypt_encryptor.py -i "Secret message" -o snapshot.txt
```

### **Encrypt from a text file**

```bash
python voxcrypt_encryptor.py -I message.txt -o key.txt
```

### **Silent mode (no debug prints in CLI)**

```bash
python voxcrypt_encryptor.py -I message.txt -o snapshot.txt --silent
```

### **Decrypt the last snapshot**

```bash
python voxcrypt_decryptor.py snapshot.txt --last
```

### **Decrypt and merge all snapshots**

```bash
python voxcrypt_decryptor.py snapshot.txt --all
```

---

## 📜 License

This project is released for educational and research purposes. Do **NOT** use in production or for securing sensitive data.

---

If you want, I can also add **example screenshots** of the neon waveform and example encryption/decryption output so your GitHub repo looks more attractive.
Do you want me to prepare that too?
