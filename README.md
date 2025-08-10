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
python voxcrypt_encryptor.py -i "Secret message" -o key.txt
```

### **Encrypt from a text file**

```bash
python voxcrypt_encryptor.py -I message.txt -o key.txt
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
Sample:
input:
<img width="630" height="30" alt="image" src="https://github.com/user-attachments/assets/675f843d-aca1-4600-8674-f1b69da1340a" />

process:
<img width="914" height="704" alt="image" src="https://github.com/user-attachments/assets/b24e4c0b-88c7-479f-9dc5-f19d57b4adc7" />

output:
<img width="449" height="73" alt="image" src="https://github.com/user-attachments/assets/a64d4f8d-f529-4adf-b122-17567c355fa0" />



