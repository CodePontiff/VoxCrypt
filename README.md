
---

# 🎤 VoxCrypt Audio-Seeded RSA + AES-GCM Encryptor/Decryptor

**VoxCrypt Audio-Seeded RSA + AES-GCM** is an experimental encryption tool that combines cryptography with real-time audio processing.
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

| Option       | Description                                                           |
| ------------ | --------------------------------------------------------------------- |
| `input_file` | output file to decrypt                                                |
| `--first`    | Decrypts only the first output                                        |
| `--last`     | Decrypts only the last line of output file                            |
| `--all`      | Merges all snapshots into one output, removing duplicate text         |

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

##Note:Sound input device problem may occur 

---

## 📜 License

This project is released for educational and research purposes. Do **NOT** use in production or for securing sensitive data.


---
Sample:
input text:
```
python voxcrypt_encryptor.py -i "test vox_crypt" -o output_short.txt

```
<img width="601" height="29" alt="image" src="https://github.com/user-attachments/assets/d85910bb-06d6-42a8-ace1-211a469d9375" />

process text:
<img width="976" height="705" alt="image" src="https://github.com/user-attachments/assets/b20ee8ef-5740-4b7e-a1b7-9540b4b3ba7b" />

output text:
```
python voxcrypt_decryptor.py output_short.txt --all 
```

<img width="471" height="65" alt="image" src="https://github.com/user-attachments/assets/6c6f6169-1060-4b19-bc8e-5ee79caee8df" />

---

input file:
```
python voxcrypt_encryptor.py -I loremipsum.txt -o output_long.txt 

```
<img width="598" height="25" alt="image" src="https://github.com/user-attachments/assets/dbfdf358-28e7-4af8-a9f4-360308e53e5d" />



process file:
<img width="1079" height="712" alt="image" src="https://github.com/user-attachments/assets/a1a15ab8-fb01-489e-b2bb-6f163ce1edbd" />


output file:
```
python voxcrypt_decryptor.py output_long.txt --all    
```

<img width="786" height="196" alt="image" src="https://github.com/user-attachments/assets/b4ddce9d-f247-4b12-9aae-3bfb6a6f3c98" />


---
