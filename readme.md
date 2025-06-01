# Encrypted Notepad

A simple and secure encrypted notepad/diary for protecting your personal notes using strong cryptography.  
This project was built for local use, focused on privacy and protecting sensitive files.

---

## Features

- Text editor with a user-friendly graphical interface (Tkinter)
- **AES-256-CBC** encryption of all saved notes, with password protection
- Secure password-based key derivation (PBKDF2-HMAC-SHA256, 1 million iterations, random salt)
- Each encryption uses a unique salt and IV for extra security
- Files are stored as base64-encoded blobs (safe for text storage and easy to share, if needed)
- Automatic edit lock on encrypted files to prevent accidental changes
- Supports opening, editing, encrypting, decrypting, and saving notes

---

## How It Works

1. **Write your note:** Use the editor as you would any notepad.
2. **Encrypt:** Use the “Encrypt Text” menu option to encrypt your note with a password of your choice. The content is turned into unreadable text using strong encryption.
3. **Save:** Save your encrypted file. Only someone with the correct password can decrypt it.
4. **Open/Decrypt:** When opening an encrypted file, the editor will prompt for your password to decrypt and allow editing.

---

## Technical Details

- **Language:** Python 3
- **GUI:** Tkinter (built-in with Python)
- **Encryption:**  
  - Algorithm: **AES-256** (CBC mode)
  - Padding: **PKCS7**
  - Key Derivation: **PBKDF2-HMAC-SHA256**  
    - 1,000,000 iterations  
    - 16-byte random salt  
    - Key size: 32 bytes (256 bits)
  - IV: 16 bytes, random per encryption
- **File Format:**  
  Encrypted files store data as base64-encoded blobs with the following structure:
  [status (1 byte)] + [salt (16 bytes)] + [IV (16 bytes)] + [ciphertext (variable size)]

- `status`: 0x01 for encrypted, 0x00 for plain text
- `salt`: needed to derive the key from your password
- `IV`: required to decrypt with CBC mode
- `ciphertext`: the encrypted note
- **Security Notes:**  
- The password is never saved or transmitted—only you know it.
- PBKDF2 with a high iteration count slows down brute-force attacks.
- Each encryption operation uses fresh salt and IV for maximum security.
- There is **no password recovery**. If you lose your password, your data cannot be decrypted.


---

## Installation

1. Make sure you have Python 3 installed.
2. Install dependencies:
 ```bash
 pip install -r requirements.txt