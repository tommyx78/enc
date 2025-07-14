"""
File Encryption and Decryption Script using Password-Based Key Derivation

This script allows you to securely encrypt and decrypt files using a password.
It uses PBKDF2 (Password-Based Key Derivation Function 2) with a random salt 
and AES-based symmetric encryption (via Fernet) for strong protection.

Author: Tommaso Palo
Email: tommaso.palo@gmail.com
"""

import os
import sys
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from getpass import getpass

# Deriva una chiave da password e salt
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Cripta il file
def encrypt_file(filepath: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(filepath, 'rb') as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)

    # Scrive salt + encrypted
    with open(filepath + ".enc", 'wb') as f:
        f.write(salt + encrypted_data)

    print(f"File '{filepath}' crypted as '{filepath}.enc'.")

# Decripta il file
def decrypt_file(filepath: str, password: str):
    with open(filepath, 'rb') as f:
        content = f.read()

    salt = content[:16]
    encrypted_data = content[16:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        print("Incorrect password or corrupted file.")
        return

    output_file = filepath.replace(".enc", ".dec")

    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

    print(f"File '{filepath}' decrypted as '{output_file}'.")

# CLI usage
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Use:")
        print("  python3 enc.py e <file>")
        print("  python3 enc.py d <file.enc>")
        sys.exit(1)

    command = sys.argv[1]
    filepath = sys.argv[2]

    if not os.path.isfile(filepath):
        print(f"File '{filepath}' not found.")
        sys.exit(1)

    password = getpass("Insert Password: ")

    if command == "e":
        encrypt_file(filepath, password)
    elif command == "d":
        decrypt_file(filepath, password)
    else:
        print("Comando non valido. Usa 'e' o 'd'.")
