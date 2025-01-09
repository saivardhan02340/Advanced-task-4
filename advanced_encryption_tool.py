import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from base64 import b64encode, b64decode
import getpass

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate an AES-256 key from a password and a salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str):
    """Encrypt a file using AES-256."""
    backend = default_backend()
    salt = os.urandom(16)  # Generate a random salt
    key = generate_key(password, salt)

    iv = os.urandom(16)  # Initialization Vector for AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        data = f.read()

    # Pad the data to be a multiple of the block size (16 bytes)
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as f:
        f.write(salt + iv + encrypted_data)

    print(f"File encrypted successfully: {encrypted_file_path}")

def decrypt_file(file_path: str, password: str):
    """Decrypt a file encrypted with AES-256."""
    backend = default_backend()

    with open(file_path, "rb") as f:
        content = f.read()

    salt = content[:16]  # Extract the salt
    iv = content[16:32]  # Extract the Initialization Vector
    encrypted_data = content[32:]

    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    decrypted_file_path = file_path.replace(".enc", "")
    with open(decrypted_file_path, "wb") as f:
        f.write(data)

    print(f"File decrypted successfully: {decrypted_file_path}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Advanced Encryption Tool")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("file", help="File to encrypt or decrypt")

    args = parser.parse_args()

    password = getpass.getpass("Enter encryption password: ")

    if args.mode == "encrypt":
        encrypt_file(args.file, password)
    elif args.mode == "decrypt":
        decrypt_file(args.file, password)
