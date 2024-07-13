import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from itertools import product

# Constants
AES_KEY_SIZE = 32  # AES-256 uses 32 bytes key
SALT_SIZE = 16     # Size of the salt
NONCE_SIZE = 12    # Size of the nonce for AESGCM
ITERATIONS = 100000  # Number of iterations for PBKDF2

# Utility functions
def generate_salt():
    return os.urandom(SALT_SIZE)

def derive_key_from_passphrase(passphrase: str, salt: bytes, key_size: int):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# Encryption function
def encrypt_file(input_file: str, passphrase: str):
    # Generate a random file encryption key
    file_encryption_key = os.urandom(AES_KEY_SIZE)

    # Encrypt the file using the file encryption key
    file_nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(file_encryption_key)
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    ciphertext = aesgcm.encrypt(file_nonce, plaintext, None)

    # Derive a key encryption key (KEK) from the passphrase
    kek_salt = generate_salt()
    kek = derive_key_from_passphrase(passphrase, kek_salt, AES_KEY_SIZE)

    # Encrypt the file encryption key using the KEK
    key_nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(kek)
    encrypted_file_encryption_key = aesgcm.encrypt(key_nonce, file_encryption_key, None)

    # Save the encrypted file and metadata
    with open(input_file, 'wb') as f:
        f.write(kek_salt + key_nonce + encrypted_file_encryption_key + file_nonce + ciphertext)

# Decryption function
def decrypt_file(input_file: str, passphrase: str):
    with open(input_file, 'rb') as f:
        kek_salt = f.read(SALT_SIZE)
        key_nonce = f.read(NONCE_SIZE)
        encrypted_file_encryption_key = f.read(AES_KEY_SIZE + 16)
        file_nonce = f.read(NONCE_SIZE)
        ciphertext = f.read()

    # Derive the key encryption key (KEK) from the passphrase
    kek = derive_key_from_passphrase(passphrase, kek_salt, AES_KEY_SIZE)

    # Decrypt the file encryption key using the KEK
    aesgcm = AESGCM(kek)
    file_encryption_key = aesgcm.decrypt(key_nonce, encrypted_file_encryption_key, None)

    # Decrypt the file using the file encryption key
    aesgcm = AESGCM(file_encryption_key)
    plaintext = aesgcm.decrypt(file_nonce, ciphertext, None)

    # Save the decrypted file
    with open(input_file, 'wb') as f:
        f.write(plaintext)

# Brute-force recovery function
def brute_force_decrypt(input_file: str, charset: str, max_length: int, update_callback=None):
    def attempt_decrypt(passphrase):
        try:
            decrypt_file(input_file, passphrase)
            return True
        except Exception:
            return False

    for length in range(1, max_length + 1):
        for attempt in product(charset, repeat=length):
            passphrase = ''.join(attempt)
            if update_callback:
                update_callback(passphrase)
            if attempt_decrypt(passphrase):
                return passphrase, passphrase
    return None, None
