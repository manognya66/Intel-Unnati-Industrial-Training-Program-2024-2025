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

def derive_key_from_passphrase(passphrase: str, salt: bytes, length: int):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def hash_passphrase(passphrase: str):
    return hashlib.sha256(passphrase.encode()).digest()

# Encryption function
def encrypt_file_inplace(input_file: str, passphrase: str):
    dek_salt = generate_salt()
    dek = os.urandom(AES_KEY_SIZE)
    kek_salt = generate_salt()
    kek = derive_key_from_passphrase(passphrase, kek_salt, AES_KEY_SIZE)

    aesgcm = AESGCM(kek)
    dek_nonce = os.urandom(NONCE_SIZE)
    encrypted_dek = aesgcm.encrypt(dek_nonce, dek, None)

    file_nonce = os.urandom(NONCE_SIZE)
    with open(input_file, 'rb') as f:
        data = f.read()
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(file_nonce, data, None)

    passphrase_hash = hash_passphrase(passphrase)

    with open(input_file, 'wb') as f:
        f.write(dek_salt + kek_salt + dek_nonce + encrypted_dek + passphrase_hash + file_nonce + ciphertext)
    
    # Return debug information
    return dek_salt, kek_salt, dek_nonce, encrypted_dek, passphrase_hash, file_nonce, ciphertext

# Decryption function
def decrypt_file_inplace(input_file: str, passphrase: str):
    try:
        with open(input_file, 'rb') as f:
            dek_salt = f.read(SALT_SIZE)
            kek_salt = f.read(SALT_SIZE)
            dek_nonce = f.read(NONCE_SIZE)
            encrypted_dek = f.read(AES_KEY_SIZE + 16)
            stored_passphrase_hash = f.read(32)
            file_nonce = f.read(NONCE_SIZE)
            ciphertext = f.read()

        provided_passphrase_hash = hash_passphrase(passphrase)
        if provided_passphrase_hash != stored_passphrase_hash:
            raise ValueError("Passphrase does not match.")

        kek = derive_key_from_passphrase(passphrase, kek_salt, AES_KEY_SIZE)

        aesgcm = AESGCM(kek)
        dek = aesgcm.decrypt(dek_nonce, encrypted_dek, None)

        aesgcm = AESGCM(dek)
        plaintext = aesgcm.decrypt(file_nonce, ciphertext, None)

        with open(input_file, 'wb') as f:
            f.write(plaintext)
        
        # Debugging
        return dek_salt, kek_salt, dek_nonce, encrypted_dek, stored_passphrase_hash, file_nonce, ciphertext, plaintext

    except Exception as e:
        print("Decryption failed:", str(e))
        raise

# Brute-force recovery function
def brute_force_decrypt(input_file: str, charset: str, max_length: int, update_callback=None):
    def attempt_decrypt(input_file, passphrase):
        try:
            result = decrypt_file_inplace(input_file, passphrase)
            return True, result
        except Exception:
            return False, None

    for length in range(1, max_length + 1):
        for attempt in product(charset, repeat=length):
            passphrase = ''.join(attempt)
            if update_callback:
                update_callback(passphrase)
            print(f"Trying passphrase: {passphrase}")
            success, result = attempt_decrypt(input_file, passphrase)
            if success:
                print(f"Passphrase found: {passphrase}")
                return passphrase, result
    print("Passphrase not found.")
    return None, None
