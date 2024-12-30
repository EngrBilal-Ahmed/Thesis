import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# Hashing the password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Encrypt biometric data using ChaCha20
def encrypt_data(data, key):
    nonce = os.urandom(12)  # 96-bit nonce
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce, ciphertext

# Derive a key from the password
def derive_key(password):
    salt = os.urandom(16)  # Random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return salt, key

# Example usage
password = "SecurePass123"
hashed_password = hash_password(password)

biometric_data = b"sample_biometric_data"  # Replace with actual biometric template bytes
salt, key = derive_key(password)
nonce, encrypted_biometric = encrypt_data(biometric_data, key)

print(f"Hashed Password: {hashed_password}")
print(f"Salt: {base64.b64encode(salt).decode()}")
print(f"Nonce: {base64.b64encode(nonce).decode()}")
print(f"Encrypted Biometric: {base64.b64encode(encrypted_biometric).decode()}")
