import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from cryptography.hazmat.backends import default_backend  # Fix: Added import

# Encrypt data
def encrypt_data(data, key):
    nonce = os.urandom(12)  # 96-bit nonce
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce, ciphertext

# Example Usage
key = os.urandom(32)  # ChaCha20 requires a 256-bit key
data = b"Sensitive Data"
nonce, encrypted_data = encrypt_data(data, key)

print(f"Nonce: {nonce.hex()}")
print(f"Encrypted Data: {encrypted_data.hex()}")

def decrypt_data(ciphertext, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# Example Usage
decrypted_data = decrypt_data(encrypted_data, key, nonce)
print(f"Decrypted Data: {decrypted_data.decode()}")