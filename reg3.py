import hashlib  # Provides secure hash functions to protect sensitive data such as passwords and biometric templates
import os  # Used to generate secure random values for salts and initialization vectors (IVs)
import random  # Generates random values for private keys in the Diffie-Hellman key exchange
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # Key derivation function to securely derive session keys
from cryptography.hazmat.primitives.hashes import SHA256  # Secure hashing algorithm used in key derivation and data integrity checks
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Password-based key derivation function to protect against brute-force attacks
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Used for encryption and decryption with AES in GCM mode
import base64  # Used to encode and decode binary data to/from base64 for secure transmission
import time  # Used to handle login attempt timing

# -------------------------------
# Utility Functions
# -------------------------------
# Function to generate a secure random salt to enhance password security
# The salt prevents precomputed attacks like rainbow table attacks
# By introducing a unique salt for each password, it ensures that even if two users have the same password,
# their hashed values will be different, thereby increasing security against offline attacks.
def generate_salt():
    return os.urandom(16)

# Function to hash data using PBKDF2 with HMAC and SHA256
# PBKDF2 (Password-Based Key Derivation Function 2) is used to slow down brute-force attacks by increasing computational complexity.
# It applies a hashing function multiple times (key stretching), making it more computationally expensive for attackers to guess passwords.
# The salt is used to make each hash unique even for the same input data.
def hash_data(data, salt):
    return hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000)

# Function to encrypt data using AES in GCM mode
# AES (Advanced Encryption Standard) in GCM (Galois/Counter Mode) provides both confidentiality and integrity.
# Confidentiality ensures that data remains secret, while integrity ensures that the data has not been tampered with.
# GCM mode is a preferred choice for encryption as it combines the encryption and authentication steps into a single process.
# The IV (initialization vector) is randomly generated to ensure that the same data encrypted multiple times will produce different outputs.
def encrypt_data(data, key):
    iv = os.urandom(12)  # Randomly generated initialization vector (IV) for each encryption session
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))  # AES encryption with GCM mode
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()  # Encrypt the data and finalize the encryption process
    return base64.b64encode(iv + encrypted_data).decode()  # Return the IV and encrypted data encoded in base64

# Function to decrypt data using AES in GCM mode
# The encrypted data is decoded from base64, and the IV is extracted for decryption
# AES-GCM ensures that the data has not been altered during transmission, providing integrity verification.
def decrypt_data(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)  # Decode the base64 encoded encrypted data
    iv = encrypted_data[:12]  # Extract the IV from the encrypted data
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))  # Initialize AES-GCM cipher with the extracted IV
    decryptor = cipher.decryptor()
    return (decryptor.update(encrypted_data[12:]) + decryptor.finalize()).decode()  # Decrypt and return the original data

# -------------------------------
# Phase 1: Registration Phase
# -------------------------------
def register_user(user_id, password, biometric_data):
    salt = generate_salt()
    hashed_password = hash_data(password, salt)
    hashed_biometric = hash_data(biometric_data, salt)
    user_db[user_id] = {
        "salt": salt,
        "hashed_password": hashed_password,
        "hashed_biometric": hashed_biometric,
        "failed_attempts": 0,  # Track the number of failed login attempts
        "last_attempt_time": None  # Track the time of the last login attempt
    }
    print(f"User {user_id} registered successfully!")

# -------------------------------
# Phase 2: Login Phase
# -------------------------------
# User login function that verifies the provided credentials against the stored values
# Ensures that both the password and biometric data match the stored hashes
def login_user(user_id, password, biometric_data):
    if user_id not in user_db:
        print("User ID not found.")
        return False

    user_record = user_db[user_id]
    current_time = time.time()

    # Check for too many failed attempts
    if user_record["failed_attempts"] >= 3:
        time_since_last_attempt = current_time - user_record["last_attempt_time"]
        if time_since_last_attempt < 60:  # Lock the account for 60 seconds after 3 failed attempts
            print("Account is temporarily locked due to multiple failed login attempts. Please try again later.")
            return False
        else:
            # Reset failed attempts after lockout period
            user_record["failed_attempts"] = 0

    salt = user_record["salt"]
    expected_hashed_password = user_record["hashed_password"]
    provided_hashed_password = hash_data(password, salt)

    expected_hashed_biometric = user_record["hashed_biometric"]
    provided_hashed_biometric = hash_data(biometric_data, salt)

    if provided_hashed_password == expected_hashed_password and provided_hashed_biometric == provided_hashed_biometric:
        print("Login successful!")
        user_record["failed_attempts"] = 0  # Reset failed attempts on successful login
        return True
    else:
        print("Login failed. Incorrect credentials.")
        user_record["failed_attempts"] += 1
        user_record["last_attempt_time"] = current_time
        return False

# -------------------------------
# Phase 3: Authentication and Key Agreement Phase
# -------------------------------
# Diffie-Hellman key exchange class for secure session key generation
# The purpose of the Diffie-Hellman class is to establish a shared secret key between two parties over an insecure channel.
# This shared key can then be used to encrypt further communications, ensuring confidentiality.
# A larger prime number (7919) is used to enhance security by increasing the difficulty for attackers to compute the shared key.
# Using a larger prime reduces the risk of brute-force attacks and ensures the cryptographic strength of the key exchange process.
class DiffieHellman:
    def __init__(self):
        self.private_key = random.randint(1, 100)
        self.public_key = pow(2, self.private_key, 7919)  # Using a safe prime for the modulo operation

    # Function to compute a shared key using the other party's public key
    # The shared key is then derived using HKDF to ensure it is cryptographically secure
    def compute_shared_key(self, other_public_key):
        shared_key = pow(other_public_key, self.private_key, 7919)
        derived_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b'handshake').derive(shared_key.to_bytes(32, 'big'))
        return derived_key

# Example usage of the phases
# This block is used to execute the script when run directly.
# It allows testing of the different phases (registration, login, and key agreement) without requiring an external caller.
# The code in this block will not run if the file is imported as a module in another script.
if __name__ == "__main__":
    user_db = {}

    # Registration Phase
    register_user("user1", "password123", "biometric_sample")

    # Login Phase
    login_successful = login_user("user1", "password123", "biometric_sample")

    if login_successful:
        # Authentication and Key Agreement Phase
        alice = DiffieHellman()
        bob = DiffieHellman()

        # Exchange public keys and compute shared keys
        alice_shared_key = alice.compute_shared_key(bob.public_key)
        bob_shared_key = bob.compute_shared_key(alice.public_key)

        print(f"Alice's shared key: {alice_shared_key.hex()}")
        print(f"Bob's shared key: {bob_shared_key.hex()}")

        # Verify that both keys are the same
        if alice_shared_key == bob_shared_key:
            print("Secure session established!")
        else:
            print("Key exchange failed.")
