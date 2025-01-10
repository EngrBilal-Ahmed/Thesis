import hashlib
import os
import random

# -------------------------------
# Phase 1: Registration Phase
# -------------------------------
# Users register with their ID, password, and biometric data (hashed for security)
def register_user(user_id, password, biometric_data):
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.sha256(password.encode() + salt).hexdigest()
    hashed_biometric = hashlib.sha256(biometric_data.encode()).hexdigest()
    user_db[user_id] = {
        "salt": salt,
        "hashed_password": hashed_password,
        "hashed_biometric": hashed_biometric
    }
    print(f"User {user_id} registered successfully!")

# -------------------------------
# Phase 2: Login Phase
# -------------------------------
# Users provide their ID, password, and biometric data for authentication
def login_user(user_id, password, biometric_data):
    if user_id not in user_db:
        print("User ID not found.")
        return False

    salt = user_db[user_id]["salt"]
    expected_hashed_password = user_db[user_id]["hashed_password"]
    provided_hashed_password = hashlib.sha256(password.encode() + salt).hexdigest()

    expected_hashed_biometric = user_db[user_id]["hashed_biometric"]
    provided_hashed_biometric = hashlib.sha256(biometric_data.encode()).hexdigest()

    if provided_hashed_password == expected_hashed_password and provided_hashed_biometric == expected_hashed_biometric:
        print("Login successful!")
        return True
    else:
        print("Login failed. Incorrect credentials.")
        return False

# -------------------------------
# Phase 3: Authentication and Key Agreement Phase
# -------------------------------
# Establish a session key using a simple Diffie-Hellman key exchange
class DiffieHellman:
    def __init__(self):
        self.private_key = random.randint(1, 100)
        self.public_key = pow(5, self.private_key, 23)  # Using small prime numbers for simplicity

    def compute_shared_key(self, other_public_key):
        return pow(other_public_key, self.private_key, 23)

# Example usage of the phases
if __name__ == "__main__":
    user_db = {}  # In-memory user database

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

        print(f"Alice's shared key: {alice_shared_key}")
        print(f"Bob's shared key: {bob_shared_key}")

        # Verify that both keys are the same
        if alice_shared_key == bob_shared_key:
            print("Secure session established!")
        else:
            print("Key exchange failed.")