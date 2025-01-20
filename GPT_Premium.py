import hashlib
import os
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# --- Helper Functions ---

def generate_hash(data):
    """
    Generate a SHA-256 hash for the input data.

    Parameters:
    data (str): Input data to hash.

    Returns:
    str: Hexadecimal representation of the hash.
    """
    return hashlib.sha256(data.encode()).hexdigest()




def encrypt_data(key, data):
    """
    Encrypt data using AES encryption in CFB mode.

    Parameters:
    key (bytes): AES key for encryption.
    data (str): Plaintext data to encrypt.

    Returns:
    bytes: Encrypted data, including the initialization vector (IV) prepended.
    """
    iv = os.urandom(16)  # Generate a random initialization vector (16 bytes)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + encrypted  # Prepend IV for decryption


def decrypt_data(key, encrypted_data):
    """
    Decrypt data using AES encryption in CFB mode.

    Parameters:
    key (bytes): AES key for decryption.
    encrypted_data (bytes): Encrypted data, including the IV prepended.

    Returns:
    str: Decrypted plaintext data.
    """
    iv = encrypted_data[:16]  # Extract the initialization vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted.decode()

# --- Flask Server ---

class Server:
    """
    Represents the server responsible for handling authentication and key agreement.
    """
    def __init__(self):
        self.master_key = generate_hash("server_master_key")

    def authenticate_user(self, user_key):
        """
        Simulate server-side authentication by verifying the user key.

        Parameters:
        user_key (str): Key provided by the user for authentication.

        Returns:
        bool: True if authentication is successful, False otherwise.
        """
        return user_key == self.master_key

    def generate_session_key(self, user_key):
        """
        Generate a session key based on the user key.

        Parameters:
        user_key (str): Key provided by the user for authentication.

        Returns:
        str: Generated session key.
        """
        if self.authenticate_user(user_key):
            return generate_hash(user_key + "session")
        else:
            return None

# Instantiate server instance
server_instance = Server()

@app.route('/authenticate', methods=['POST'])
def authenticate():
    """
    Endpoint for user authentication and session key generation.
    """
    data = request.get_json()
    user_key = data.get('user_key')

    if not user_key:
        return jsonify({"error": "Missing user key."}), 400

    session_key = server_instance.generate_session_key(user_key)

    if session_key:
        return jsonify({"session_key": session_key}), 200
    else:
        return jsonify({"error": "Authentication failed."}), 401

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
