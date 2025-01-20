# Import necessary libraries for building the web application and securing data
from flask import Flask, request, jsonify  # Flask for creating the web server and handling requests
import bcrypt  # bcrypt for password hashing and secure password verification
from Crypto.Cipher import AES  # AES from pycryptodome for lightweight encryption and decryption
from Crypto.Random import get_random_bytes  # Random byte generator for generating encryption keys
from fuzzyextractor import FuzzyExtractor  # For privacy-preserving biometric data verification
import time  # Time module to track timestamps for brute force prevention

# Initialize Flask application
app = Flask(__name__)

# In-memory database (for demonstration purposes)
users_db = {}  # To store registered user credentials and biometric data
retry_tracker = {}  # To track login retries and prevent brute force attacks

# Constants for brute force prevention
MAX_RETRIES = 3  # Maximum allowed retries before blocking the user
BLOCK_TIME = 300  # Block duration in seconds (5 minutes)

# Function to hash passwords securely using bcrypt
def hash_password(password: str) -> str:
    """
    Hashes the provided plain-text password using bcrypt to ensure it is securely stored.
    This function also generates a salt for added security.

    Parameters:
        password (str): The user's plain-text password.

    Returns:
        str: The hashed password with salt.
    """
    salt = bcrypt.gensalt()  # Generate a cryptographic salt to make the hash unique
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)  # Hash the password with the salt
    return hashed

# Function to verify a plain-text password against a stored hashed password
def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verifies a plain-text password against the hashed password stored in the database.

    Parameters:
        password (str): The user's plain-text password.
        hashed_password (str): The hashed password stored in the database.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

# AES encryption function to securely encrypt sensitive data
def encrypt_data(data: str, key: bytes) -> bytes:
    """
    Encrypts sensitive data using AES encryption in EAX mode, which provides both confidentiality
    and integrity of the data.

    Parameters:
        data (str): The plain-text data to encrypt.
        key (bytes): The symmetric AES key for encryption.

    Returns:
        bytes: The encrypted data, including nonce, tag, and ciphertext.
    """
    cipher = AES.new(key, AES.MODE_EAX)  # Create AES cipher with EAX mode
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))  # Encrypt the data and generate an integrity tag
    return cipher.nonce + tag + ciphertext  # Combine nonce, tag, and ciphertext for secure transmission

# AES decryption function to decrypt data encrypted with AES
def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """
    Decrypts AES-encrypted data and verifies its integrity using the provided key.

    Parameters:
        encrypted_data (bytes): The encrypted data, including nonce, tag, and ciphertext.
        key (bytes): The symmetric AES key for decryption.

    Returns:
        str: The decrypted plain-text data.
    """
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]  # Extract nonce, tag, and ciphertext
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)  # Create AES cipher for decryption using the nonce
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')  # Decrypt the data and verify its integrity

# Function to check if a user is temporarily blocked due to too many retries
def is_user_blocked(username: str) -> bool:
    """
    Checks if a user is currently blocked due to exceeding the maximum retry limit.

    Parameters:
        username (str): The username to check.

    Returns:
        bool: True if the user is blocked, False otherwise.
    """
    if username in retry_tracker:
        retry_info = retry_tracker[username]
        if retry_info['attempts'] >= MAX_RETRIES:
            time_since_last_attempt = time.time() - retry_info['last_attempt']
            if time_since_last_attempt < BLOCK_TIME:
                return True  # User is still blocked
            else:
                # Reset retry tracker if block time has elapsed
                retry_tracker[username] = {'attempts': 0, 'last_attempt': None}
    return False

# Function to log a failed attempt and block the user if necessary
def log_failed_attempt(username: str):
    """
    Logs a failed login attempt for a user. If the maximum retries are exceeded,
    the user is temporarily blocked.

    Parameters:
        username (str): The username of the user who failed the login attempt.
    """
    if username not in retry_tracker:
        retry_tracker[username] = {'attempts': 0, 'last_attempt': None}  # Initialize tracker for new user
    retry_tracker[username]['attempts'] += 1  # Increment the number of failed attempts
    retry_tracker[username]['last_attempt'] = time.time()  # Update the timestamp of the last failed attempt

# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    """
    Handles user registration by storing their credentials (username, hashed password, smart card,
    and biometric data) securely in the database.
    """
    data = request.get_json()  # Get registration details from the request
    username = data['username']
    password = data['password']
    smart_card = data['smart_card']
    biometric = data['biometric']

    # Check if the username already exists
    if username in users_db:
        return jsonify({"message": "Username already exists"}), 400

    # Store the user's credentials in the database
    hashed_password = hash_password(password)  # Hash the password before storing
    users_db[username] = {
        "password": hashed_password,
        "smart_card": smart_card,
        "biometric": biometric
    }
    return jsonify({"message": "User registered successfully"}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    """
    Handles user login by verifying the username and password. Tracks login attempts
    to prevent brute force attacks.
    """
    data = request.get_json()  # Get login details from the request
    username = data['username']
    password = data['password']

    # Check if the user is currently blocked
    if is_user_blocked(username):
        return jsonify({"message": "Too many failed attempts. User temporarily blocked."}), 403

    # Verify if the username exists
    if username not in users_db:
        return jsonify({"message": "User not found"}), 400

    # Verify the password
    stored_data = users_db[username]
    if not verify_password(password, stored_data['password']):
        log_failed_attempt(username)  # Log the failed attempt
        return jsonify({"message": "Invalid password"}), 400

    # Reset the retry tracker on successful login
    if username in retry_tracker:
        retry_tracker[username] = {'attempts': 0, 'last_attempt': None}

    return jsonify({"message": "Login successful"}), 200

# Authentication endpoint
@app.route('/authenticate', methods=['POST'])
def authenticate():
    """
    Authenticates a user based on their username, password, smart card, and biometric data.
    """
    data = request.get_json()
    username = data['username']
    password = data['password']
    smart_card = data['smart_card']
    biometric = data['biometric']

    if is_user_blocked(username):
        return jsonify({"message": "Too many failed attempts. User temporarily blocked."}), 403

    if username not in users_db:
        return jsonify({"message": "User not found"}), 400

    stored_data = users_db[username]
    if not verify_password(password, stored_data['password']):
        log_failed_attempt(username)
        return jsonify({"message": "Invalid password"}), 400

    if smart_card != stored_data['smart_card']:
        return jsonify({"message": "Smart card mismatch"}), 400

    extractor = FuzzyExtractor()
    if not extractor.verify(biometric, stored_data['biometric']):
        return jsonify({"message": "Biometric mismatch"}), 400

    # Generate a shared session key
    key = get_random_bytes(16)
    encrypted_key = encrypt_data("Shared session key", key)

    return jsonify({"message": "Authentication successful", "shared_key": encrypted_key.hex()}), 200

# Run the Flask application
if __name__ == "__main__":
    app.run(debug=True, host="192.168.100.43", port=5000)
