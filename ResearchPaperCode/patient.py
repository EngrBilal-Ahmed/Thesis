import hashlib  # For generating secure hashes of data
import random  # For generating random values like r1, r2 used in biometric verification
#from trusted_server import registration  # Import the registration function from the trusted server
#from medical_server import medical_server_authentication  # Import the authentication function from the medical server
import time  # For simulating real-time delays in processing
import requests  # For making HTTP requests to the trusted and medical servers
import psutil  # For monitoring system resources (CPU and memory usage)

# Simple hash function using hashlib for SHA256 hashing
def simple_hash(data):
    """
    Generates a SHA-256 hash for a given input 'data'.
	This function generates a SHA-256 hash for a given input 'data'.
    The hash is generated by encoding the input and using the hashlib library to perform the hash.
    This is commonly used for password protection, data integrity, and creating unique keys.	

    Parameters:
    data (str): The input data to hash.

    Returns:
    str: The SHA-256 hash of the input data.
    """
    return hashlib.sha256(data.encode()).hexdigest()

# Hamming Distance function to compare two binary strings
def hamming_distance(str1, str2):
    """
    Calculates the Hamming distance between two equal-length strings.
    If the strings are not of equal length, returns -1.

    Parameters:
    str1 (str): The first binary string.
    str2 (str): The second binary string.

    Returns:
    int: The Hamming distance, or -1 if lengths are unequal.
    """
    # Ensure both strings are of equal length, otherwise return -1
    if len(str1) != len(str2):
        return -1  # Return -1 if the strings are not the same length
    return sum(el1 != el2 for el1, el2 in zip(str1, str2))  # Count differing bits

# Random number generator for creating random integers
def generate_random():
    """
    Generates a random integer between 1 and 100,000.

    Returns:
    int: A random integer.
    """
    return random.randint(1, 100000)


# Simulating a user database with login attempts
users_db = {
    "patient1": {
        "password": simple_hash("password123"),  # Hashed password
        "biometric_data": "biometric_template_data",  # Simulated biometric data
        "login_attempts": 0  # Track login attempts
    },
    "patient2": {
        "password": simple_hash("password123"),
        "biometric_data": "another_biometric_template_data",
        "login_attempts": 0
    }
}

# Max login attempts before account is locked
MAX_LOGIN_ATTEMPTS = 3

def monitor_resources():
    """
    Logs the current CPU and memory usage of the system.
    This function helps to analyze the resource consumption of the application.
    """
    print(f"CPU Usage: {psutil.cpu_percent()}%")
    print(f"Memory Usage: {psutil.virtual_memory().percent}%")

# Patient Login Phase - Login & Authentication using Hamming Distance
def login(IDi, pwi, biometric_data, smart_card, threshold=200):  # Increased threshold for Hamming distance tolerance
    """
    This function simulates the login process for the patient. The login involves:
    - Validating credentials (username and password)
    - Checking biometric data using Hamming distance
    - Generating an authentication message (Authut) based on the login credentials and biometric data.

    Parameters:
    IDi (str): Patient's identity (ID).
    pwi (str): Patient's password.
    biometric_data (str): The patient's biometric data (e.g., fingerprint, iris scan).
    smart_card (dict): The smart card data containing credentials and encryption keys.
    threshold (int): The Hamming distance threshold for biometric verification.

    Returns:
    str: The Authut (authentication message) if successful, or None if authentication fails.
    """
    # Monitor system resources at the start of the function
    monitor_resources()

    # Check if the user has exceeded the max login attempts
    if users_db[IDi]["login_attempts"] >= MAX_LOGIN_ATTEMPTS:
        print(f"Account locked due to too many failed login attempts for user: {IDi}")
        return None  # Account locked, do not proceed

    print("\nLogin Phase:")

    # Measure the execution time of biometric processing
    start_time = time.time()

    # Step 1: Process biometric data to get a hash (convert to binary)
    hbio_result = simple_hash(biometric_data)  # Simulate biohashing of the biometric data

    # Store the original biometric data (Bir) from the smart card
    Bir = hbio_result + str(smart_card['r1'])  # Combine biometric data hash with random number (r1)

    # Step 2: Convert the stored Bir and inputted biometric data to binary strings
    stored_bir_binary = ''.join(format(ord(c), '08b') for c in Bir)  # Convert the stored biometric to a binary string
    input_bio_binary = ''.join(
        format(ord(c), '08b') for c in hbio_result)  # Convert inputted biometric to binary string

    # Print lengths of the binary strings for debugging purposes
    print(f"Stored Biometric (Binary): {stored_bir_binary}")
    print(f"Input Biometric (Binary): {input_bio_binary}")
    print(f"Length of stored binary: {len(stored_bir_binary)}")
    print(f"Length of input binary: {len(input_bio_binary)}")

    # Step 3: Pad binary strings to the same length
    max_len = max(len(stored_bir_binary), len(input_bio_binary))  # Find the maximum length
    stored_bir_binary = stored_bir_binary.zfill(max_len)  # Pad with leading zeros if needed
    input_bio_binary = input_bio_binary.zfill(max_len)  # Pad input data to match length

    print(f"Stored Biometric (Padded): {stored_bir_binary}")
    print(f"Input Biometric (Padded): {input_bio_binary}")

    # Step 4: Calculate Hamming Distance
    dist = hamming_distance(stored_bir_binary, input_bio_binary)  # Calculate the Hamming distance

    # If the Hamming distance is above the threshold, consider the match failed
    # Log the biometric verification time
    print(f"Biometric processing time: {time.time() - start_time:.6f} seconds")

    if dist == -1 or dist > threshold:
        print(f"Biometric check failed. Hamming distance: {dist}")
        users_db[IDi]["login_attempts"] += 1  # Increment the login attempt counter for failed attempt
        print(f"Login attempts for {IDi}: {users_db[IDi]['login_attempts']}")
        return None  # Return None if the biometric check fails

    print(f"Biometric check passed. Hamming distance: {dist}")

    # Reset login attempts after successful authentication
    users_db[IDi]["login_attempts"] = 0

    # Recompute HPW and P
    HPW = simple_hash(IDi + pwi + hbio_result)  # Recompute HPW based on ID, password, and biometric data
    P = simple_hash(HPW + Bir)  # Hash of HPW and biometric reference Bir

    # Generate authentication information
    m = generate_random()  # Random integer for session key generation
    print(f"Generated random number in Patient (m): {m}")
    Ai = simple_hash(IDi + str(m) + "IDm") + P  # Combining the random integer and the patient ID
    X1 = simple_hash(IDi + smart_card["Cut"] + Ai) + str(m)  # Final authentication information

    # Print out variables that will be used in generating the authentication message
    print(f"Generated Ai: {Ai}")
    print(f"Generated X1: {X1}")
    print(f"Generated HPW: {HPW}")
    print(f"Generated P: {P}")

    # Modify the Authut construction to match medical server expectation
    # Construct the Authut with Ni, IDi, and Cut
    Authut = simple_hash(f"{smart_card['Ni']}{IDi}{smart_card['Cut']}")

    print(f"Generated Authut: {Authut}")

    # Reset login attempts after successful authentication
    users_db[IDi]["login_attempts"] = 0  # Reset the login attempt counter after a successful login
    return Authut  # Return the authentication message (Authut)

    # Monitor system resources after processing
    monitor_resources()

    return Authut # Return the authentication message (Authut)

# Main Simulation Function
def main():
    """
    Main function to simulate the registration, login, and authentication phases.
    It calls the trusted server for registration, then performs the login process, and finally
    sends the Authut to the medical server for verification.
    """
    IDi = "patient1"
    pwi = "password123"
    biometric_data = "biometric_template_data"  # Placeholder for the biometric template

    # Step 1: Registration with the Trusted Server
    print("\nContacting the Trusted Server for Registration...")
    start_time = time.time()

    registration_url = "http://127.0.0.1:5000/register" # Trusted server's registration endpoint
    registration_data = {
        "IDi": IDi,
        "pwi": pwi,
        "biometric_data": biometric_data
    }
    response = requests.post(registration_url, json=registration_data)

    if response.status_code != 200:
        print(f"Failed to register: {response.text}")
        return
    smart_card = response.json()  # Receive smart card data from the trusted server
    print("Smart Card Data received:", smart_card)

    print(f"Registration time: {time.time() - start_time:.6f} seconds")

    # Step 2: Login
    print("\nStarting the Login Phase...")
    Authut = login(IDi, pwi, biometric_data, smart_card)
    if not Authut:
        print("Login failed.")
        return

    # Step 3: Authentication with the Medical Server
    print("\nContacting the Medical Server for Authentication...")
    authentication_url = "http://127.0.0.1:5001/authenticate"  # Medical server's authentication endpoint
    authentication_data = {
        "Authut": Authut,
        "smart_card": smart_card,
        "IDi": IDi
    }

    start_time = time.time()
    response = requests.post(authentication_url, json=authentication_data)

    if response.status_code == 200:
        session_key = response.json().get("session_key")
        print(f"Authentication successful. Session Key: {session_key}")
    else:
        print(f"Authentication failed: {response.text}")

    print(f"Authentication time: {time.time() - start_time:.6f} seconds")

# Start the simulation when the script is executed
if __name__ == "__main__":
    main()
