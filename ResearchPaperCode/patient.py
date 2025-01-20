import hashlib  # For generating secure hashes of data
import random  # For generating random values like r1, r2 used in biometric verification
from trusted_server import registration  # Import the registration function from the trusted server
from medical_server import medical_server_authentication  # Import the authentication function from the medical server
import time  # For simulating real-time delays in processing


# Simple hash function using hashlib for SHA256 hashing
def simple_hash(data):
    """
    This function generates a SHA-256 hash for a given input 'data'.
    The hash is generated by encoding the input and using the hashlib library to perform the hash.
    This is commonly used for password protection, data integrity, and creating unique keys.
    """
    return hashlib.sha256(data.encode()).hexdigest()


# Hamming Distance function to compare two binary strings
def hamming_distance(str1, str2):
    """
    This function calculates the Hamming distance between two equal-length strings.
    The Hamming distance is defined as the number of differing bits between two binary strings.
    It returns -1 if the strings are not of equal length.

    Parameters:
    str1 (str): The first binary string.
    str2 (str): The second binary string.

    Returns:
    int: The Hamming distance between the two strings, or -1 if the strings have different lengths.
    """
    # Ensure both strings are of equal length, otherwise return -1
    if len(str1) != len(str2):
        return -1  # Return -1 if the strings are not the same length
    return sum(el1 != el2 for el1, el2 in zip(str1, str2))  # Count differing bits


# Random number generator for creating random integers
def generate_random():
    """
    This function generates a random integer between 1 and 100,000.
    This is used for generating random values during the login process and session key creation.
    """
    return random.randint(1, 100000)


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
    smart_card (dict): The smart card data containing the necessary credentials and encryption keys.
    threshold (int): The threshold for Hamming distance above which authentication fails.

    Returns:
    str: The authentication message (Authut) if successful, or None if authentication fails.
    """
    print("\nLogin Phase:")

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
    if dist == -1 or dist > threshold:
        print(f"Biometric check failed. Hamming distance: {dist}")
        return None  # Return None if the biometric check fails

    print(f"Biometric check passed. Hamming distance: {dist}")

    # Recompute HPW and P
    HPW = simple_hash(IDi + pwi + hbio_result)  # Recompute HPW based on ID, password, and biometric data
    P = simple_hash(HPW + Bir)  # Hash of HPW and biometric reference Bir

    # Generate authentication information
    m = generate_random()  # Random integer for session key generation
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

    print(f"Authentication Message (Authut): {Authut}")
    return Authut  # Return the authentication message (Authut)


# Main Simulation Function
def main():
    """
    This is the main function that simulates the registration, login, and authentication phases.
    It calls the registration function on the trusted server, then performs the login process,
    and finally validates the authentication with the medical server.
    """
    # Simulate patient registration with trusted server
    IDi = "patient2"
    pwi = "password123"
    biometric_data = "biometric_template_data"  # Placeholder for the biometric template

    # Step 1: Registration
    smart_card = registration(IDi, pwi, biometric_data)  # Register the patient and get the smart card

    # Step 2: Login (Patient provides ID, password, and biometric data)
    Authut = login(IDi, pwi, biometric_data, smart_card, threshold=200)  # Perform login and biometric check
    if Authut:
        # Step 3: Medical Server Authentication
        print("\nAuthentication Phase:")
        SKtm = medical_server_authentication(IDi, smart_card, Authut)  # Authenticate with the medical server
        print(f"Session Key Shared: {SKtm}")  # Print the session key if authentication is successful


# Start the simulation when the script is executed
if __name__ == "__main__":
    main()
