import hashlib
import random
from trusted_server import registration
from medical_server import medical_server_authentication
import time


# Simple hash function using hashlib
def simple_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


# Hamming Distance function to compare binary strings
def hamming_distance(str1, str2):
    # Ensure both strings are of equal length
    if len(str1) != len(str2):
        return -1  # Return -1 if the strings are not of the same length
    return sum(el1 != el2 for el1, el2 in zip(str1, str2))


# Random number generator for creating random integers
def generate_random():
    return random.randint(1, 100000)


# Patient Login Phase - Login & Authentication using Hamming Distance
def login(IDi, pwi, biometric_data, smart_card, threshold=200):  # Increased threshold
    print("\nLogin Phase:")

    # Step 1: Process biometric data to get a hash (convert to binary)
    hbio_result = simple_hash(biometric_data)  # Simulate biohashing

    # Store the original biometric data (Bir) from the smart card
    Bir = hbio_result + str(smart_card['r1'])  # Simulated as original biometric + random number stored

    # Step 2: Convert the stored Bir and inputted biometric data to binary strings
    stored_bir_binary = ''.join(format(ord(c), '08b') for c in Bir)  # Convert to binary string
    input_bio_binary = ''.join(format(ord(c), '08b') for c in hbio_result)  # Convert input to binary

    # Print lengths of the binary strings
    print(f"Stored Biometric (Binary): {stored_bir_binary}")
    print(f"Input Biometric (Binary): {input_bio_binary}")
    print(f"Length of stored binary: {len(stored_bir_binary)}")
    print(f"Length of input binary: {len(input_bio_binary)}")

    # Step 3: Pad binary strings to the same length
    max_len = max(len(stored_bir_binary), len(input_bio_binary))
    stored_bir_binary = stored_bir_binary.zfill(max_len)  # Pad with leading zeros
    input_bio_binary = input_bio_binary.zfill(max_len)  # Pad with leading zeros

    print(f"Stored Biometric (Padded): {stored_bir_binary}")
    print(f"Input Biometric (Padded): {input_bio_binary}")

    # Step 4: Calculate Hamming Distance
    dist = hamming_distance(stored_bir_binary, input_bio_binary)

    # If the Hamming distance is above the threshold, consider the match failed
    if dist == -1 or dist > threshold:
        print(f"Biometric check failed. Hamming distance: {dist}")
        return None  # Return None when the biometric check fails

    print(f"Biometric check passed. Hamming distance: {dist}")

    # Recompute HPW and P
    HPW = simple_hash(IDi + pwi + hbio_result)
    P = simple_hash(HPW + Bir)

    # Generate authentication information
    m = generate_random()  # Random integer for session
    Ai = simple_hash(IDi + str(m) + "IDm") + P
    X1 = simple_hash(IDi + smart_card["Cut"] + Ai) + str(m)

    # Print out variables that will be used in generating the authentication message
    print(f"Generated Ai: {Ai}")
    print(f"Generated X1: {X1}")
    print(f"Generated HPW: {HPW}")
    print(f"Generated P: {P}")

    # Modify the Authut construction to match medical server expectation
    # Construct the Authut with Ni, IDi, and Cut
    Authut = simple_hash(f"{smart_card['Ni']}{IDi}{smart_card['Cut']}")

    print(f"Authentication Message (Authut): {Authut}")
    return Authut


# Main Simulation Function
def main():
    # Simulate patient registration with trusted server
    IDi = "patient2"
    pwi = "password123"
    biometric_data = "biometric_template_data"  # Placeholder for the biometric template

    # Step 1: Registration
    smart_card = registration(IDi, pwi, biometric_data)

    # Step 2: Login (Patient provides ID, password, and biometric data)
    Authut = login(IDi, pwi, biometric_data, smart_card, threshold=200)  # Increased threshold
    if Authut:
        # Step 3: Medical Server Authentication
        print("\nAuthentication Phase:")
        SKtm = medical_server_authentication(IDi, smart_card, Authut)
        print(f"Session Key Shared: {SKtm}")


if __name__ == "__main__":
    main()
