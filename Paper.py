import hashlib
import random
import time


# Helper functions
def xor(data1, data2):
    return bytes([a ^ b for a, b in zip(data1, data2)])


def h(input_string):
    # A simple hash function for demonstration, replace with secure hash in production
    return hashlib.sha256(input_string.encode()).digest()


# Registration Phase
def registration_phase(IDi, pwi, biometric_data):
    r1 = random.randint(0, 255)  # Random integer r1 for the registration phase
    h_pw = h(IDi + str(pwi) + biometric_data)  # Hash of ID, password, and biometric data
    Bir = xor(biometric_data.encode(), bytes([r1]))  # XOR biometric data with r1
    P = xor(h_pw, Bir)  # Combine hash and biometric data

    R = xor(h(IDi + biometric_data + str(pwi)), bytes([r1]))  # Create R for smart card

    # Create smart card information
    smart_card = {
        'IDi': IDi,
        'HPW': h_pw,
        'P': P,
        'Bir': Bir,
        'R': R,
    }

    return smart_card


# Login Phase
def login_phase(IDi, pwi, biometric_data, smart_card):
    if smart_card is None:
        print("Error: Smart card is invalid!")
        return None

    # Step L1: Check biometric match
    r0 = xor(h(IDi + str(pwi) + biometric_data), smart_card['R'])
    Bir = xor(biometric_data.encode(), bytes([random.randint(0, 255)]))  # XOR with random value
    if r0 != smart_card['Bir']:  # Check if the biometric data matches
        print("Biometric mismatch!")
        return None

    # Step L2: Proceed with login phase calculations
    h_pw = h(IDi + str(pwi) + biometric_data)
    P0 = xor(h_pw, Bir)

    m = random.randint(0, 255)  # Random number for encryption
    Ai = xor(h(IDi + str(m) + biometric_data), P0)  # Compute Ai

    # Now proceed to compute the authentication message
    X1 = xor(h(IDi + str(m)), Ai)  # X1 = h(IDi || m) ⊕ Ai

    # Compute the final authentication message
    SK = xor(h_pw, Ai)  # Encryption key SK
    Authut = xor(X1, SK)  # Authentication message (simplified)

    return Authut


# Main logic to simulate registration and login
IDi = 'patient123'
pwi = 'password123'
biometric_data = 'iris_data_here'

# Step 1: Registration phase (Smart card created)
smart_card = registration_phase(IDi, pwi, biometric_data)

# Step 2: Login phase (Verify using smart card)
if smart_card is not None:
    auth_message = login_phase(IDi, pwi, biometric_data, smart_card)
    if auth_message:
        print("Authentication successful, message:", auth_message)
else:
    print("Registration failed, smart card is invalid!")
