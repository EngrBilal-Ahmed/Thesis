import hashlib
import random


# Simple hash function using hashlib
def simple_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


# Random number generator for creating random integers
def generate_random():
    return random.randint(1, 100000)


# Medical Server - Authentication Phase
def medical_server_authentication(IDi, smart_card, Authut):
    # Step 1: Log the incoming authentication message and expected format
    print(f"Received Authut: {Authut}")

    # Expected format of the Authut based on smart card and IDi
    expected_authut = simple_hash(f"{smart_card['Ni']}{IDi}{smart_card['Cut']}")
    print(f"Expected Authut: {expected_authut}")

    # Step 2: Validate the Authut
    if Authut != expected_authut:
        print("Authentication failed: Invalid Authut")
        return None  # Authentication failed

    print("Authentication passed.")

    # Step 3: Generate session key using IDi and a random number n
    n = generate_random()
    X2 = simple_hash(f"{IDi}{n}")  # Placeholder for X2 value (more complex logic can be added)

    # Simulate session key creation
    SKtm = simple_hash(f"{IDi}{n}")  # Pre-shared session key based on IDi and n

    print(f"Generated session key: {SKtm}")

    # Step 4: Proceed with the next session steps
    return SKtm
