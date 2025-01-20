# trusted_server.py
import hashlib
import random


# Simple hash function using hashlib
def simple_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


# Random number generator for creating random integers
def generate_random():
    return random.randint(1, 100000)


# Trusted Server - Registration Phase
def registration(IDi, pwi, biometric_data):
    r1 = generate_random()  # Random number for masking biometric data
    hbio_result = simple_hash(biometric_data)  # Simulate biohashing

    HPW = simple_hash(IDi + pwi + hbio_result)  # Hash of IDi, pwi, and bio data
    Bir = hbio_result + str(r1)  # Combine biometric hash with random integer
    P = simple_hash(HPW + Bir)  # Hash of HPW and Bir
    R = simple_hash(IDi + hbio_result + pwi) + str(r1)  # Final combination for R

    # Trusted server generates smart card data
    r2 = generate_random()
    M1 = IDi + "IDt"  # Trusted server ID
    Cut = simple_hash(M1 + str(r2) + P)  # Simplified encryption simulation
    Ni = simple_hash(IDi + "IDt" + str(r2)) + HPW  # Generate Ni

    # Smart card data
    smart_card = {"Cut": Cut, "Ni": Ni, "r1": r1}
    print("Registration Phase:")
    print(f"Smart Card Data: {smart_card}")
    return smart_card
