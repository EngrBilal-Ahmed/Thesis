import unittest
import hashlib
import random
import time


# Dummy implementations of functions you already have
def simple_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


def generate_random():
    return random.randint(1, 100000)


def login(IDi, pwi, biometric_data, smart_card, threshold=200):
    # Step 1: Validate credentials
    if IDi != "patient1" or pwi != "password123":  # Simple validation
        return None  # Invalid credentials

    # Step 2: Process biometric data to get a hash (convert to binary)
    hbio_result = simple_hash(biometric_data)

    # Check if biometric data is valid by comparing it against expected value (dummy check for now)
    expected_biohash = "expected_biometric_hash"
    if hbio_result != expected_biohash:
        return None  # Invalid biometric data

    Bir = hbio_result + str(smart_card['r1'])
    stored_bir_binary = ''.join(format(ord(c), '08b') for c in Bir)
    input_bio_binary = ''.join(format(ord(c), '08b') for c in hbio_result)

    # Step 3: Calculate Hamming Distance
    dist = sum(el1 != el2 for el1, el2 in zip(stored_bir_binary, input_bio_binary))

    if dist > threshold:
        return None  # Failed biometric check

    HPW = simple_hash(IDi + pwi + hbio_result)
    P = simple_hash(HPW + Bir)
    Ai = simple_hash(IDi + str(generate_random()) + "IDm") + P
    X1 = simple_hash(IDi + smart_card["Cut"] + Ai)

    # Step 4: Generate Authut message
    Authut = simple_hash(f"{smart_card['Ni']}{IDi}{smart_card['Cut']}")

    return Authut


def medical_server_authentication(IDi, smart_card, Authut):
    expected_authut = simple_hash(f"{smart_card['Ni']}{IDi}{smart_card['Cut']}")
    if Authut != expected_authut:
        return None
    return simple_hash(f"{IDi}{generate_random()}")


class TestAuthentication(unittest.TestCase):

    def setUp(self):
        self.IDi = "patient1"
        self.pwi = "password123"
        self.smart_card = {"Ni": "Ni_value", "Cut": "Cut_value", "r1": 12345}

    def test_valid_biometric_data(self):
        biometric_data = "valid_biometric_data"
        Authut = login(self.IDi, self.pwi, biometric_data, self.smart_card, threshold=200)
        self.assertIsNotNone(Authut)  # Assert that Authut is not None for valid data

    def test_invalid_biometric_data(self):
        biometric_data = "invalid_biometric_data"
        Authut = login(self.IDi, self.pwi, biometric_data, self.smart_card, threshold=200)
        self.assertIsNone(Authut)  # Assert that Authut is None for invalid data

    def test_invalid_credentials(self):
        invalid_ID = "invalid_user"
        invalid_pwi = "invalid_password"
        biometric_data = "valid_biometric_data"
        Authut = login(invalid_ID, invalid_pwi, biometric_data, self.smart_card, threshold=200)
        self.assertIsNone(Authut)  # Assert that Authut is None for invalid credentials

    def test_randomized_r1(self):
        biometric_data = "valid_biometric_data"
        random_r1 = generate_random()
        self.smart_card['r1'] = random_r1
        Authut = login(self.IDi, self.pwi, biometric_data, self.smart_card, threshold=200)
        self.assertIsNotNone(Authut)  # Assert that Authut is not None for valid data with random r1

    def test_medical_server_authentication(self):
        biometric_data = "valid_biometric_data"
        Authut = login(self.IDi, self.pwi, biometric_data, self.smart_card, threshold=200)
        session_key = medical_server_authentication(self.IDi, self.smart_card, Authut)
        self.assertIsNotNone(session_key)  # Assert that session key is shared after authentication


if __name__ == '__main__':
    unittest.main()
