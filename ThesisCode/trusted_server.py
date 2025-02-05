import hashlib  # For generating hashes of data
import random  # For generating random numbers for masking
from flask import Flask, request, jsonify  # For creating a Flask web server

# Initialize Flask app
app = Flask(__name__)

# Simple hash function using hashlib for generating SHA256 hashes
def simple_hash(data):
    """
    Function to generate a SHA-256 hash of the input data.
    It takes the input 'data', encodes it into bytes, and returns the hash as a hexadecimal string.
    This is useful for hashing passwords, biometric data, and other sensitive information.
    """
    return hashlib.sha256(data.encode()).hexdigest()

# Random number generator for creating random integers
def generate_random():
    """
    Function to generate a random integer between 1 and 100,000.
    This is used to generate random numbers, which are later used for masking biometric data
    and creating session keys.
    """
    return random.randint(1, 100000)

# Simulating a database of users
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

# Trusted Server - Registration Phase
@app.route('/register', methods=['POST'])
def registration(): #IDi, pwi, biometric_data):
    """
    Endpoint for registering a new patient. It receives patient details from the client (patient system),
    hashes the password and biometric data, and generates the smart card data to be used in the login phase.

    Incase without the flask app, the function can be called as:
    This function simulates the registration phase on the trusted server.
    It takes the patient's identity (IDi), password (pwi), and biometric data as input,
    performs various cryptographic operations to generate the smart card data, and returns it.

    This simulates the real-world process where a trusted server registers a user and generates
    a smart card containing encrypted data.
    """

    # Get input data from the POST request
    data = request.get_json()
    IDi = data.get("IDi")
    pwi = data.get("pwi")
    biometric_data = data.get("biometric_data")

    # Step 1: Generate a random number (r1) for masking the biometric data
    r1 = generate_random()  # Random number for masking biometric data
    print("Random number (r1) for biometric data masking in TS:", r1)

    # Step 2: Hash the biometric data
    hbio_result = simple_hash(biometric_data)  # Simulate biohashing (hashed biometric data)

    # Step 3: Combine IDi, password, and the hashed biometric data to generate the hash HPW
    HPW = simple_hash(IDi + pwi + hbio_result)  # A secure hash generated from ID, password, and biometric hash

    # Step 4: Combine the biometric hash with the random number to create the biometric reference Bir
    Bir = hbio_result + str(r1)  # Combine biometric hash with the random number (r1)

    # Step 5: Create the password hash (P) by hashing HPW with the biometric reference (Bir)
    P = simple_hash(HPW + Bir)  # Hash of HPW and Bir to create a secure password hash

    # Step 6: Generate the final value R by combining ID, hashed biometric data, password, and r1
    R = simple_hash(IDi + hbio_result + pwi) + str(r1)  # Final combination for R

    # Step 7: Generate another random number (r2) for encryption purposes
    r2 = generate_random()  # Generate another random number for masking

    print("Random number (r2) for smart card generation in TS:", r2)

# Step 8: Create the trusted server ID and generate the Cut value (encryption simulation)
    M1 = IDi + "IDt"  # Combining patient ID with trusted server ID for masking
    Cut = simple_hash(M1 + str(r2) + P)  # Encrypted data (simulated encryption) to generate Cut

    # Step 9: Generate the Ni value (a secure key) using a combination of ID, trusted server ID, and r2
    Ni = simple_hash(
        IDi + "IDt" + str(r2)) + HPW  # Another key generation using a hash of ID, trusted server ID, and r2

    # Step 10: Prepare the smart card data with Cut, Ni, and r1
    smart_card = {"Cut": Cut, "Ni": Ni, "r1": r1}

    # Step 11: Print the smart card data for debugging purposes
    print("Registration Phase:")
    print(f"Smart Card Data: {smart_card}")

    # Return the smart card data to be used in the login phase later
    return smart_card

# Function to reset login attempts after a successful login
def reset_login_attempts(IDi):
    """
    Resets the login attempts counter for a user after a successful login.
    """
    if IDi in users_db:
        users_db[IDi]["login_attempts"] = 0
        print(f"Login attempts for {IDi} have been reset.")

# Start the Flask application
if __name__ == '__main__':
    # Run the Flask app on localhost at port 5000
    app.run(host='localhost', port=5000, debug=True)
#     main()  # Start the simulation