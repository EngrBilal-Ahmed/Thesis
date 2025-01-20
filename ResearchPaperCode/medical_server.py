import hashlib  # For generating cryptographic hashes
import random  # For generating random values used in session creation
from flask import Flask, request, jsonify  # For creating a Flask web server

# Initialize Flask app
app = Flask(__name__)

# Simple hash function using hashlib for generating SHA256 hashes
def simple_hash(data):
    """
    This function generates a SHA-256 hash from the input data.
    The data is first encoded into bytes, then hashed using SHA-256,
    and the hexadecimal string is returned as the output hash.
    """
    return hashlib.sha256(data.encode()).hexdigest()


# Random number generator for creating random integers
def generate_random():
    """
    This function generates a random integer between 1 and 100,000.
    The random integer is used in various cryptographic operations
    to create unique values, including session keys and temporary data.
    """
    return random.randint(1, 100000)



# Medical Server - Authentication Phase
@app.route('/authenticate', methods=['POST'])
def medical_server_authentication(): #IDi, smart_card, Authut):
    """
    Endpoint for verifying patient authentication. The Authut message is validated against the expected value,
    and if valid, a session key is generated and returned to the patient.

    Incase without the flask app, the function can be called as:
    This function handles the authentication phase on the medical server.
    It compares the provided authentication message (Authut) with the expected value
    and generates a session key if the authentication is successful.

    Parameters:
    IDi (str): The identity of the patient (User ID).
    smart_card (dict): The smart card data from the trusted server, containing Cut, Ni, and r1.
    Authut (str): The authentication message generated by the patient, which will be validated.

    Returns:
    str: The session key (SKtm) if authentication is successful, None otherwise.
    """

    # Get the incoming data from the POST request
    data = request.get_json()
    Authut = data.get("Authut")
    smart_card = data.get("smart_card")
    IDi = data.get("IDi")

    # Step 1: Log the incoming authentication message and expected format
    print(f"Received Authut: {Authut}")

    # Step 2: Generate the expected Authut based on the smart card and patient ID
    expected_authut = simple_hash(f"{smart_card['Ni']}{IDi}{smart_card['Cut']}")
    print(f"Expected Authut: {expected_authut}")

    # Step 3: Validate the Authut
    if Authut != expected_authut:
        print("Authentication failed: Invalid Authut")  # Authentication fails if the hashes do not match
        return jsonify({"message": "Authentication failed"}), 401  # Return failure response if Authut is invalid

    # Step 4: Generate session key
    print("Authentication passed.")

    # Step 5: Generate a random integer (n) for further encryption and session key creation
    n = generate_random()
    print(f"Generated random number in MS (n): {n}")

    # Step 6: Generate the X2 value using patient ID and random number
    X2 = simple_hash(f"{IDi}{n}")  # Generate X2 value for session

    # Step 7: Generate the session key (SKtm) based on IDi and n
    SKtm = simple_hash(f"{IDi}{n}")  # Generate a session key (SKtm) from the patient ID and random number

    print(f"Generated session key: {SKtm}")

    # Step 8: Proceed with the next session steps (this could involve further secure communication)
    return jsonify({"session_key": SKtm}), 200  # Return the session key if authentication is successful

# Start the Flask application
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)
