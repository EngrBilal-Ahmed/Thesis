from flask import Flask, request, jsonify
import logging

# Initialize Flask app
app = Flask(__name__)

# Configure logging to output to console with INFO level
logging.basicConfig(level=logging.DEBUG)

# Example "database" for demonstration purposes (in real-life, use a proper database)
users_db = {
    'user1': {
        'password': 'securepassword123'  # Example password for the user
    }
}

# Utility function to validate incoming JSON request
def validate_request(data):
    required_fields = ['username', 'password']
    for field in required_fields:
        if field not in data:
            return f"Missing required field: {field}", False
    return "Valid", True

# Route to handle POST request to authenticate a user
@app.route("/authenticate", methods=["POST"])
def authenticate():
    try:
        # Get the incoming JSON request data
        data = request.json
        logging.debug("Request data received: %s", data)

        # Validate the request data (check if required fields are present)
        validation_msg, is_valid = validate_request(data)
        if not is_valid:
            logging.error("Validation failed: %s", validation_msg)
            return jsonify({"status": "error", "message": validation_msg}), 400

        # Extract the username and password from the request data
        username = data['username']
        password = data['password']

        # Check if the username exists in the "database"
        if username not in users_db:
            logging.error("User not found: %s", username)
            return jsonify({"status": "error", "message": "User not found"}), 404

        # Check if the password provided matches the stored password for the user
        if users_db[username]['password'] != password:
            logging.error("Invalid password for user: %s", username)
            return jsonify({"status": "error", "message": "Invalid password"}), 401

        # Placeholder for the actual authentication logic (e.g., token generation, etc.)
        b = 2 + 6  # This is just a placeholder for authentication logic

        # Log the successful authentication attempt
        logging.info(f"User '{username}' authenticated successfully.")

        # Return a JSON response indicating success and include the computed value
        return jsonify({"status": "success", "message": "User authenticated", "Value": b}), 200

    except Exception as e:
        logging.error("Error occurred: %s", str(e))
        return jsonify({"status": "error", "message": "An error occurred during authentication"}), 500

# Run the Flask application
if __name__ == "__main__":
    app.run(host="localhost", port=5000)
