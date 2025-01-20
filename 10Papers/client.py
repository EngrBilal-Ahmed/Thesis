# Import necessary libraries
import requests  # Used for making HTTP requests to the server
import json  # Used for formatting and handling JSON data


def authenticate_user(username, password, smart_card, biometric):
    """
    Sends the user's authentication data (username, password, smart card, and biometric data)
    to the server's /authenticate endpoint for verification. If authentication is successful,
    a shared session key is received. Handles cases where authentication fails.

    Parameters:
        username (str): The username entered by the user.
        password (str): The password entered by the user.
        smart_card (str): The smart card public key entered by the user (simulated as a string).
        biometric (str): The biometric data (e.g., fingerprint or face data) entered by the user.

    Returns:
        None: Displays success or failure messages based on the server response.
    """
    # Construct a dictionary to hold the user data to be sent to the server
    user_data = {
        "username": username,  # User's unique username
        "password": password,  # User's plain-text password
        "smart_card": smart_card,  # Simulated smart card public key
        "biometric": biometric  # Simulated biometric data
    }

    try:
        # Send a POST request to the server at the /authenticate endpoint
        # The user_data dictionary is automatically converted to JSON format by the requests library
        response = requests.post("http://127.0.0.1:5000/authenticate", json=user_data)

        # Check the HTTP status code of the server's response
        if response.status_code == 200:
            # If status code is 200, authentication was successful
            print("Authentication Successful!")

            # Extract the shared session key from the JSON response
            shared_key = response.json().get("shared_key")

            # Display the shared session key (hex-encoded) to the user
            print(f"Shared Key: {shared_key}")
        elif response.status_code == 403:
            # Status code 403 indicates that the user is temporarily blocked due to too many failed attempts
            print("Authentication Failed: Too many failed attempts. Your account is temporarily blocked.")
        elif response.status_code == 400:
            # Status code 400 indicates a bad request (e.g., invalid credentials)
            print(f"Authentication Failed: {response.json().get('message')}")
        else:
            # Any other status code indicates an unexpected server-side error
            print(f"Unexpected Error: {response.status_code}")

    except requests.exceptions.RequestException as e:
        # Handle network-related errors (e.g., server not running, connection issues)
        print(f"Error connecting to server: {e}")


def login_user(username, password):
    """
    Sends the username and password to the server's /login endpoint for verification.
    If login is successful, a success message is displayed. Handles cases where the user is blocked
    or the credentials are invalid.

    Parameters:
        username (str): The username entered by the user.
        password (str): The password entered by the user.

    Returns:
        None: Displays success or failure messages based on the server response.
    """
    # Construct a dictionary to hold the login credentials
    login_data = {
        "username": username,  # User's unique username
        "password": password  # User's plain-text password
    }

    try:
        # Send a POST request to the server at the /login endpoint
        response = requests.post("http://127.0.0.1:5000/login", json=login_data)

        # Check the HTTP status code of the server's response
        if response.status_code == 200:
            # If status code is 200, login was successful
            print("Login Successful!")
        elif response.status_code == 403:
            # Status code 403 indicates that the user is temporarily blocked
            print("Login Failed: Too many failed attempts. Your account is temporarily blocked.")
        elif response.status_code == 400:
            # Status code 400 indicates a bad request (e.g., invalid credentials)
            print(f"Login Failed: {response.json().get('message')}")
        else:
            # Any other status code indicates an unexpected server-side error
            print(f"Unexpected Error: {response.status_code}")

    except requests.exceptions.RequestException as e:
        # Handle network-related errors (e.g., server not running, connection issues)
        print(f"Error connecting to server: {e}")


def register_user(username, password, smart_card, biometric):
    """
    Sends the user's registration data (username, password, smart card, and biometric data)
    to the server's /register endpoint to create a new account. Handles cases where the username
    is already taken or other registration errors occur.

    Parameters:
        username (str): The desired username for the new account.
        password (str): The desired password for the new account.
        smart_card (str): The smart card public key (simulated as a string).
        biometric (str): The biometric data (e.g., fingerprint or face data).

    Returns:
        None: Displays success or failure messages based on the server response.
    """
    # Construct a dictionary to hold the registration data
    user_data = {
        "username": username,  # Desired unique username
        "password": password,  # Desired plain-text password
        "smart_card": smart_card,  # Simulated smart card public key
        "biometric": biometric  # Simulated biometric data
    }

    try:
        # Send a POST request to the server at the /register endpoint
        response = requests.post("http://127.0.0.1:5000/register", json=user_data)

        # Check the HTTP status code of the server's response
        if response.status_code == 201:
            # If status code is 201, registration was successful
            print("Registration Successful!")
        elif response.status_code == 400:
            # Status code 400 indicates a bad request (e.g., username already exists)
            print(f"Registration Failed: {response.json().get('message')}")
        else:
            # Any other status code indicates an unexpected server-side error
            print(f"Unexpected Error: {response.status_code}")

    except requests.exceptions.RequestException as e:
        # Handle network-related errors (e.g., server not running, connection issues)
        print(f"Error connecting to server: {e}")


# Example usage:
if __name__ == "__main__":
    """
    Example of using the registration, login, and authentication functions. You can
    modify the parameters below to test the workflow.
    """
    # Example user credentials for testing
    username = "john_doe"
    password = "securePassword123"
    smart_card = "A1B2C3D4E5F6070809A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7"  # Simulated smart card public key
    biometric = "eNq8V8+0JhI0dQsS9bMIghLMwkcGcHF8yTmf68Pb6wQ="  # Simulated biometric data

    print("---- Registration ----")
    register_user(username, password, smart_card, biometric)  # Register a new user

    print("\n---- Login ----")
    login_user(username, password)  # Log in the user

    print("\n---- Authentication ----")
    authenticate_user(username, password, smart_card, biometric)  # Authenticate the user
