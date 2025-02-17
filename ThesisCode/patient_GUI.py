import hashlib
import secrets
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import psutil
import requests
import time


# Simple hash function using hashlib for SHA256 hashing
def simple_hash(data):
    """
    Generates a SHA-256 hash for a given input string.

    This function uses Python's hashlib library to create a SHA-256 hash of the input string.
    This is typically used for hashing passwords or sensitive data to ensure security.

    Args:
        data (str): The input string to be hashed.

    Returns:
        str: The SHA-256 hash of the input data.
    """
    return hashlib.sha256(data.encode()).hexdigest()


# Random number generator for creating random integers
def generate_random():
    """
    Generates a random integer between 1 and 100,000.

    This function is used for generating random integers that can be used for cryptographic
    or session management purposes.

    Returns:
        int: A random integer between 1 and 100,000.
    """
    return secrets.randbelow(1, 100000)


# Simulated user database for login (this could be replaced by a real database)
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

MAX_LOGIN_ATTEMPTS = 3  # Maximum login attempts before account is locked


# Function to monitor system resources (CPU and memory usage)
def monitor_resources():
    """
    Monitors the system's current CPU and memory usage.

    This function uses the `psutil` library to check the current CPU and memory usage of the
    system, which can be useful for debugging or performance monitoring.

    Returns:
        tuple: CPU usage as a percentage and memory usage as a percentage.
    """
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    return cpu_usage, memory_usage


# Hamming Distance function to compare two binary strings
def hamming_distance(str1, str2):
    """
    Computes the Hamming distance between two binary strings.

    The Hamming distance measures how different two strings of equal length are by comparing
    their characters at each position. A higher distance indicates a greater difference.

    Args:
        str1 (str): The first binary string.
        str2 (str): The second binary string.

    Returns:
        int: The Hamming distance, or -1 if the strings are of unequal lengths.
    """
    if len(str1) != len(str2):
        return -1
    return sum(el1 != el2 for el1, el2 in zip(str1, str2))


# Login function
def login(IDi, pwi, biometric_data, smart_card, threshold=200):
    """
    Handles the user login and performs biometric, password validation.

    This function checks the entered User ID, password, and biometric data against the stored
    information in the `users_db` and performs additional authentication using Hamming distance.

    Args:
        IDi (str): The user ID.
        pwi (str): The user's password.
        biometric_data (str): The biometric data entered by the user (e.g., fingerprint).
        smart_card (dict): The smart card data containing additional credentials.
        threshold (int): The Hamming distance threshold for biometric validation.

    Returns:
        str: The authentication key (Authut) if successful, otherwise `None`.
    """
    cpu_usage, memory_usage = monitor_resources()

    # Check if the user has exceeded the max login attempts
    if users_db[IDi]["login_attempts"] >= MAX_LOGIN_ATTEMPTS:
        show_error_popup(f"Account locked due to too many failed login attempts for user: {IDi}")
        return None

    start_time = time.time()

    # Hash biometric data and calculate Hamming distance
    hbio_result = simple_hash(biometric_data)
    Bir = hbio_result + str(smart_card['r1'])
    stored_bir_binary = ''.join(format(ord(c), '08b') for c in Bir)
    input_bio_binary = ''.join(format(ord(c), '08b') for c in hbio_result)

    max_len = max(len(stored_bir_binary), len(input_bio_binary))
    stored_bir_binary = stored_bir_binary.zfill(max_len)
    input_bio_binary = input_bio_binary.zfill(max_len)

    dist = hamming_distance(stored_bir_binary, input_bio_binary)

    # If Hamming distance exceeds threshold, return None
    if dist == -1 or dist > threshold:
        users_db[IDi]["login_attempts"] += 1
        show_error_popup(f"Biometric check failed. Hamming distance: {dist}")
        return None

    users_db[IDi]["login_attempts"] = 0
    HPW = simple_hash(IDi + pwi + hbio_result)
    P = simple_hash(HPW + Bir)

    m = generate_random()
    Ai = simple_hash(IDi + str(m) + "IDm") + P
    X1 = simple_hash(IDi + smart_card["Cut"] + Ai) + str(m)

    Authut = simple_hash(f"{smart_card['Ni']}{IDi}{smart_card['Cut']}")

    users_db[IDi]["login_attempts"] = 0  # Reset the login attempt counter

    # Capture execution time
    execution_time = time.time() - start_time

    # Display login info with CPU, Memory, Execution Time, and Authut
    login_info = (
        f"Login successful for {IDi}!\n\n"
        f"Execution Time: {execution_time:.6f} seconds\n"
        f"CPU Usage: {cpu_usage}%\n"
        f"Memory Usage: {memory_usage}%\n"
        f"Authentication Key (Authut): {Authut}"
    )

    show_info_popup("Login Successful", login_info)

    return Authut


# Function to register the user
def register_user():
    """
    Handles the user registration process.

    This function collects user data (User ID, password, biometric data) from the GUI input fields,
    checks if the user already exists in the database, and sends a registration request to the server.

    If registration is successful, the new user is added to the local database and a success message is displayed.

    Returns:
        None
    """
    IDi = entry_register_id.get()
    pwi = entry_register_password.get()
    biometric_data = entry_register_biometric_data.get()

    # Check if the user already exists in the users_db
    if IDi in users_db:
        show_error_popup(f"User ID '{IDi}' already exists. Please choose a different ID.")
        return

    # If user does not exist, proceed with registration
    registration_url = "http://localhost:5000/register"
    registration_data = {
        "IDi": IDi,
        "pwi": pwi,
        "biometric_data": biometric_data
    }

    response = requests.post(registration_url, json=registration_data)
    if response.status_code != 200:
        show_error_popup(f"Registration failed: {response.text}")
    else:
        smart_card = response.json()
        # Save this user to the local database (users_db) to prevent future duplicates
        users_db[IDi] = {
            "password": simple_hash(pwi),  # Storing the hashed password
            "biometric_data": biometric_data,
            "login_attempts": 0  # Reset login attempts to 0 for the new user
        }
        show_info_popup("Success", f"Registration successful!\n\nSmart Card Data: {smart_card}")


# Custom function to show an error popup
def show_error_popup(message):
    """
    Displays a custom error popup window.

    This function creates a separate window for error messages with a red background and appropriate
    styling for clear visibility.

    Args:
        message (str): The error message to be displayed.

    Returns:
        None
    """
    error_popup = tk.Toplevel(root)
    error_popup.title("Error")
    error_popup.geometry("300x150")
    error_popup.config(bg="#f8d7da")

    label = tk.Label(error_popup, text=message, font=("Segoe UI", 12), fg="red", bg="#f8d7da", wraplength=250)
    label.pack(pady=20)

    button = ttk.Button(error_popup, text="OK", command=error_popup.destroy)
    button.pack()

    error_popup.mainloop()


# Custom function to show an info popup
def show_info_popup(title, message):
    """
    Displays a custom information popup window.

    This function creates a separate window to show informational messages (e.g., successful login,
    registration success, etc.) with a green background and appropriate styling.

    Args:
        title (str): The title of the popup window.
        message (str): The message to be displayed.

    Returns:
        None
    """
    info_popup = tk.Toplevel(root)
    info_popup.title(title)
    info_popup.geometry("650x240")
    info_popup.config(bg="#d4edda")

    label = tk.Label(info_popup, text=message, font=("Segoe UI", 12), fg="green", bg="#d4edda", wraplength=600)
    label.pack(pady=20)

    button = ttk.Button(info_popup, text="OK", command=info_popup.destroy)
    button.pack()

    info_popup.mainloop()


def authenticate_user():
    """
    Handles the user authentication process.

    This function collects user data from the input fields, verifies the user's credentials (ID, password,
    biometric data), and if successful, it performs authentication with the server.

    Returns:
        None
    """
    IDi = entry_login_id.get()
    pwi = entry_login_password.get()
    biometric_data = entry_login_biometric_data.get()

    # Check if the user ID exists in the users_db
    if IDi not in users_db:
        show_error_popup(f"User ID '{IDi}' does not exist. Please check the ID.")
        return

    # Check if the user has exceeded the max login attempts
    if users_db[IDi]["login_attempts"] >= MAX_LOGIN_ATTEMPTS:
        show_error_popup(f"Account locked due to too many failed login attempts for user: {IDi}")
        return

    # Check if the password is correct
    if users_db[IDi]["password"] != simple_hash(pwi):
        users_db[IDi]["login_attempts"] += 1
        show_error_popup("Incorrect password.")
        return

    # Check if the biometric data is correct
    if users_db[IDi]["biometric_data"] != biometric_data:
        users_db[IDi]["login_attempts"] += 1
        show_error_popup("Incorrect biometric data.")
        return

    registration_url = "http://localhost:5000/register"
    registration_data = {
        "IDi": IDi,
        "pwi": pwi,
        "biometric_data": biometric_data
    }

    # Perform registration (if needed)
    response = requests.post(registration_url, json=registration_data)
    if response.status_code != 200:
        show_error_popup("Registration failed.")
        return

    smart_card = response.json()

    # Perform login and authentication
    Authut = login(IDi, pwi, biometric_data, smart_card)
    if Authut:
        authentication_url = "http://localhost:5001/authenticate"
        authentication_data = {
            "Authut": Authut,
            "smart_card": smart_card,
            "IDi": IDi
        }
        response = requests.post(authentication_url, json=authentication_data)

        if response.status_code == 200:
            session_key = response.json().get("session_key")
            show_info_popup("Authentication Successful", f"Session Key: {session_key}")
        else:
            show_error_popup(f"Authentication failed: {response.text}")


# GUI Setup
root = tk.Tk()
root.title("Patient Registration & Authentication")
root.geometry("540x420")
root.configure(bg="#f0f0f0")
root.iconbitmap("icon.ico")

# Create a frame for styling
frame = tk.Frame(root, bg="#ffffff", bd=2, relief="solid")
frame.pack(padx=5, pady=5, anchor="center")

# Title Label
title_label = tk.Label(frame, text="Patient Registration & Authentication", font=("Segoe UI", 18, "bold"), fg="#505050",
                       bg="#ffffff")
title_label.grid(row=0, column=0, columnspan=2, padx=45, pady=20, sticky="ew")

# Register Section
label_register_id = tk.Label(frame, text="User ID:", font=("Segoe UI", 12), bg="#ffffff")
label_register_id.grid(row=1, column=0, padx=10, pady=4, sticky="w")
entry_register_id = ttk.Entry(frame, font=("Segoe UI", 12), width=25)
entry_register_id.grid(row=1, column=1, padx=10, pady=4, sticky="w")

label_register_password = tk.Label(frame, text="Password:", font=("Segoe UI", 12), bg="#ffffff")
label_register_password.grid(row=2, column=0, padx=10, pady=4, sticky="w")
entry_register_password = ttk.Entry(frame, show="*", font=("Segoe UI", 12), width=25)
entry_register_password.grid(row=2, column=1, padx=10, pady=4, sticky="w")

label_register_biometric_data = tk.Label(frame, text="Simulated Biometric Data:", font=("Segoe UI", 12), bg="#ffffff")
label_register_biometric_data.grid(row=3, column=0, padx=10, pady=4, sticky="w")
entry_register_biometric_data = ttk.Entry(frame, font=("Segoe UI", 12), width=25)
entry_register_biometric_data.grid(row=3, column=1, padx=10, pady=4, sticky="w")

register_button = ttk.Button(frame, text="Register", command=register_user, width=20, style="TButton")
register_button.grid(row=4, columnspan=2, padx=45, pady=15, sticky="e")

# Login Section
label_login_id = tk.Label(frame, text="User ID:", font=("Segoe UI", 12), bg="#ffffff")
label_login_id.grid(row=5, column=0, padx=10, pady=4, sticky="w")
entry_login_id = ttk.Entry(frame, font=("Segoe UI", 12), width=25)
entry_login_id.grid(row=5, column=1, padx=10, pady=4, sticky="w")

label_login_password = tk.Label(frame, text="Password:", font=("Segoe UI", 12), bg="#ffffff")
label_login_password.grid(row=6, column=0, padx=10, pady=4, sticky="w")
entry_login_password = ttk.Entry(frame, show="*", font=("Segoe UI", 12), width=25)
entry_login_password.grid(row=6, column=1, padx=10, pady=4, sticky="w")

label_login_biometric_data = tk.Label(frame, text="Biometric Data:", font=("Segoe UI", 12), bg="#ffffff")
label_login_biometric_data.grid(row=7, column=0, padx=10, pady=4, sticky="w")
entry_login_biometric_data = ttk.Entry(frame, font=("Segoe UI", 12), width=25)
entry_login_biometric_data.grid(row=7, column=1, padx=10, pady=4, sticky="w")

login_button = ttk.Button(frame, text="Login", command=authenticate_user, width=20, style="TButton")
login_button.grid(row=8, columnspan=2, padx=45, pady=15, sticky="e")

# Run the main window loop
root.mainloop()
