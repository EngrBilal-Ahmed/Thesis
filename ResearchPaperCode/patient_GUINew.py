import hashlib
import random
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import psutil
import requests
import time


# Simple hash function using hashlib for SHA256 hashing
def simple_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


# Random number generator for creating random integers
def generate_random():
    return random.randint(1, 100000)


# Simulated user database for login
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

MAX_LOGIN_ATTEMPTS = 3


# Function to monitor system resources (for simulation purposes)
def monitor_resources():
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    return cpu_usage, memory_usage


# Hamming Distance function to compare two binary strings
def hamming_distance(str1, str2):
    if len(str1) != len(str2):
        return -1
    return sum(el1 != el2 for el1, el2 in zip(str1, str2))


# Login function
def login(IDi, pwi, biometric_data, smart_card, threshold=200):
    cpu_usage, memory_usage = monitor_resources()

    if users_db[IDi]["login_attempts"] >= MAX_LOGIN_ATTEMPTS:
        show_error_popup(f"Account locked due to too many failed login attempts for user: {IDi}")
        return None

    start_time = time.time()

    hbio_result = simple_hash(biometric_data)
    Bir = hbio_result + str(smart_card['r1'])
    stored_bir_binary = ''.join(format(ord(c), '08b') for c in Bir)
    input_bio_binary = ''.join(format(ord(c), '08b') for c in hbio_result)

    max_len = max(len(stored_bir_binary), len(input_bio_binary))
    stored_bir_binary = stored_bir_binary.zfill(max_len)
    input_bio_binary = input_bio_binary.zfill(max_len)

    dist = hamming_distance(stored_bir_binary, input_bio_binary)

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
        show_info_popup("Success", f"Registration successful!\nSmart Card Data: {smart_card}")


# Custom function to show an error popup
def show_error_popup(message):
    error_popup = tk.Toplevel(root)
    error_popup.title("Error")
    error_popup.geometry("300x150")
    error_popup.config(bg="#f8d7da")

    label = tk.Label(error_popup, text=message, font=("Arial", 12), fg="red", bg="#f8d7da", wraplength=250)
    label.pack(pady=20)

    button = ttk.Button(error_popup, text="OK", command=error_popup.destroy)
    button.pack()

    error_popup.mainloop()


# Custom function to show an info popup
def show_info_popup(title, message):
    info_popup = tk.Toplevel(root)
    info_popup.title(title)
    info_popup.geometry("400x200")
    info_popup.config(bg="#d4edda")

    label = tk.Label(info_popup, text=message, font=("Arial", 12), fg="green", bg="#d4edda", wraplength=350)
    label.pack(pady=20)

    button = ttk.Button(info_popup, text="OK", command=info_popup.destroy)
    button.pack()

    info_popup.mainloop()


def authenticate_user():
    IDi = entry_login_id.get()
    pwi = entry_login_password.get()
    biometric_data = entry_login_biometric_data.get()

    # Check if the user ID exists in the users_db
    if IDi not in users_db:
        show_error_popup(f"User ID '{IDi}' does not exist. Please check the ID.")
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

    # Check if the user has exceeded the max login attempts
    if users_db[IDi]["login_attempts"] >= MAX_LOGIN_ATTEMPTS:
        show_error_popup(f"Account locked due to too many failed login attempts for user: {IDi}")
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
root.title("Patient Authentication")
root.geometry("500x500")
root.configure(bg="#f0f0f0")

# Create a frame for styling
frame = tk.Frame(root, bg="#ffffff", bd=2, relief="solid")
frame.pack(padx=20, pady=20, fill="both", expand=True)

# Register Section
label_register_id = tk.Label(frame, text="User ID:", font=("Arial", 12), bg="#ffffff")
label_register_id.grid(row=0, column=0, padx=10, pady=10, sticky="w")
entry_register_id = ttk.Entry(frame, font=("Arial", 12))
entry_register_id.grid(row=0, column=1, padx=10, pady=10, sticky="w")

label_register_password = tk.Label(frame, text="Password:", font=("Arial", 12), bg="#ffffff")
label_register_password.grid(row=1, column=0, padx=10, pady=10, sticky="w")
entry_register_password = ttk.Entry(frame, show="*", font=("Arial", 12))
entry_register_password.grid(row=1, column=1, padx=10, pady=10, sticky="w")

label_register_biometric_data = tk.Label(frame, text="Biometric Data:", font=("Arial", 12), bg="#ffffff")
label_register_biometric_data.grid(row=2, column=0, padx=10, pady=10, sticky="w")
entry_register_biometric_data = ttk.Entry(frame, font=("Arial", 12))
entry_register_biometric_data.grid(row=2, column=1, padx=10, pady=10, sticky="w")

register_button = ttk.Button(frame, text="Register", command=register_user, width=20)
register_button.grid(row=3, columnspan=2, pady=20)

# Login Section
label_login_id = tk.Label(frame, text="User ID:", font=("Arial", 12), bg="#ffffff")
label_login_id.grid(row=4, column=0, padx=10, pady=10, sticky="w")
entry_login_id = ttk.Entry(frame, font=("Arial", 12))
entry_login_id.grid(row=4, column=1, padx=10, pady=10, sticky="w")

label_login_password = tk.Label(frame, text="Password:", font=("Arial", 12), bg="#ffffff")
label_login_password.grid(row=5, column=0, padx=10, pady=10, sticky="w")
entry_login_password = ttk.Entry(frame, show="*", font=("Arial", 12))
entry_login_password.grid(row=5, column=1, padx=10, pady=10, sticky="w")

label_login_biometric_data = tk.Label(frame, text="Biometric Data:", font=("Arial", 12), bg="#ffffff")
label_login_biometric_data.grid(row=6, column=0, padx=10, pady=10, sticky="w")
entry_login_biometric_data = ttk.Entry(frame, font=("Arial", 12))
entry_login_biometric_data.grid(row=6, column=1, padx=10, pady=10, sticky="w")

login_button = ttk.Button(frame, text="Login", command=authenticate_user, width=20)
login_button.grid(row=7, columnspan=2, pady=20)

# Run the main window loop
root.mainloop()
