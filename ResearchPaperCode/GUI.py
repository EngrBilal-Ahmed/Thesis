import hashlib
import random
import tkinter as tk
from tkinter import messagebox


# Simple hash function using hashlib for SHA256 hashing
def simple_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


# Random number generator for creating random integers
def generate_random():
    return random.randint(1, 100000)


# Simulating a user database with login attempts
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

# Max login attempts before account is locked
MAX_LOGIN_ATTEMPTS = 3


# Registration Function
def register_user():
    user_id = entry_register_id.get()
    password = entry_register_password.get()
    biometric_data = entry_register_biometric_data.get()

    if user_id in users_db:
        messagebox.showerror("Registration Error", "User ID already exists.")
    else:
        hashed_password = simple_hash(password)
        users_db[user_id] = {
            "password": hashed_password,
            "biometric_data": biometric_data,
            "login_attempts": 0
        }
        messagebox.showinfo("Registration Successful", f"User {user_id} registered successfully!")
        reset_register_fields()


# Login Function
def login_user():
    user_id = entry_login_id.get()
    password = entry_login_password.get()
    biometric_data = entry_login_biometric_data.get()

    # Check if user exists in the database
    if user_id not in users_db:
        messagebox.showerror("Login Error", "User ID does not exist.")
        return

    # Check if account is locked due to multiple failed login attempts
    if users_db[user_id]["login_attempts"] >= MAX_LOGIN_ATTEMPTS:
        messagebox.showerror("Login Error", "Account locked due to too many failed attempts.")
        return

    # Check password
    if users_db[user_id]["password"] != simple_hash(password):
        users_db[user_id]["login_attempts"] += 1
        messagebox.showerror("Login Error", "Incorrect password.")
        return

    # Check biometric data (Simulated match check)
    if users_db[user_id]["biometric_data"] != biometric_data:
        users_db[user_id]["login_attempts"] += 1
        messagebox.showerror("Login Error", "Biometric data mismatch.")
        return

    # Reset login attempts after successful login
    users_db[user_id]["login_attempts"] = 0
    messagebox.showinfo("Login Successful", f"Welcome {user_id}!")


# Reset Register Fields
def reset_register_fields():
    entry_register_id.delete(0, tk.END)
    entry_register_password.delete(0, tk.END)
    entry_register_biometric_data.delete(0, tk.END)


# Reset Login Fields
def reset_login_fields():
    entry_login_id.delete(0, tk.END)
    entry_login_password.delete(0, tk.END)
    entry_login_biometric_data.delete(0, tk.END)


# Create the main window
root = tk.Tk()
root.title("User Registration and Login")

# Register Section
frame_register = tk.Frame(root)
frame_register.pack(pady=10)

label_register_id = tk.Label(frame_register, text="User ID:")
label_register_id.grid(row=0, column=0, padx=5, pady=5)
entry_register_id = tk.Entry(frame_register)
entry_register_id.grid(row=0, column=1, padx=5, pady=5)

label_register_password = tk.Label(frame_register, text="Password:")
label_register_password.grid(row=1, column=0, padx=5, pady=5)
entry_register_password = tk.Entry(frame_register, show="*")
entry_register_password.grid(row=1, column=1, padx=5, pady=5)

label_register_biometric_data = tk.Label(frame_register, text="Biometric Data:")
label_register_biometric_data.grid(row=2, column=0, padx=5, pady=5)
entry_register_biometric_data = tk.Entry(frame_register)
entry_register_biometric_data.grid(row=2, column=1, padx=5, pady=5)

register_button = tk.Button(frame_register, text="Register", command=register_user)
register_button.grid(row=3, columnspan=2, pady=10)

# Login Section
frame_login = tk.Frame(root)
frame_login.pack(pady=10)

label_login_id = tk.Label(frame_login, text="User ID:")
label_login_id.grid(row=0, column=0, padx=5, pady=5)
entry_login_id = tk.Entry(frame_login)
entry_login_id.grid(row=0, column=1, padx=5, pady=5)

label_login_password = tk.Label(frame_login, text="Password:")
label_login_password.grid(row=1, column=0, padx=5, pady=5)
entry_login_password = tk.Entry(frame_login, show="*")
entry_login_password.grid(row=1, column=1, padx=5, pady=5)

label_login_biometric_data = tk.Label(frame_login, text="Biometric Data:")
label_login_biometric_data.grid(row=2, column=0, padx=5, pady=5)
entry_login_biometric_data = tk.Entry(frame_login)
entry_login_biometric_data.grid(row=2, column=1, padx=5, pady=5)

login_button = tk.Button(frame_login, text="Login", command=login_user)
login_button.grid(row=3, columnspan=2, pady=10)

# Run the main window loop
root.mainloop()
