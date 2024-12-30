import requests

server_url = "http://<server-ip>:5000/authenticate"
payload = {"password": "hashed_password_here", "biometric": "encrypted_biometric_here"}

response = requests.post(server_url, json=payload)
print(response.json())
