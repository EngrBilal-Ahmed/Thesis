import requests

#server_url = "http://172.19.121.189:5000/authenticate"
server_url = "http://localhost:5000/authenticate"
payload = {"password": "hashed_password_here", "biometric": "encrypted_biometric_here"}

response = requests.post(server_url, json=payload)
print(response.json())
