def decrypt_data(ciphertext, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# Simulate authentication
def authenticate_user(input_password, stored_hashed_password, input_biometric, stored_biometric, salt):
    # Hash input password
    hashed_input_password = hash_password(input_password)

    # Verify password
    if hashed_input_password != stored_hashed_password:
        return False, "Password mismatch!"

    # Derive key from input password
    _, derived_key = derive_key(input_password)

    # Decrypt biometric data
    decrypted_biometric = decrypt_data(stored_biometric, derived_key, nonce)

    # Verify biometric
    if decrypted_biometric != input_biometric:
        return False, "Biometric mismatch!"

    return True, "Authentication successful!"

# Example usage
input_password = "SecurePass123"
input_biometric = b"sample_biometric_data"  # Replace with live biometric scan bytes

auth_status, message = authenticate_user(input_password, hashed_password, input_biometric, encrypted_biometric, salt)
print(message)
