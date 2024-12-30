from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate ECC key pair
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize and deserialize public keys
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

# Key exchange
def perform_key_exchange(private_key, peer_public_key_bytes):
    peer_public_key = deserialize_public_key(peer_public_key_bytes)
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key

# Example usage
private_key, public_key = generate_ecc_keys()
peer_private_key, peer_public_key = generate_ecc_keys()

shared_key_1 = perform_key_exchange(private_key, serialize_public_key(peer_public_key))
shared_key_2 = perform_key_exchange(peer_private_key, serialize_public_key(public_key))

assert shared_key_1 == shared_key_2  # Shared keys must match
print(f"Shared Key: {shared_key_1.hex()}")
