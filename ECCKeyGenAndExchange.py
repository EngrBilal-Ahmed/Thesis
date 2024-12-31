from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.backends import default_backend  # Fix: Added import

# Generate ECC key pair
def generate_keys():
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

# Key Exchange
def perform_key_exchange(private_key, peer_public_key_bytes):
    peer_public_key = deserialize_public_key(peer_public_key_bytes)
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key

# Example Usage
private_key, public_key = generate_keys()
peer_private_key, peer_public_key = generate_keys()

# Serialize public key for transmission
peer_public_bytes = serialize_public_key(peer_public_key)

# Key exchange
shared_key = perform_key_exchange(private_key, peer_public_bytes)
print(f"Shared Key: {shared_key.hex()}")
