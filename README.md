# CRYPTOGRAPHY-IMAGE-TRANSFER
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from PIL import Image
import io

# Utility functions
def generate_rsa_keys():
    """Generate RSA public and private keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

def encrypt_image(image_path, key):
    """Encrypt an image using AES encryption."""
    with open(image_path, "rb") as image_file:
        image_data = image_file.read()

    # Generate a random IV
    iv = os.urandom(16)

    # Encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(image_data) + encryptor.finalize()

    return iv, ciphertext

def decrypt_image(ciphertext, key, iv, output_path):
    """Decrypt an encrypted image using AES decryption."""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Write decrypted data to file
    with open(output_path, "wb") as output_file:
        output_file.write(decrypted_data)

def hash_image(image_path):
    """Generate a hash for an image file to ensure integrity."""
    digest = hashes.Hash(SHA256(), backend=default_backend())
    with open(image_path, "rb") as image_file:
        while chunk := image_file.read(4096):
            digest.update(chunk)
    return digest.finalize()

def save_encrypted_metadata(encrypted_data, metadata_file):
    """Save encrypted data and metadata."""
    with open(metadata_file, "wb") as file:
        file.write(encrypted_data)

# Main workflow
if __name__ == "__main__":
    # Step 1: Generate keys
    private_key, public_key = generate_rsa_keys()

    # Step 2: Save the keys to disk
    with open("private_key.pem", "wb") as f:
        f.write(private_key)

    with open("public_key.pem", "wb") as f:
        f.write(public_key)

    # Step 3: Encrypt an image
    image_path = "sample.jpg"  # Replace with your image file
    key = os.urandom(32)  # AES-256 key
    iv, encrypted_image = encrypt_image(image_path, key)

    # Save encrypted image and metadata
    save_encrypted_metadata(encrypted_image, "encrypted_image.bin")

    # Step 4: Hash the image for integrity verification
    image_hash = hash_image(image_path)
    print("Image Hash:", image_hash.hex())

    # Step 5: Decrypt the image
    output_path = "decrypted_sample.jpg"
    decrypt_image(encrypted_image, key, iv, output_path)
    print(f"Decrypted image saved at {output_path}")
