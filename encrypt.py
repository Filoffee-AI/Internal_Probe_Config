import json
import os
from cryptography.fernet import Fernet
import keyring


def set_password(service, username, password):
    keyring.set_password(service, username, password)


# Generate a secret key for encryption and decryption
def generate_key():
    key = Fernet.generate_key().decode('utf-8')
    # with open("secret.key", "wb") as key_file:
    #     key_file.write(key)
    # os.chmod("secret.key", 0o700)
    set_password("Gyan_LinkEye", "Key", key)


# Load the secret key from a file
def load_key():
    # return open("secret.key", "rb").read()
    key = keyring.get_password("Gyan_LinkEye", "Key")
    if key:
        return key
    else:
        return "Password not found in keyring."


# Encrypt JSON data and write it to a file
def encrypt_json(data, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(data).encode())
    with open("data.json", "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)


if __name__ == "__main__":
    # Generate and save the secret key
    generate_key()

    # Load the secret key
    key = load_key()
    # Sample JSON data to encrypt
    data_to_encrypt = json.load(open("config.json", "r"))

    # Encrypt and save the JSON data
    encrypt_json(data_to_encrypt, key)
