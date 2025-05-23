# encryption.py
import os
from cryptography.fernet import Fernet

# Retrieve the key from the environment variable
# setx ENCRYPTION_KEY "bVck39AsLz8KNJY_UIT3uhZfRuFNDBRWv91lFEq4bF0="

key = os.getenv("ENCRYPTION_KEY")

if not key:
    raise ValueError("ENCRYPTION_KEY environment variable not set")

fernet = Fernet(key)

def encrypt_data(data):
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data):
    return fernet.decrypt(encrypted_data).decode()
