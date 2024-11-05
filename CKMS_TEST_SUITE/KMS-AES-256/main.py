import botan3 as botan
import os
import subprocess
import time
import logging
from typing import Optional, Tuple

# Constants
AES_MODE = 'AES-256/CBC'
BLOCK_SIZE = 16
IV_SIZE = 16
KEY_TYPE = "aes"
KEY_LENGTH = 256
KMS_PORT = 9998
KMS_CONTAINER_NAME = "kms"
KMS_IMAGE = "ghcr.io/cosmian/kms:4.17.0"

# # Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to run a shell command
def run_command(command: str) -> Optional[str]:
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e.output.decode('utf-8').strip()}")
        return None

# Function to start the Cosmian KMS server
def start_kms_server():
    existing_container = run_command(f"docker ps -q -f name={KMS_CONTAINER_NAME}")
    if existing_container:
        logging.info("KMS server is already running.")
        return

    existing_container = run_command(f"docker ps -aq -f name={KMS_CONTAINER_NAME}")
    if existing_container:
        logging.info("KMS container found. Starting the KMS server...")
        run_command(f"docker start {KMS_CONTAINER_NAME}")
    else:
        logging.info("KMS container not found. Starting a new KMS container...")
        run_command(f"docker run -d -p {KMS_PORT}:{KMS_PORT} --name {KMS_CONTAINER_NAME} {KMS_IMAGE}")
    
    logging.info("Waiting for KMS server to start...")
    # Implement a loop to wait until the server is active
    for _ in range(10):
        if run_command(f"docker ps -q -f name={KMS_CONTAINER_NAME}"):
            logging.info("KMS server started.")
            return
        time.sleep(1)
    logging.error("KMS server failed to start.")

# Function to generate a key using ckms
def generate_key(key_name: str, key_type: str = KEY_TYPE, key_length: int = KEY_LENGTH, temp_key_file: str = 'temp_key_check.key'):
    logging.info(f"Checking if key '{key_name}' already exists...")
    result = run_command(f"ckms sym keys export --tag {key_name} --key-format raw {temp_key_file}")
    
    if result:
        logging.info(f"Key '{key_name}' already exists. Skipping key generation.")
        os.remove(temp_key_file)
    else:
        logging.info(f"Key '{key_name}' does not exist. Generating key...")
        run_command(f"ckms sym keys create --algorithm {key_type} --number-of-bits {key_length} --tag {key_name}")
        logging.info(f"Key '{key_name}' generated.")

# Function to retrieve the key from the KMS using ckms
def retrieve_key(key_name: str, key_file: str = 'key_exported.key') -> Optional[bytes]:
    logging.info(f"Retrieving key '{key_name}'...")
    result = run_command(f"ckms sym keys export --tag {key_name} --key-format raw {key_file}")
    if result:
        with open(key_file, 'rb') as f:
            key_data = f.read()
        os.remove(key_file)
        return key_data
    logging.error(f"Failed to retrieve the key '{key_name}'.")
    return None

def print_hex(label: str, data: bytes):
    hex_data = data.hex()
    logging.info(f'{label}: {hex_data}')

def pad(data: bytes, block_size: int) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    return data[:-padding_len]

def string_to_bytes(s: str) -> bytes:
    return s.encode('utf-8')

def bytes_to_string(b: bytes) -> str:
    return b.decode('utf-8')

def encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    try:
        cipher = botan.SymmetricCipher(AES_MODE)
        cipher.set_key(key)
        iv = os.urandom(IV_SIZE)
        cipher.start(iv)
        padded_plaintext = pad(plaintext, BLOCK_SIZE)
        ciphertext = cipher.finish(padded_plaintext)
        print_hex("AES-256 ____plain text", padded_plaintext)
        print_hex("AES-256 encrypted text", ciphertext)
        return iv, ciphertext
    except botan.BotanException as e:
        logging.error(f"Encryption error: {e}")
        return b'', b''

def decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    try:
        cipher = botan.SymmetricCipher(AES_MODE, False)
        cipher.set_key(key)
        cipher.start(iv)
        plaintext = cipher.finish(ciphertext)
        unpadded_plaintext = unpad(plaintext)
        print_hex("AES-256 decrypted text", unpadded_plaintext)
        return unpadded_plaintext
    except botan.BotanException as e:
        logging.error(f"Decryption error: {e}")
        return b''

def main():
    start_kms_server()
    key_name = "sym_encryption_key"
    generate_key(key_name)
    key = retrieve_key(key_name)

    if key:
        message = "This is a test message"
        iv, ciphertext = encrypt(key, string_to_bytes(message))
        plaintext = decrypt(key, iv, ciphertext)
        logging.info(f'Decrypted message: {bytes_to_string(plaintext)}')

if __name__ == "__main__":
    main()
