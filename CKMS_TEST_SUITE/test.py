import botan3 as botan
import os
from typing import Optional, Tuple
import General

def print_hex(label: str, data: bytes):
    hex_data = data.hex()
    General.logging.info(f'{label}: {hex_data}')

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
        cipher = botan.SymmetricCipher(General.AES_MODE)
        cipher.set_key(key)
        iv = os.urandom(General.IV_SIZE)
        cipher.start(iv)
        padded_plaintext = pad(plaintext, General.BLOCK_SIZE)
        ciphertext = cipher.finish(padded_plaintext)
        print_hex("AES-256 ____plain text", padded_plaintext)
        print_hex("AES-256 encrypted text", ciphertext)
        return iv, ciphertext
    except botan.BotanException as e:
        General.logging.error(f"Encryption error: {e}")
        return b'', b''

def decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    try:
        cipher = botan.SymmetricCipher(General.AES_MODE, False)
        cipher.set_key(key)
        cipher.start(iv)
        plaintext = cipher.finish(ciphertext)
        unpadded_plaintext = unpad(plaintext)
        print_hex("AES-256 decrypted text", unpadded_plaintext)
        return unpadded_plaintext
    except botan.BotanException as e:
        General.logging.error(f"Decryption error: {e}")
        return b''

def main():
    General.start_kms_server()
    key_name = "sym_encryption_key"
    General.generate_key(key_name)
    key = General.retrieve_key(key_name)

    if key:
        message = "This is a test message"
        iv, ciphertext = encrypt(key, string_to_bytes(message))
        plaintext = decrypt(key, iv, ciphertext)
        General.logging.info(f'Decrypted message: {bytes_to_string(plaintext)}')

if __name__ == "__main__":
    main()
