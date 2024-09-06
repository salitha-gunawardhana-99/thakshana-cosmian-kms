import botan3 as botan
import os
from typing import Optional, Tuple
import CKMS_keys


def print_hex(label: str, data: bytes):
    hex_data = data.hex()
    CKMS_keys.logging.info(f'{label}: {hex_data}')


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


# Constants
AES_MODE = 'AES-256/CBC'
BLOCK_SIZE = 16
IV_SIZE = 16
KEY_TYPE = "aes"
KEY_LENGTH = 256
KMS_PORT = 9998
KMS_CONTAINER_NAME = "kms"
KMS_IMAGE = "ghcr.io/cosmian/kms:4.17.0"


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
        CKMS_keys.logging.error(f"Encryption error: {e}")
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
        CKMS_keys.logging.error(f"Decryption error: {e}")
        return b''


def main():
    CKMS_keys.start_kms_server()
    key_tags = ["sym_encryption_key"]
    CKMS_keys.generate_key(key_tags[0])
    key1 = CKMS_keys.export_key(tags=key_tags)
    key = CKMS_keys.retrieve_key(key_tags[0])
    print(key1)
    print(key)

    if key:
        message = "This is a test message"
        iv, ciphertext = encrypt(key1, string_to_bytes(message))
        plaintext = decrypt(key1, iv, ciphertext)
        CKMS_keys.logging.info(
            f'Decrypted message: {bytes_to_string(plaintext)}')


if __name__ == "__main__":
    main()
