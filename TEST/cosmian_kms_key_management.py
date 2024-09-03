# cosmian_kms_key_management.py

import subprocess

def create_symmetric_key(algorithm='aes', number_of_bits=256):
    """
    Create a symmetric key using the Cosmian KMS CLI.

    Parameters:
    algorithm (str): The encryption algorithm to use (e.g., 'aes', 'chacha20').
    number_of_bits (int): The length of the generated key in bits.

    Returns:
    str: The output of the key creation command if successful.
    None: If the command fails.
    """
    try:
        # Command to create a symmetric key with the specified algorithm and key length
        result = subprocess.run([
            'ckms', 'sym', 'keys', 'create',
            '--algorithm', algorithm,
            '--number-of-bits', str(number_of_bits)
        ], check=True, capture_output=True, text=True)
        
        # Return the output if successful
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error creating symmetric key: {e}")
        return None
