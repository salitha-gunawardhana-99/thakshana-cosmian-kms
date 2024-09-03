# test_cosmian_kms_key_management.py

import unittest
from cosmian_kms_key_management import create_symmetric_key

class TestCosmianKMSKeyManagement(unittest.TestCase):

    def test_create_aes_key(self):
        """
        Test the creation of a 256-bit AES symmetric key.
        """
        output = create_symmetric_key('aes', 256)
        self.assertIsNotNone(output, "Failed to create AES key.")
        self.assertIn("Key created", output, "Unexpected output from key creation.")

    def test_create_chacha20_key(self):
        """
        Test the creation of a 128-bit ChaCha20 symmetric key.
        """
        output = create_symmetric_key('chacha20', 128)
        self.assertIsNotNone(output, "Failed to create ChaCha20 key.")
        self.assertIn("Key created", output, "Unexpected output from key creation.")

if __name__ == "__main__":
    unittest.main()
