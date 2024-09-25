"""

10.1.1 ckms sym keys create

Create a new symmetric key

Usage

ckms sym keys create [options]

Arguments

--number-of-bits [-l] <NUMBER_OF_BITS> The length of the generated random key or salt in bits

--bytes-b64 [-k] <WRAP_KEY_B64> The symmetric key bytes or salt as a base 64 string

--algorithm [-a] <ALGORITHM> The algorithm

Possible values: "chacha20", "aes", "sha3", "shake" [default: "aes"]

--tag [-t] <TAG> The tag to associate with the key. To specify multiple tags, use the option multiple times

"""

import unittest
import logging
import CKMS_general
import CKMS_keys

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestCkmsSymKeysGenerate(unittest.TestCase):
    def setUp(self):
        print("")
        
        logging.info("Setting up KMS server and generating RSA key pair.")
        CKMS_general.start_kms_server()
        
        # Test data
        self.algo_list = ["chacha20", "aes", "sha3", "shake", "rsa", "ec"]
        self.len_list = [16, 64, 96, 100, 128, 200, 224, 256, 300, 384, 400, 512, 1024, 2048, 3072, 4096]
        self.key_length = 256
        
        print("")

    def tearDown(self):
        print("")
        print("=" * 120)

    def test_generate_sym_keys_with_valid_algorithms(self):
        logging.info("Starting test case: test_generate_sym_keys_with_valid_algorithms")
        print("")

        for algo in self.algo_list:
            for length in self.len_list:
                tags = f"sym_encryption_key_{algo}_{length}"
                CKMS_keys.generate_key(
                tags=tags, key_type=algo, key_length=length)
                
                CKMS_keys.revoke_key(revocation_reason="testing", tags=[tags])
                CKMS_keys.destroy_key(tags=[tags])
                
                print("")
                
            print("=" * 120)
            print("")
        
        logging.info("Completed test case: test_generate_sym_keys_with_valid_algorithms")

if __name__ == '__main__':
    unittest.main()
