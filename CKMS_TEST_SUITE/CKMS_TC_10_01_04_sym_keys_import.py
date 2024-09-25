"""

10.1.4 ckms sym keys import

Import a private or public key in the KMS.

Usage

ckms sym keys import [options] <KEY_FILE> [KEY_ID]

Arguments

<KEY_FILE> The KMIP JSON TTLV key file

<KEY_ID> The unique id of the key; a unique id based on the key material is generated if not specified

--key-format [-f] <KEY_FORMAT> The format of the key

Possible values: "json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8", "spki", "aes", "chacha20" [default: "json-ttlv"]

--public-key-id [-p] <PUBLIC_KEY_ID> For a private key: the corresponding public key id if any

--private-key-id [-k] <PRIVATE_KEY_ID> For a public key: the corresponding private key id if any

--certificate-id [-c] <CERTIFICATE_ID> For a public or private key: the corresponding certificate id if any

--unwrap [-u] <UNWRAP> In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

Possible values: "true", "false" [default: "false"]

--replace [-r] <REPLACE_EXISTING> Replace an existing key under the same id

Possible values: "true", "false" [default: "false"]

--tag [-t] <TAG> The tag to associate with the key. To specify multiple tags, use the option multiple times

--key-usage <KEY_USAGE> For what operations should the key be used

Possible values: "sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"

"""

import unittest
import os
import logging
import CKMS_general
import CKMS_keys

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestCkmsSymKeysImport(unittest.TestCase):

    def setUp(self):
        print("")
        
        logging.info("Setting up KMS server.")
        CKMS_general.start_kms_server()
        
        # Set up variables for testing
        self.key_file_json = "sym_key_for_import.json"
        self.key_file_key = "sym_key_for_import.key"
        self.key_file_bin = "sym_key_for_import.bin"
        
        self.key_name = "MyKeyfor_import"
        
        self.import_key_tags = ["test-import-sym-key"]
        self.imported_key_id = None
        
        print("")

    def tearDown(self):
        print("")
        
        # Remove created test key after every test scenario
        CKMS_keys.revoke_key(revocation_reason="testing",tags=self.import_key_tags)
        CKMS_keys.destroy_key(tags=self.import_key_tags)
        
        # Clean up test key files
        # if os.path.exists(self.key_file_json):
        #     os.remove(self.key_file_json)
        # if os.path.exists(self.key_file_key):
        #     os.remove(self.key_file_key)
        # if os.path.exists(self.key_file_bin):
        #     os.remove(self.key_file_bin)
        
        print("")
        print("=" * 120)
        
    def test_import_symkey_from_key_file(self):
        logging.info("Starting test case: test_import_symkey_from_key_file")
        
        self.imported_key_id = CKMS_keys.import_key(
            key_file = self.key_file_key,
            key_format = "aes",
            tags=self.import_key_tags,
        )[1]
        
        # Assert the key is imported successfully
        self.assertIsNotNone(self.imported_key_id, "Failed to import the key.")

        logging.info("Finishing test case: test_import_symkey_from_key_file")
        
    def test_import_symkey_from_bin_file(self):
        logging.info("Starting test case: test_import_symkey_from_bin_file")
        
        self.imported_key_id = CKMS_keys.import_key(
            key_file = self.key_file_bin,
            key_format = "aes",
            tags=self.import_key_tags,
        )[1]
        
        # Assert the key is imported successfully
        self.assertIsNotNone(self.imported_key_id, "Failed to import the key.")

        logging.info("Finishing test case: test_import_symkey_from_bin_file")
        
    def test_import_symkey_from_json_file(self):
        logging.info("Starting test case: test_import_symkey_from_json_file")
        
        self.imported_key_id = CKMS_keys.import_key(
            key_file = self.key_file_json,
            key_format = "json-ttlv",
            tags=self.import_key_tags,
        )[1]
        
        # Assert the key is imported successfully
        self.assertIsNotNone(self.imported_key_id, "Failed to import the key.")

        logging.info("Finishing test case: test_import_symkey_from_json_file")

if __name__ == '__main__':
    unittest.main()
