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
