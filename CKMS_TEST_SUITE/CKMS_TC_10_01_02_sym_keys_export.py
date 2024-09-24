import unittest
import logging
import os
import CKMS_general
import CKMS_keys

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestCkmsSymKeysExport(unittest.TestCase):
    def setUp(self):
        print("")
        
        logging.info("Setting up KMS server.")
        self.test_key_tags = ["export-test-key"]

        # Assuming keys are generated beforehand or in the setup process
        self.test_key_id = CKMS_keys.generate_key(tags=self.test_key_tags[0],
                                       key_type="aes", key_length=256)[1]
        
        # Set up variables for testing
        # self.export_file_pem = "exported_sym_key.pem"
        # self.export_file_der = "exported_sym_key.der"
        self.export_file_json = "exported_sym_key.json"
        self.export_file_key = "exported_sym_key.key"
        self.export_file_bin = "exported_sym_key.bin"
        
        print("")

    def tearDown(self):
        print("")
        
        CKMS_keys.revoke_key(revocation_reason="Testing",
                            tags=self.test_key_tags)
        CKMS_keys.destroy_key(tags=self.test_key_tags)
        
        # Clean up exported files
        # if os.path.exists(self.export_file_pem):
        #     os.remove(self.export_file_pem)
        # if os.path.exists(self.export_file_der):
        #     os.remove(self.export_file_der)
        if os.path.exists(self.export_file_json):
            os.remove(self.export_file_json)
        if os.path.exists(self.export_file_key):
            os.remove(self.export_file_key)
        if os.path.exists(self.export_file_bin):
            os.remove(self.export_file_bin)
        
        print("")
        print("=" * 120)

    def test_export_key_with_key_id(self):
        logging.info("Starting test case: test_export_key_with_key_id")

        exported_key = CKMS_keys.export_key(key_id=self.test_key_id)

        # Verify that the exported key is not None
        self.assertIsNotNone(
            exported_key, "The command failed and returned None.")

        logging.info("Finishing test case: test_export_key_with_key_id")

    def test_export_key_with_invalid_key_id(self):
        logging.info("Starting test case: test_export_key_invalid_key_id")

        CKMS_keys.revoke_key(revocation_reason="Testing",
                            key_id=self.test_key_id)

        exported_key = CKMS_keys.export_key(key_id=self.test_key_id)

        # Verify that the exported key is not None
        self.assertIsNone(
            exported_key, "The command failed and returned a key.")

        logging.info("Finishing test case: test_export_key_invalid_key_id")

    def test_export_key_with_tags(self):
        logging.info("Starting test case: test_export_key_with_tags")

        exported_key = CKMS_keys.export_key(tags=self.test_key_tags)

        # Verify that the exported key is not None
        self.assertIsNotNone(
            exported_key, "The command failed and returned None.")

        logging.info("Finishing test case: test_export_key_with_tags")

    def test_export_key_with_invalid_tags(self):
        logging.info("Starting test case: test_export_key_with_invalid_tags")

        CKMS_keys.revoke_key(revocation_reason="Testing", tags=self.test_key_tags)

        exported_key = CKMS_keys.export_key(tags=self.test_key_tags)

        # Verify that the exported key is not None
        self.assertIsNone(
            exported_key, "The command failed and returned a key.")

        logging.info("Finishing test case: test_export_key_with_invalid_tags")

    def test_export_key_in_json_ttlv(self):
        logging.info("Starting test case: test_export_key_in_json_ttlv")

        exported_key = CKMS_keys.export_key(tags=self.test_key_tags, key_format="json-ttlv", key_file=self.export_file_json)

        # Verify that the exported key is not None
        self.assertIsNotNone(
            exported_key, "The command failed and returned None.")

        logging.info("Finishing test case: test_export_key_in_json_ttlv")

    def test_export_key_in_raw_keyfile(self):
        logging.info("Starting test case: test_export_key_in_raw_keyfile")

        exported_key = CKMS_keys.export_key(tags=self.test_key_tags, key_format="raw", key_file=self.export_file_key)

        # Verify that the exported key is not None
        self.assertIsNotNone(
            exported_key, "The command failed and returned None.")

        logging.info("Finishing test case: test_export_key_in_raw_keyfile")
        
    def test_export_key_in_raw_binfile(self):
        logging.info("Starting test case: test_export_key_in_raw_binfile")

        exported_key = CKMS_keys.export_key(tags=self.test_key_tags, key_format="raw", key_file=self.export_file_bin)

        # Verify that the exported key is not None
        self.assertIsNotNone(
            exported_key, "The command failed and returned None.")

        logging.info("Finishing test case: test_export_key_in_raw_binfile")

if __name__ == '__main__':
    unittest.main()
