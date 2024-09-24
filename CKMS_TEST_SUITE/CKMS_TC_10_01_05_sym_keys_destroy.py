import unittest
import logging
import CKMS_general
import CKMS_keys

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestCkmsSymKeysDestroy(unittest.TestCase):

    def setUp(self):
        print("")
        
        logging.info("Setting up KMS server and generating a symmetric key.")
        CKMS_general.start_kms_server()
        
        # Generate an key for revoke test
        self.test_key_tags = ["test_sym_key"]
        self.test_key_id = CKMS_keys.generate_key(tags=self.test_key_tags[0])[1]
        
        self.revocation_reason = "Testing"
        
        print("")
        
    def tearDown(self):
        print("")
        
        # Remove test key after every test scenario        
        CKMS_keys.revoke_key(revocation_reason="Testing", tags=self.test_key_tags)
        CKMS_keys.destroy_key(tags=self.test_key_tags)
            
        print("")
        print("=" * 120)

    def test_destroy_key_by_id(self):
        print("")
        
        # Remove test key after every test scenario        
        CKMS_keys.revoke_key(revocation_reason="Testing", tags=self.test_key_tags)
        CKMS_keys.destroy_key(tags=self.test_key_tags)
            
        print("")
        print("=" * 120)

    def test_destroy_certificate_by_id(self):
        logging.info("Starting test case: test_destroy_certificate_by_id")
        
        CKMS_keys.revoke_key(revocation_reason="testing",tags=self.test_key_tags)
        
        status = CKMS_keys.destroy_key(key_id=self.test_key_id)

        self.assertIn("pass", status, "Failed to destroy key by ID.")

        logging.info("Starting test case: test_destroy_certificate_by_id")

    def test_destroy_certificate_by_tag(self):
        logging.info("Starting test case: test_destroy_certificate_by_tag")
        
        CKMS_keys.revoke_key(revocation_reason="testing",tags=self.test_key_tags)
        
        status = CKMS_keys.destroy_key(tags=self.test_key_tags)

        self.assertIn("pass", status, "Failed to destroy key by ID.")

        logging.info("Starting test case: test_destroy_certificate_by_tag")

    def test_destroy_certificate_without_id_or_tag(self):
        logging.info("Starting test case: test_destroy_certificate_without_id_or_tag")
        
        CKMS_keys.revoke_key(revocation_reason="testing",tags=self.test_key_tags)
        
        status = CKMS_keys.destroy_key()

        self.assertIn("fail", status, "Invalid destruction occured.")

        logging.info("Starting test case: test_destroy_certificate_without_id_or_tag")

if __name__ == '__main__':
    unittest.main()
