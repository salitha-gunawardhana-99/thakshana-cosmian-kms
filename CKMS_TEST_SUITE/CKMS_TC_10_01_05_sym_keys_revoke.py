"""

10.1.5 ckms sym keys revoke

Revoke a symmetric key

Usage

ckms sym keys revoke [options] <REVOCATION_REASON>

Arguments

<REVOCATION_REASON> The reason for the revocation as a string

--key-id [-k] <KEY_ID> The key unique identifier of the key to revoke. If not specified, tags should be specified

--tag [-t] <TAG> Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

"""

import unittest
import logging
import CKMS_general
import CKMS_keys

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestCkmsSymKeysRevoke(unittest.TestCase):
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

    def test_revoke_symkey_by_id(self):
        logging.info("Starting test case: test_revoke_symkey_by_id")

        status = CKMS_keys.revoke_key(
            key_id=self.test_key_id,
            revocation_reason=self.revocation_reason
        )

        self.assertIn("pass", status, "Failed to revoke key by ID.")

        logging.info("Starting test case: test_revoke_symkey_by_id")

    def test_revoke_symkey_by_tag(self):
        logging.info("Starting test case: test_revoke_symkey_by_tag")

        status = CKMS_keys.revoke_key(
            tags=self.test_key_tags,
            revocation_reason=self.revocation_reason
        )

        self.assertIn("pass", status, "Failed to revoke key by ID.")

        logging.info("Starting test case: test_revoke_symkey_by_tag")

    def test_revoke_symkey_without_reason(self):
        logging.info("Starting test case: test_revoke_symkey_without_reason")

        status = CKMS_keys.revoke_key(
            key_id=self.test_key_id
        )

        self.assertIn("fail", status, "Invalid revocation occured.")

        logging.info("Starting test case: test_revoke_symkey_without_reason")

    def test_revoke_symkey_without_id_or_tag(self):
        logging.info("Starting test case: test_revoke_symkey_without_id_or_tag")

        status = CKMS_keys.revoke_key(
            revocation_reason=self.revocation_reason
        )

        self.assertIn("fail", status, "Invalid revocation occured.")

        logging.info("Starting test case: test_revoke_symkey_without_id_or_tag")

if __name__ == '__main__':
    unittest.main()
