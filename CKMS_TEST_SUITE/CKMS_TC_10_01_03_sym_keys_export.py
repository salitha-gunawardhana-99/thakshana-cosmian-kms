"""

10.1.3 ckms sym keys export

Export a key from the KMS

Usage

ckms sym keys export [options] <KEY_FILE>

Arguments

<KEY_FILE> The file to export the key to

--key-id [-k] <KEY_ID> The key unique identifier stored in the KMS. If not specified, tags should be specified

--tag [-t] <TAG> Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

--key-format [-f] <KEY_FORMAT> The format of the key

    json-ttlv [default]. It should be the format to use to later re-import the key
    sec1-pem and sec1-deronly apply to NIST EC private keys (Not Curve25519 or X448)
    pkcs1-pem and pkcs1-der only apply to RSA private and public keys
    pkcs8-pem and pkcs8-der only apply to RSA and EC private keys
    spki-pem and spki-der only apply to RSA and EC public keys
    raw returns the raw bytes of
        symmetric keys
        Covercrypt keys
        wrapped keys

Possible values: "json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "spki-pem", "spki-der", "base64", "raw" [default: "json-ttlv"]

--unwrap [-u] <UNWRAP> Unwrap the key if it is wrapped before export

Possible values: "true", "false" [default: "false"]

--wrap-key-id [-w] <WRAP_KEY_ID> The id of the key/certificate to use to wrap this key before export

--allow-revoked [-i] <ALLOW_REVOKED> Allow exporting revoked and destroyed keys. The user must be the owner of the key. Destroyed keys have their key material removed.

Possible values: "true", "false" [default: "false"]

"""

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
