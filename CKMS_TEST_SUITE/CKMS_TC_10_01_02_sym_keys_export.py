import unittest
import re
import CKMS_general
import CKMS_keys


class TestCkmsSymKeysExport(unittest.TestCase):
    def setUp(self):
        CKMS_general.start_kms_server()  # Ensure the KMS server is running
        self.test_key_tags = ["export-test-key-tag2"]

        # Assuming keys are generated beforehand or in the setup process
        output = CKMS_keys.generate_key(key_tag=self.test_key_tags[0],
                                       key_type="aes", key_length=256)

        # Regular expression to match the UUID (unique identifier)
        match = re.search(r"Unique identifier:\s+([a-f0-9\-]+)", output[0])
        if match:
            self.test_key_id = match.group(1)
            print(f"Extracted Unique ID: {self.test_key_id}")
        else:
            self.test_key_id = None
            print("Unique identifier not found.")

    def tearDown(self):
        CKMS_keys.revoke_key(revocation_reason="Testing",
                            tags=self.test_key_tags)
        # CKMS_sym.destroy_key(tags=self.test_key_tags)  # Cleanup the test key

    def test_export_key_with_key_id(self):
        print("\nStarting test case: test_export_key_with_key_id")

        exported_key = CKMS_keys.export_key(key_id=self.test_key_id)

        # Verify that the exported key is not None
        self.assertIsNotNone(
            exported_key, "The command failed and returned None.")

        # Print the exported key in hexadecimal format for verification
        CKMS_general.print_hex("Exported_key: ", exported_key)

        print("Finishing test case: test_export_key_with_key_id\n")

    def test_export_key_with_invalid_key_id(self):
        print("\nStarting test case: test_export_key_invalid_key_id")

        CKMS_keys.revoke_key(revocation_reason="Testing",
                            key_id=self.test_key_id)

        exported_key = CKMS_keys.export_key(key_id=self.test_key_id)

        # Verify that the exported key is not None
        self.assertIsNone(
            exported_key, "The command failed and returned a key.")

        print("Finishing test case: test_export_key_invalid_key_id\n")

    def test_export_key_with_tags(self):
        print("\nStarting test case: test_export_key_with_tags")

        exported_key = CKMS_keys.export_key(tags=self.test_key_tags)

        # Verify that the exported key is not None
        self.assertIsNotNone(
            exported_key, "The command failed and returned None.")

        # Print the exported key in hexadecimal format for verification
        CKMS_general.print_hex("Exported_key: ", exported_key)

        print("Finishing test case: test_export_key_with_tags\n")

    def test_export_key_with_invalid_tags(self):
        print("\nStarting test case: test_export_key_with_invalid_tags")

        CKMS_keys.revoke_key(revocation_reason="Testing",
                            tags=self.test_key_tags)

        exported_key = CKMS_keys.export_key(tags=self.test_key_tags)

        # Verify that the exported key is not None
        self.assertIsNone(
            exported_key, "The command failed and returned a key.")

        print("Finishing test case: test_export_key_with_invalid_tags\n")

    # def test_export_key_in_json_ttlv_format(self):
    #     print("Starting test case: test_export_key_in_json_ttlv_format")
    #     output = CKMS_sym.run_command(
    #         f"ckms sym keys export -k {self.test_key_id} -f json-ttlv {self.exported_file}")
    #     self.assertIsNotNone(output, "The command failed and returned None.")
    #     self.assertTrue(os.path.exists(self.exported_file),
    #                     "Exported key file does not exist.")
    #     print("Finishing test case: test_export_key_in_json_ttlv_format")

    # def test_export_key_in_pkcs8_pem_format(self):
    #     print("Starting test case: test_export_key_in_pkcs8_pem_format")
    #     output = CKMS_sym.run_command(
    #         f"ckms sym keys export -k {self.test_key_id} -f pkcs8-pem {self.exported_file}")
    #     self.assertIsNotNone(output, "The command failed and returned None.")
    #     self.assertTrue(os.path.exists(self.exported_file),
    #                     "Exported key file does not exist.")
    #     print("Finishing test case: test_export_key_in_pkcs8_pem_format")

    # def test_export_key_with_unwrap(self):
    #     print("Starting test case: test_export_key_with_unwrap")
    #     output = CKMS_sym.run_command(
    #         f"ckms sym keys export -k {self.test_key_id} -u true {self.exported_file}")
    #     self.assertIsNotNone(output, "The command failed and returned None.")
    #     self.assertTrue(os.path.exists(self.exported_file),
    #                     "Exported key file does not exist.")
    #     print("Finishing test case: test_export_key_with_unwrap")

    # def test_export_key_with_wrap_key_id(self):
    #     print("Starting test case: test_export_key_with_wrap_key_id")
    #     wrap_key_id = "wrap-key-id"
    #     output = CKMS_sym.run_command(
    #         f"ckms sym keys export -k {self.test_key_id} -w {wrap_key_id} {self.exported_file}")
    #     self.assertIsNotNone(output, "The command failed and returned None.")
    #     self.assertTrue(os.path.exists(self.exported_file),
    #                     "Exported key file does not exist.")
    #     print("Finishing test case: test_export_key_with_wrap_key_id")

    # def test_export_revoked_key(self):
    #     print("Starting test case: test_export_revoked_key")
    #     # Assuming this method revokes the key
    #     CKMS_sym.revoke_key(self.test_key_id)
    #     output = CKMS_sym.run_command(
    #         f"ckms sym keys export -k {self.test_key_id} -i true {self.exported_file}")
    #     self.assertIsNone(
    #         output, "Expected the command to fail for a revoked key.")
    #     print("Finishing test case: test_export_revoked_key")

    # def test_export_destroyed_key(self):
    #     print("Starting test case: test_export_destroyed_key")
    #     CKMS_sym.destroy_key(tags=[self.test_key_id])
    #     output = CKMS_sym.run_command(
    #         f"ckms sym keys export -k {self.test_key_id} -i true {self.exported_file}")
    #     self.assertIsNone(
    #         output, "Expected the command to fail for a destroyed key.")
    #     print("Finishing test case: test_export_destroyed_key")


if __name__ == '__main__':
    unittest.main()
