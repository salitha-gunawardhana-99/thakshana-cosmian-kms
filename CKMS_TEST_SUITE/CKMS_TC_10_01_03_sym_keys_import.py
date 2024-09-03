import unittest
import os
import CKMS_sym


class TestCkmsSymKeysImport(unittest.TestCase):

    def setUp(self):
        # Setup for common variables, paths, or any required keys.
        self.test_key_file = "test_key_file.json"
        self.imported_key_id = "imported_key_id"
        self.public_key_id = "public_key_id"
        self.private_key_id = "private_key_id"
        self.certificate_id = "certificate_id"
        self.tag = "test-tag"
        # Create a test key file if necessary.
        with open(self.test_key_file, 'w') as f:
            f.write('{"key": "dummy_key_data"}')

    def tearDown(self):
        # Cleanup the key file and any other artifacts after each test.
        if os.path.exists(self.test_key_file):
            os.remove(self.test_key_file)

    def test_import_key_default_format(self):
        print("Starting test case: test_import_key_default_format")
        output = CKMS_sym.run_command(
            f"ckms sym keys import {self.test_key_file} {self.imported_key_id}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_import_key_default_format")

    def test_import_key_with_format(self):
        print("Starting test case: test_import_key_with_format")
        output = CKMS_sym.run_command(
            f"ckms sym keys import -f pem {self.test_key_file} {self.imported_key_id}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_import_key_with_format")

    def test_import_key_with_public_key_id(self):
        print("Starting test case: test_import_key_with_public_key_id")
        output = CKMS_sym.run_command(
            f"ckms sym keys import -p {self.public_key_id} {self.test_key_file}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_import_key_with_public_key_id")

    def test_import_key_with_private_key_id(self):
        print("Starting test case: test_import_key_with_private_key_id")
        output = CKMS_sym.run_command(
            f"ckms sym keys import -k {self.private_key_id} {self.test_key_file}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_import_key_with_private_key_id")

    def test_import_key_with_certificate_id(self):
        print("Starting test case: test_import_key_with_certificate_id")
        output = CKMS_sym.run_command(
            f"ckms sym keys import -c {self.certificate_id} {self.test_key_file}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_import_key_with_certificate_id")

    def test_import_key_with_unwrap(self):
        print("Starting test case: test_import_key_with_unwrap")
        output = CKMS_sym.run_command(
            f"ckms sym keys import -u true {self.test_key_file}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_import_key_with_unwrap")

    def test_import_key_with_replace_existing(self):
        print("Starting test case: test_import_key_with_replace_existing")
        output = CKMS_sym.run_command(
            f"ckms sym keys import -r true {self.test_key_file} {self.imported_key_id}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_import_key_with_replace_existing")

    def test_import_key_with_tag(self):
        print("Starting test case: test_import_key_with_tag")
        output = CKMS_sym.run_command(
            f"ckms sym keys import -t {self.tag} {self.test_key_file} {self.imported_key_id}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_import_key_with_tag")

    def test_import_key_invalid_key_file(self):
        print("Starting test case: test_import_key_invalid_key_file")
        output = CKMS_sym.run_command(
            f"ckms sym keys import invalid_key_file.json")
        self.assertIsNone(
            output, "Expected the command to fail, but it succeeded.")
        print("Finishing test case: test_import_key_invalid_key_file")

    def test_import_key_invalid_key_format(self):
        print("Starting test case: test_import_key_invalid_key_format")
        output = CKMS_sym.run_command(
            f"ckms sym keys import -f invalid-format {self.test_key_file}")
        self.assertIsNone(
            output, "Expected the command to fail, but it succeeded.")
        print("Finishing test case: test_import_key_invalid_key_format")

    def test_import_key_with_key_usage(self):
        print("Starting test case: test_import_key_with_key_usage")
        output = CKMS_sym.run_command(
            f"ckms sym keys import --key-usage sign {self.test_key_file} {self.imported_key_id}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_import_key_with_key_usage")


if __name__ == '__main__':
    unittest.main()
