import unittest
import CKMS_general
import CKMS_keys


class TestCkmsSymKeysDestroy(unittest.TestCase):

    def setUp(self):
        # Setup for common variables, key IDs, or any other required setup.
        self.key_id = "test_key_id"
        self.tag = "test-tag"

    def test_destroy_key_by_id(self):
        print("Starting test case: test_destroy_key_by_id")
        output = CKMS_keys.run_command(
            f"ckms sym keys destroy -k {self.key_id}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_destroy_key_by_id")

    def test_destroy_key_by_tag(self):
        print("Starting test case: test_destroy_key_by_tag")
        output = CKMS_keys.run_command(f"ckms sym keys destroy -t {self.tag}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_destroy_key_by_tag")

    def test_destroy_key_without_id_or_tag(self):
        print("Starting test case: test_destroy_key_without_id_or_tag")
        output = CKMS_keys.run_command(f"ckms sym keys destroy")
        self.assertIsNone(
            output, "Expected the command to fail, but it succeeded.")
        print("Finishing test case: test_destroy_key_without_id_or_tag")

    def test_destroy_key_with_invalid_id(self):
        print("Starting test case: test_destroy_key_with_invalid_id")
        output = CKMS_keys.run_command(
            f"ckms sym keys destroy -k invalid_key_id")
        self.assertIsNone(
            output, "Expected the command to fail, but it succeeded.")
        print("Finishing test case: test_destroy_key_with_invalid_id")

    def test_destroy_key_with_invalid_tag(self):
        print("Starting test case: test_destroy_key_with_invalid_tag")
        output = CKMS_keys.run_command(f"ckms sym keys destroy -t invalid_tag")
        self.assertIsNone(
            output, "Expected the command to fail, but it succeeded.")
        print("Finishing test case: test_destroy_key_with_invalid_tag")

    def test_destroy_key_by_multiple_tags(self):
        print("Starting test case: test_destroy_key_by_multiple_tags")
        additional_tag = "backup-tag"
        output = CKMS_keys.run_command(
            f"ckms sym keys destroy -t {self.tag} -t {additional_tag}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_destroy_key_by_multiple_tags")

    def test_destroy_key_by_id_and_tag(self):
        print("Starting test case: test_destroy_key_by_id_and_tag")
        output = CKMS_keys.run_command(
            f"ckms sym keys destroy -k {self.key_id} -t {self.tag}")
        self.assertIsNotNone(output, "The command failed and returned None.")
        print("Finishing test case: test_destroy_key_by_id_and_tag")


if __name__ == '__main__':
    unittest.main()
