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

logging.info("Setting up KMS server...")
CKMS_general.start_kms_server()

CKMS_general.clear_database()

sut = CKMS_general.SUT
version = CKMS_general.VERSION

testing_category = "Symmetric Keys"
test_case_id = "CKMS_TC_10_01_04".replace("_", "\\_")
test_case_name = "sym_keys_import".replace("_", "\\_")
test_case_description = "Import symmetric keys from different supported file formats."

import latex_content

table_1 = latex_content.generate_latex_table_1(test_case_name, sut, version, testing_category, test_case_id, test_case_description)

with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(table_1)
            
print("")

class TestCkmsSymKeysImport(unittest.TestCase):
    # Class-level attributes to track overall test status
    all_tests_passed = True
    table_2 = latex_content.table_2_init
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.test_scenario = ""
        self.expected_result = ""
        self.obtained_result = ""
        self.error_row_color = "red!30"

    def setUp(self):
        print("")
        
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
        
    def test_01_import_symkey_from_key_file(self):
        logging.info("Starting test case: test_import_symkey_from_key_file")
        
        self.imported_key_id = CKMS_keys.import_key(
            key_file = self.key_file_key,
            key_format = "aes",
            tags=self.import_key_tags,
        )[1]
                
        try:
             # Assert the key is imported successfully
            self.assertIsNotNone(self.imported_key_id, "Failed to import the key.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_import_symkey_from_key_file: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_import_symkey_from_key_file: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_import_symkey_from_key_file".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Finishing test case: test_import_symkey_from_key_file")
        
    def test_02_import_symkey_from_bin_file(self):
        logging.info("Starting test case: test_import_symkey_from_bin_file")
        
        self.imported_key_id = CKMS_keys.import_key(
            key_file = self.key_file_bin,
            key_format = "aes",
            tags=self.import_key_tags,
        )[1]
        
        try:
             # Assert the key is imported successfully
            self.assertIsNotNone(self.imported_key_id, "Failed to import the key.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_import_symkey_from_bin_file: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_import_symkey_from_bin_file: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_import_symkey_from_bin_file".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Finishing test case: test_import_symkey_from_bin_file")
        
    def test_03_import_symkey_from_json_file(self):
        logging.info("Starting test case: test_import_symkey_from_json_file")
        
        self.imported_key_id = CKMS_keys.import_key(
            key_file = self.key_file_json,
            key_format = "json-ttlv",
            tags=self.import_key_tags,
        )[1]
        
        try:
            # Assert the key is imported successfully
            self.assertIsNotNone(self.imported_key_id, "Failed to import the key.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_import_symkey_from_json_file: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_import_symkey_from_json_file: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_import_symkey_from_json_file".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Finishing test case: test_import_symkey_from_json_file")

from datetime import datetime
date_of_execution = datetime.now().timestamp()  # This gives you the timestamp
timestamp = datetime.fromtimestamp(date_of_execution).strftime("%Y-%m-%d %H:%M:%S")
tester = "Unknown"
status = "Fail"
row_color = "red!30"

if __name__ == '__main__':
    # Create a test suite
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestCkmsSymKeysImport)

    # Run the test suite
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    TestCkmsSymKeysImport.table_2 += f"""
    \\end{{tabularx}}
\\end{{table}}
"""

    table_2 = TestCkmsSymKeysImport.table_2
    with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(table_2)

    # Check the result and print a message accordingly
    if TestCkmsSymKeysImport.all_tests_passed:
        print("All tests passed!")
        status = "Pass"
        row_color = "green!30"        
    else:
        print("Some tests failed!")
        
    # LaTeX table for overall result of test case
    table_3 = latex_content.generate_latex_table_3(timestamp, tester, status, row_color)

    with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
        f.write(table_3)
