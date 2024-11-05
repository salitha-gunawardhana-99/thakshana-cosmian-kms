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

logging.info("Setting up KMS server...")
CKMS_general.start_kms_server()

CKMS_general.clear_database()

sut = CKMS_general.SUT
version = CKMS_general.VERSION

testing_category = "Symmetric Keys"
test_case_id = "CKMS_TC_10_01_05".replace("_", "\\_")
test_case_name = "sym_keys_revoke".replace("_", "\\_")
test_case_description = "Revoke symmetric keys using different methods."

import latex_content

table_1 = latex_content.generate_latex_table_1(test_case_name, sut, version, testing_category, test_case_id, test_case_description)

with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(table_1)
            
print("")

class TestCkmsSymKeysRevoke(unittest.TestCase):
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

    def test_01_revoke_symkey_by_id(self):
        logging.info("Starting test case: test_revoke_symkey_by_id")

        status = CKMS_keys.revoke_key(
            key_id=self.test_key_id,
            revocation_reason=self.revocation_reason
        )
        
        try:
            self.assertIn("pass", status, "Failed to revoke key by ID.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_revoke_symkey_by_id: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_revoke_symkey_by_id: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_revoke_symkey_by_id".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Starting test case: test_revoke_symkey_by_id")

    def test_02_revoke_symkey_by_tag(self):
        logging.info("Starting test case: test_revoke_symkey_by_tag")

        status = CKMS_keys.revoke_key(
            tags=self.test_key_tags,
            revocation_reason=self.revocation_reason
        )
        
        try:
            self.assertIn("pass", status, "Failed to revoke key by ID.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_revoke_symkey_by_tag: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_revoke_symkey_by_tag: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_revoke_symkey_by_tag".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Starting test case: test_revoke_symkey_by_tag")

    def test_03_revoke_symkey_without_reason(self):
        logging.info("Starting test case: test_revoke_symkey_without_reason")

        status = CKMS_keys.revoke_key(
            key_id=self.test_key_id
        )
        
        try:
            self.assertIn("fail", status, "Invalid revocation occured.")
            self.obtained_result = "Fail"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_revoke_symkey_without_reason: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Pass"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_revoke_symkey_without_reason: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_revoke_symkey_without_reason".replace("_", "\\_")
        self.expected_result = "Fail"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Starting test case: test_revoke_symkey_without_reason")

    def test_04_revoke_symkey_without_id_or_tag(self):
        logging.info("Starting test case: test_revoke_symkey_without_id_or_tag")

        status = CKMS_keys.revoke_key(
            revocation_reason=self.revocation_reason
        )
        
        try:
            self.assertIn("fail", status, "Invalid revocation occured.")
            self.obtained_result = "Fail"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_revoke_symkey_without_id_or_tag: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Pass"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_revoke_symkey_without_id_or_tag: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_revoke_symkey_without_id_or_tag".replace("_", "\\_")
        self.expected_result = "Fail"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Starting test case: test_revoke_symkey_without_id_or_tag")

from datetime import datetime
date_of_execution = datetime.now().timestamp()  # This gives you the timestamp
timestamp = datetime.fromtimestamp(date_of_execution).strftime("%Y-%m-%d %H:%M:%S")
tester = "Unknown"
status = "Fail"
row_color = "red!30"

if __name__ == '__main__':
    # Create a test suite
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestCkmsSymKeysRevoke)

    # Run the test suite
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    TestCkmsSymKeysRevoke.table_2 += f"""
    \\end{{tabularx}}
\\end{{table}}
"""

    table_2 = TestCkmsSymKeysRevoke.table_2
    with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(table_2)

    # Check the result and print a message accordingly
    if TestCkmsSymKeysRevoke.all_tests_passed:
        print("All tests passed!")
        status = "Pass"
        row_color = "green!30"        
    else:
        print("Some tests failed!")
        
    # LaTeX table for overall result of test case
    table_3 = latex_content.generate_latex_table_3(timestamp, tester, status, row_color)

    with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
        f.write(table_3)
