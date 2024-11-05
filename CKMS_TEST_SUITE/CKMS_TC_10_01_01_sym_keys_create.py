"""

10.1.1 ckms sym keys create

Create a new symmetric key

Usage

ckms sym keys create [options]

Arguments

--number-of-bits [-l] <NUMBER_OF_BITS> The length of the generated random key or salt in bits

--bytes-b64 [-k] <WRAP_KEY_B64> The symmetric key bytes or salt as a base 64 string

--algorithm [-a] <ALGORITHM> The algorithm

Possible values: "chacha20", "aes", "sha3", "shake" [default: "aes"]

--tag [-t] <TAG> The tag to associate with the key. To specify multiple tags, use the option multiple times

"""

import unittest
import logging
import CKMS_general
import CKMS_keys
import latex_content

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

logging.info("Setting up KMS server...")
CKMS_general.start_kms_server()
        
CKMS_general.clear_database()

sut = CKMS_general.SUT
version = CKMS_general.VERSION

testing_category = "Symmetric Keys"
test_case_id = "CKMS_TC_10_01_01".replace("_", "\\_")
test_case_name = "sym_keys_create".replace("_", "\\_")
test_case_description = "Create certificates using chacha20 and aes symmetric key algorithms."

import latex_content

table_1 = latex_content.generate_latex_table_1(test_case_name, sut, version, testing_category, test_case_id, test_case_description)

with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(table_1)
            
print("")

class TestCkmsSymKeysGenerate(unittest.TestCase):
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
        
        # Test data
        # self.algo_list = ["chacha20", "aes", "sha3", "shake", "rsa", "ec"]
        # self.algo_list = ["chacha20", "aes", "sha3", "shake"]
        self.algo_list = ["chacha20", "aes"]
        self.len_list = [16, 64, 96, 100, 128, 200, 224, 256, 300, 384, 400, 512, 1024, 2048, 3072, 4096]
        self.key_length = 256
        
        print("")

    def tearDown(self):
        print("")
        print("=" * 120)

    def test_generate_sym_keys_with_valid_algorithms(self):
        logging.info("Starting test case: test_generate_sym_keys_with_valid_algorithms")
        print("")

        for algo in self.algo_list:
            try:
                for length in self.len_list:
                    tags = f"sym_encryption_key_{algo}_{length}"
                    CKMS_keys.generate_key(
                    tags=tags, key_type=algo, key_length=length)
                    
                    CKMS_keys.revoke_key(revocation_reason="testing", tags=[tags])
                    CKMS_keys.destroy_key(tags=[tags])
                    
                    self.obtained_result = "Pass"
                    
                    print("")

            except Exception as e:
                # Handle the error if an exception occurs
                print(f"An error occurred at test_generate_sym_keys_with_{algo}: {e}")
                self.__class__.all_tests_passed = False
                self.obtained_result = "Fail"
                self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
            else:
                self.test_scenario = f"test_generate_sym_keys_with_{algo}".replace("_", "\\_")
                self.expected_result = "Pass"
                self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""                  
            print("=" * 120)
            print("")
        
        logging.info("Completed test case: test_generate_sym_keys_with_valid_algorithms")
        
from datetime import datetime
date_of_execution = datetime.now().timestamp()  # This gives you the timestamp
timestamp = datetime.fromtimestamp(date_of_execution).strftime("%Y-%m-%d %H:%M:%S")
tester = "Unknown"
status = "Fail"
row_color = "red!30"

if __name__ == '__main__':
    # Create a test suite
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestCkmsSymKeysGenerate)

    # Run the test suite
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    TestCkmsSymKeysGenerate.table_2 += f"""
    \\end{{tabularx}}
\\end{{table}}
"""

    table_2 = TestCkmsSymKeysGenerate.table_2
    with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(table_2)

    # Check the result and print a message accordingly
    if TestCkmsSymKeysGenerate.all_tests_passed:
        print("All tests passed!")
        status = "Pass"
        row_color = "green!30"        
    else:
        print("Some tests failed!")
        
    # LaTeX table for overall result of test case
    table_3 = latex_content.generate_latex_table_3(timestamp, tester, status, row_color)

    with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
        f.write(table_3)