"""

3.6 ckms certificates revoke

Revoke a certificate

Usage

ckms certificates revoke [options] <REVOCATION_REASON>

Arguments

<REVOCATION_REASON> The reason for the revocation as a string

--certificate-id [-c] <CERTIFICATE_ID> The certificate unique identifier of the certificate to revoke. If not specified, tags should be specified

--tag [-t] <TAG> Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times

"""

import unittest
import logging
import CKMS_general
import CKMS_keys
import CKMS_certificates

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

logging.info("Setting up KMS server and generating RSA key pair.")
CKMS_general.start_kms_server()

CKMS_general.clear_database()

sut = CKMS_general.SUT
version = CKMS_general.VERSION

testing_category = "Certificates"
test_case_id = "CKMS_TC_03_06".replace("_", "\\_")
test_case_name = "revoke_certificates".replace("_", "\\_")
test_case_description = "Revoke certificates using different methods."

import latex_content

table_1 = latex_content.generate_latex_table_1(test_case_name, sut, version, testing_category, test_case_id, test_case_description)

with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(table_1)
            
print("")

class TestCkmsCertificatesRevoke(unittest.TestCase):
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
        
        # Generate an RSA key pair for create self sign certificate
        self.test_rsa_key_tags = ["test_rsa_key"]
        test_rsa_key_id = CKMS_keys.generate_rsa_key(tags=self.test_rsa_key_tags)
        self.test_public_key_id = test_rsa_key_id[1]
        
        self.test_cert_tags = ["test_certify_cert"]
        
        # Perform a self-signing operation
        CKMS_certificates.certify_certificate(
            public_key_id_to_certify=self.test_public_key_id,
            tags=self.test_cert_tags
        )
        
        # Set up variables for testing
        self.certificate_id = CKMS_general.extract_cert_id(self.test_cert_tags[0])
        
        self.revocation_reason = "Testing"
        
        print("")
        
    def tearDown(self):
        print("")
        
        # Remove test rsa key after every test scenario        
        CKMS_keys.revoke_key(revocation_reason="Testing", tags=self.test_rsa_key_tags)
        CKMS_keys.destroy_key(tags=self.test_rsa_key_tags)
        
        # Remove created test certificate after every test scenario
        CKMS_certificates.revoke_certificate(revocation_reason="testing",tags=self.test_cert_tags)
        CKMS_certificates.destroy_certificate(tags=self.test_cert_tags)
            
        print("")
        print("=" * 120)

    def test_01_revoke_certificate_by_id(self):
        logging.info("Starting test case: test_revoke_certificate_by_id")

        status = CKMS_certificates.revoke_certificate(
            certificate_id=self.certificate_id,
            revocation_reason=self.revocation_reason
        )

        try:
            # Check if the certificates are revoked
            self.assertIn("pass", status, "Failed to revoke certificate by ID.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_revoke_certificate_by_id: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_revoke_certificate_by_id: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_revoke_certificate_by_id".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Starting test case: test_revoke_certificate_by_id")

    def test_02_revoke_certificate_by_tag(self):
        logging.info("Starting test case: test_revoke_certificate_by_tag")

        status = CKMS_certificates.revoke_certificate(
            revocation_reason=self.revocation_reason,
            tags=self.test_cert_tags
        )        
        try:
            # Check if the certificates are revoked
            self.assertIn("pass", status, "Failed to revoke certificate by ID.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_revoke_certificate_by_tag: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_revoke_certificate_by_tag: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_revoke_certificate_by_tag".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Starting test case: test_revoke_certificate_by_tag")

    def test_03_revoke_certificate_without_reason(self):
        logging.info("Starting test case: test_revoke_certificate_without_reason")

        status = CKMS_certificates.revoke_certificate(
            certificate_id=self.certificate_id
        )        
        try:
            # Check if the certificates are not revoked
            self.assertIn("fail", status, "Invalid revocation occured.")
            self.obtained_result = "Fail"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_revoke_certificate_without_reason: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Pass"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_revoke_certificate_without_reason: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_revoke_certificate_without_reason".replace("_", "\\_")
        self.expected_result = "Fail"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Starting test case: test_revoke_certificate_without_reason")

    def test_04_revoke_certificate_without_id_or_tag(self):
        logging.info("Starting test case: test_revoke_certificate_without_id_or_tag")

        status = CKMS_certificates.revoke_certificate(
            revocation_reason=self.revocation_reason
        )        
        try:
            # Check if the certificates are not revoked
            self.assertIn("fail", status, "Invalid revocation occured.")
            self.obtained_result = "Fail"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_revoke_certificate_without_id_or_tag: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Pass"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_revoke_certificate_without_id_or_tag: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_revoke_certificate_without_id_or_tag".replace("_", "\\_")
        self.expected_result = "Fail"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Starting test case: test_revoke_certificate_without_id_or_tag")

from datetime import datetime
date_of_execution = datetime.now().timestamp()  # This gives you the timestamp
timestamp = datetime.fromtimestamp(date_of_execution).strftime("%Y-%m-%d %H:%M:%S")
tester = "Unknown"
status = "Fail"
row_color = "red!30"

if __name__ == '__main__':
    # Create a test suite
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestCkmsCertificatesRevoke)

    # Run the test suite
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    TestCkmsCertificatesRevoke.table_2 += f"""
    \\end{{tabularx}}
\\end{{table}}
"""

    table_2 = TestCkmsCertificatesRevoke.table_2
    with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(table_2)

    # Check the result and print a message accordingly
    if TestCkmsCertificatesRevoke.all_tests_passed:
        print("All tests passed!")
        status = "Pass"
        row_color = "green!30"        
    else:
        print("Some tests failed!")
        
    # LaTeX table for overall result of test case
    table_3 = latex_content.generate_latex_table_3(timestamp, tester, status, row_color)

    with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
        f.write(table_3)