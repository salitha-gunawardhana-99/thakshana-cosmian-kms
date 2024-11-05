"""

3.4 ckms certificates export

Export a certificate from the KMS

Usage

ckms certificates export [options] <CERTIFICATE_FILE>

Arguments

<CERTIFICATE_FILE> The file to export the certificate to

--certificate-id [-c] <UNIQUE_ID> The certificate unique identifier stored in the KMS; for PKCS#12, provide the private key id If not specified, tags should be specified

--tag [-t] <TAG> Tag to use to retrieve the certificate/private key when no unique id is specified. To specify multiple tags, use the option multiple times.

--format [-f] <OUTPUT_FORMAT> Export the certificate in the selected format

Possible values: "json-ttlv", "pem", "pkcs12", "pkcs12-legacy" [default: "json-ttlv"]

--pkcs12-password [-p] <PKCS12_PASSWORD> Password to use to protect the PKCS#12 file

--allow-revoked [-r] <ALLOW_REVOKED> Allow exporting revoked and destroyed certificates or private key (for PKCS#12). The user must be the owner of the certificate. Destroyed objects have their key material removed.

Possible values: "true", "false" [default: "false"]

"""

import unittest
import os
import logging
import CKMS_certificates
import CKMS_general
import CKMS_keys

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

logging.info("Setting up KMS server and generating RSA key pair.")
CKMS_general.start_kms_server()

CKMS_general.clear_database()

sut = CKMS_general.SUT
version = CKMS_general.VERSION

testing_category = "Certificates"
test_case_id = "CKMS_TC_03_04".replace("_", "\\_")
test_case_name = "export_certificates".replace("_", "\\_")
test_case_description = "Export certificates into different supported file formats."

import latex_content

table_1 = latex_content.generate_latex_table_1(test_case_name, sut, version, testing_category, test_case_id, test_case_description)

with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(table_1)
            
print("")

class TestCkmsCertificatesExport(unittest.TestCase):
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
        
        # Set up variables for testing
        self.export_file_pem = "exported_cert.pem"
        self.export_file_json = "exported_cert.json"
        self.export_file_pkcs12 = "exported_cert.p12" # pkcs12: .p12 or .pfx
        self.pkcs12_password = "testpassword"
        
        # ????
        self.certificate_id = "test-cert-id"
        self.test_cert_tags = ["test_exported_cert"]
        
        # create a certificate to export
        CKMS_certificates.certify_certificate(
            public_key_id_to_certify=self.test_public_key_id,
            tags=self.test_cert_tags
        )
        
        print("")       

    def tearDown(self):
        print("")
        
        # Remove test rsa key after every test scenario        
        CKMS_keys.revoke_key(revocation_reason="Testing", tags=self.test_rsa_key_tags)
        CKMS_keys.destroy_key(tags=self.test_rsa_key_tags)
        
        # Remove created test certificate after every test scenario
        CKMS_certificates.revoke_certificate(revocation_reason="testing",tags=self.test_cert_tags)
        CKMS_certificates.destroy_certificate(tags=self.test_cert_tags)
        
        # Clean up exported files
        if os.path.exists(self.export_file_pem):
            os.remove(self.export_file_pem)
        if os.path.exists(self.export_file_json):
            os.remove(self.export_file_json)
        if os.path.exists(self.export_file_pkcs12):
            os.remove(self.export_file_pkcs12)
            
        print("")
        print("=" * 120)

    def test_01_export_certificate_as_pem(self):
        logging.info("Starting test case: test_export_certificate_as_pem")

        # Check that the export has been done correctly
        CKMS_certificates.export_certificate(certificate_file = self.export_file_pem, tags=self.test_cert_tags + ["_cert"], output_format = "pem")
        
        try:
            # Check if the exported file exists
            self.assertTrue(os.path.exists(self.export_file_pem), "PEM certificate export failed at test_export_certificate_as_pem")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_export_certificate_as_pem: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_export_certificate_as_pem: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_export_certificate_as_pem".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Finishing test case: test_export_certificate_as_pem")

    def test_02_export_certificate_as_json(self):
        logging.info("Starting test case: test_export_certificate_as_json")

        # Check that the export has been done correctly
        CKMS_certificates.export_certificate(certificate_file = self.export_file_json, tags=self.test_cert_tags + ["_cert"], output_format = "json-ttlv")
        
        try:
            # Check if the exported file exists
            self.assertTrue(os.path.exists(self.export_file_json), "JSON certificate export failed at test_export_certificate_as_json.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_export_certificate_as_json: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_export_certificate_as_json: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_export_certificate_as_json".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Finishing test case: test_export_certificate_as_json")

    def test_03_export_certificate_as_pkcs12(self):
        logging.info("Starting test case: test_export_certificate_as_pkcs12")
        
        # Check that the export has been done correctly
        CKMS_certificates.export_certificate(certificate_file = self.export_file_pkcs12, tags=self.test_cert_tags + ["_cert"], output_format = "pkcs12")
            
        try:
            # Check if the exported file exists
            self.assertTrue(os.path.exists(self.export_file_pkcs12), "PKCS12 certificate export failed at test_export_certificate_as_pkcs12.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_export_certificate_as_pkcs12: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_export_certificate_as_pkcs12: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_export_certificate_as_pkcs12".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""       
        logging.info("Finishing test case: test_export_certificate_as_pkcs12")

    # def test_export_revoked_certificate(self):
    #     None

    # def test_export_certificate_with_wrong_id(self):
    #     None

    # def test_export_certificate_with_missing_id_and_tag(self):
    #     None
    
from datetime import datetime
date_of_execution = datetime.now().timestamp()  # This gives you the timestamp
timestamp = datetime.fromtimestamp(date_of_execution).strftime("%Y-%m-%d %H:%M:%S")
tester = "Unknown"
status = "Fail"
row_color = "red!30"

if __name__ == '__main__':
    # Create a test suite
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestCkmsCertificatesExport)

    # Run the test suite
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    TestCkmsCertificatesExport.table_2 += f"""
    \\end{{tabularx}}
\\end{{table}}
"""

    table_2 = TestCkmsCertificatesExport.table_2
    with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(table_2)

    # Check the result and print a message accordingly
    if TestCkmsCertificatesExport.all_tests_passed:
        print("All tests passed!")
        status = "Pass"
        row_color = "green!30"        
    else:
        print("Some tests failed!")
        
    # LaTeX table for overall result of test case
    table_3 = latex_content.generate_latex_table_3(timestamp, tester, status, row_color)

    with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
        f.write(table_3)