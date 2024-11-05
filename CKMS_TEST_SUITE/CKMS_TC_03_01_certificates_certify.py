"""

3.1 ckms certificates certify

Issue or renew a X509 certificate

Usage

ckms certificates certify [options]

Arguments

--certificate-id [-c] <CERTIFICATE_ID> The unique identifier of the certificate to issue or renew. If not provided, a random one will be generated when issuing a certificate, or the original one will be used when renewing a certificate

--certificate-signing-request [-r] <CERTIFICATE_SIGNING_REQUEST> The path to a certificate signing request

--certificate-signing-request-format [-f] <CERTIFICATE_SIGNING_REQUEST_FORMAT> The format of the certificate signing request

Possible values: "pem", "der" [default: "pem"]

--public-key-id-to-certify [-p] <PUBLIC_KEY_ID_TO_CERTIFY> The id of a public key to certify

--certificate-id-to-re-certify [-n] <CERTIFICATE_ID_TO_RE_CERTIFY> The id of a certificate to re-certify

--generate-key-pair [-g] <GENERATE_KEY_PAIR> Generate a keypair then sign the public key and generate a certificate

Possible values: "true", "false"

--subject-name [-s] <SUBJECT_NAME> When certifying a public key, or generating a keypair, the subject name to use.

--algorithm [-a] <ALGORITHM> The algorithm to use for the keypair generation

Possible values: "nist-p192", "nist-p224", "nist-p256", "nist-p384", "nist-p521", "x25519", "ed25519", "x448", "ed448", "rsa1024", "rsa2048", "rsa3072", "rsa4096" [default: "rsa4096"]

--issuer-private-key-id [-k] <ISSUER_PRIVATE_KEY_ID> The unique identifier of the private key of the issuer. A certificate must be linked to that private key if no issuer certificate id is provided

--issuer-certificate-id [-i] <ISSUER_CERTIFICATE_ID> The unique identifier of the certificate of the issuer. A private key must be linked to that certificate if no issuer private key id is provided

--days [-d] <NUMBER_OF_DAYS> The requested number of validity days The server may grant a different value

--certificate-extensions [-e] <CERTIFICATE_EXTENSIONS> The path to a X509 extension’s file, containing a v3_ca paragraph with the x509 extensions to use. For instance:

--tag [-t] <TAG> The tag to associate to the certificate. To specify multiple tags, use the option multiple times

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
test_case_id = "CKMS_TC_03_01".replace("_", "\\_")
test_case_name = "certify_certificates".replace("_", "\\_")
test_case_description = "Certify certificates using different certifying methods."

import latex_content

section_init = f"""
\\section{{Execution and Results}}
"""

with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(section_init)

table_1 = latex_content.generate_latex_table_1(test_case_name, sut, version, testing_category, test_case_id, test_case_description)

with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(table_1)

"""

Cosmian has extended the specifications and offers 4 possibilities to generate a certificate:
  1. Providing a Certificate Signing Request (CSR)
  2. Providing a public key ID to certify, as well as a subject name
  3. Providing an existing certificate ID to re-certify
  4. Generating a key pair, then signing the public key to generate a certificate by specifying a subject name and an algorithm
  
"""

print("")

class TestCkmsCertificatesCertify(unittest.TestCase):
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
        
        # Generate an RSA key pair for testing
        self.test_rsa_key_tags = ["test_rsa_key"]
        test_rsa_key_id = CKMS_keys.generate_rsa_key(tags=self.test_rsa_key_tags)
        self.test_public_key_id = test_rsa_key_id[1]

        # Tags for the certificate and issuer
        self.test_cert_tags = ["test_certify_cert"]
        self.test_issuer_tags = ["test_cert_issuer"]
        
        # Store issuer private key and certificate IDs
        self.issuer_private_key_id = None
        self.issuer_certificate_id = None
        
        print("")

    def tearDown(self):
        print("")
        
        # Remove test rsa key after every test scenario        
        CKMS_keys.revoke_key(revocation_reason="testing", tags=self.test_rsa_key_tags)
        CKMS_keys.destroy_key(tags=self.test_rsa_key_tags)
        
        # Remove created test certificate after every test scenario
        CKMS_certificates.revoke_certificate(revocation_reason="testing",tags=self.test_cert_tags)
        CKMS_certificates.destroy_certificate(tags=self.test_cert_tags)
        
        # Remove issuer after every test scenario        
        # CKMS_certificates.revoke_certificate(revocation_reason="testing",tags=self.test_issuer_tags)
        # CKMS_certificates.destroy_certificate(tags=self.test_issuer_tags)
        
        # Remove test rsa key after every test scenario        
        # CKMS_keys.revoke_key(revocation_reason="Testing", tags=self.test_issuer_tags)
        # CKMS_keys.destroy_key(tags=self.test_issuer_tags)
        
        print("")
        print("=" * 120)

    def test_01_self_sign_public_key(self):
        logging.info("Starting test case: test_self_sign_public_key")

        # Perform a self-signing operation
        CKMS_certificates.certify_certificate(
            public_key_id_to_certify=self.test_public_key_id,
            tags=self.test_cert_tags
        )
        
        # Check that the certificate has been created and extracted correctly
        cert_id = CKMS_certificates.export_certificate(tags=self.test_cert_tags + ["_cert"])
        
        try:
            # Check if the certification success by exporting the certificate
            self.assertIsNotNone(cert_id, "Failed to certify the public key.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_self_sign_public_key: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_self_sign_public_key: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_self_sign_public_key".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Finishing test case: test_self_sign_public_key")
        
    def test_02_self_sign_invalid_public_key(self):
        logging.info("Starting test case: test_self_sign_invalid_public_key")
        
        # Remove test rsa key before certification        
        CKMS_keys.revoke_key(revocation_reason="Testing", tags=self.test_rsa_key_tags)
        CKMS_keys.destroy_key(tags=self.test_rsa_key_tags)

        # Perform a self-signing operation
        CKMS_certificates.certify_certificate(
            public_key_id_to_certify=self.test_public_key_id,
            tags=self.test_cert_tags
        )
        
        # Check that the certificate has not been created and extracted
        cert_id = CKMS_certificates.export_certificate(tags=self.test_cert_tags + ["_cert"])
        
        try:
            # Check if the certification success by exporting the certificate
            self.assertIsNone(cert_id, "Unexpected certification occured.")
            self.obtained_result = "Fail"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_self_sign_invalid_public_key: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Pass"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_self_sign_invalid_public_key: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_self_sign_invalid_public_key".replace("_", "\\_")
        self.expected_result = "Fail"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Finishing test case: test_self_sign_invalid_public_key")

    def test_03_import_issuer(self):
        logging.info("Starting test case: test_import_issuer")
        
        # Generate and import an issuer certificate and private key
        CKMS_certificates.generate_pkcs12_certificate(
                common_name="TestIssuer",
                private_key_filename="test_issuer_private_key.pem",
                certificate_filename="test_issuer_certificate.pem",
                pkcs12_filename="test_my_ca.p12",
                pkcs12_password="testpassword"
            )
            
        self.issuer_private_key_id = CKMS_certificates.import_certificate(
                certificate_file="test_my_ca.p12",
                input_format = "pkcs12", 
                pkcs12_password="testpassword", 
                tags=self.test_issuer_tags + ["_sk"]
        )[1]
            
        self.issuer_certificate_id = CKMS_general.extract_cert_id(self.test_issuer_tags[0])   
        try:
            # Check if the certification success by exporting the certificate
            self.assertIsNotNone(self.issuer_private_key_id, "Failed to import the issuer private key.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_import_issuer: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_import_issuer: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_import_issuer".replace("_", "\\_")
        self.expected_result = "Pass"
        
        logging.info("Finishing test case: test_import_issuer")

    def test_04_certify_with_issuer_private_key(self):
        logging.info("Starting test case: test_certify_with_issuer_private_key")

        # Import the issuer first if not already done
        if not self.issuer_private_key_id:
            self.test_03_import_issuer()

        # Certify using the issuer private key
        CKMS_certificates.certify_certificate(
            public_key_id_to_certify=self.test_public_key_id,
            issuer_private_key_id=self.issuer_private_key_id,
            tags=self.test_cert_tags
        )
        
        # Check if certification succeeded
        cert_id = CKMS_certificates.export_certificate(tags=self.test_cert_tags + ["_cert"])
        try:
            # Check if the certification success by exporting the certificate
            self.assertIsNotNone(cert_id, "Failed to certify the public key with issuer private key.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_certify_with_issuer_private_key: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_certify_with_issuer_private_key: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_certify_with_issuer_private_key".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Finishing test case: test_certify_with_issuer_private_key")

    def test_05_certify_with_issuer_certificate(self):
        logging.info("Starting test case: test_certify_with_issuer_certificate")

        # Import the issuer first if not already done
        if not self.issuer_private_key_id:
            self.test_03_import_issuer()

        # Certify using the issuer certificate
        CKMS_certificates.certify_certificate(
            public_key_id_to_certify=self.test_public_key_id,
            issuer_certificate_id=self.issuer_certificate_id,
            tags=self.test_cert_tags
        )
        
        # Check if certification unsucceeded
        cert_id = CKMS_certificates.export_certificate(tags=self.test_cert_tags + ["_cert"])
        try:
            # Check if the certification success by exporting the certificate
            self.assertIsNotNone(cert_id, "Failed to certify the public key with issuer certificate.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_certify_with_issuer_certificate: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_certify_with_issuer_certificate: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_certify_with_issuer_certificate".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Finishing test case: test_certify_with_issuer_certificate")

    def test_06_certify_with_csr(self):
        # A self-signed certificate cannot be created from a CSR without specifying the private key id
        logging.info("Starting test case: test_certify_with_csr")

        # Import the issuer first if not already done
        if not self.issuer_private_key_id:
            self.test_03_import_issuer()

        # Certify using the issuer private key
        CKMS_certificates.certify_certificate(
            csr_path = "cert_key.csr",
            issuer_private_key_id=self.issuer_private_key_id,
            tags=self.test_cert_tags
        )
        
        # Check if certification succeeded
        cert_id = CKMS_certificates.export_certificate(tags=self.test_cert_tags + ["_cert"])
        try:
            # Check if the certification success by exporting the certificate
            self.assertIsNotNone(cert_id, "Failed to certify the csr.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_certify_with_csr: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_certify_with_csr: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_certify_with_csr".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""

        logging.info("Finishing test case: test_certify_with_csr")

    def test_07_certify_with_invalid_csr(self):
        logging.info("Starting test case: test_certify_with_invalid_csr")

        # Import the issuer first if not already done
        if not self.issuer_private_key_id:
            self.test_03_import_issuer()

        # Certify using the issuer private key
        CKMS_certificates.certify_certificate(
            csr_path = "cert_key_invalid.csr",
            issuer_private_key_id=self.issuer_private_key_id,
            tags=self.test_cert_tags
        )
        
        # Check if certification unsucceeded
        cert_id = CKMS_certificates.export_certificate(tags=self.test_cert_tags + ["_cert"])
        try:
            # Check if the certification success by exporting the certificate
            self.assertIsNone(cert_id, "Unexpected certification occured.")
            self.obtained_result = "Fail"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_certify_with_invalid_csr: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Pass"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_certify_with_invalid_csr: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_certify_with_invalid_csr".replace("_", "\\_")
        self.expected_result = "Fail"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""
        logging.info("Finishing test case: test_certify_with_invalid_csr")

    def test_08_certify_with_gen_keypair_self_sign(self):
        logging.info("Starting test case: test_certify_with_gen_keypair_self_sign")

        # Certify using the issuer private key
        CKMS_certificates.certify_certificate(
            generate_key_pair = True,
            tags=self.test_cert_tags
        )
        
        # Check if certification succeeded
        cert_id = CKMS_certificates.export_certificate(tags=self.test_cert_tags + ["_cert"])        
        try:
            # Check if the certification success by exporting the certificate
            self.assertIsNotNone(cert_id, "Failed to certify the generated key.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_certify_with_gen_keypair_self_sign: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_certify_with_gen_keypair_self_sign: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_certify_with_gen_keypair_self_sign".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""        
        logging.info("Finishing test case: test_certify_with_gen_keypair_self_sign")
        
    def test_09_certify_with_gen_keypair_from_issuer_private_key(self):
        logging.info("Starting test case: test_certify_with_gen_keypair_from_issuer_private_key")
        
        # Import the issuer first if not already done
        if not self.issuer_private_key_id:
            self.test_03_import_issuer()

        # Certify using the issuer private key
        CKMS_certificates.certify_certificate(
            
            generate_key_pair = True,
            issuer_private_key_id=self.issuer_private_key_id,
            tags=self.test_cert_tags
        )
        
        # Check if certification succeeded
        cert_id = CKMS_certificates.export_certificate(tags=self.test_cert_tags + ["_cert"])        
        try:
            # Check if the certification success by exporting the certificate
            self.assertIsNotNone(cert_id, "Failed to certify the generated key.")
            self.obtained_result = "Pass"
        except AssertionError as e:
            logging.error(f"Assertion failed at test_certify_with_gen_keypair_from_issuer_private_key: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Fail"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""
        except Exception as e:
            logging.error(f"Error during test_certify_with_gen_keypair_from_issuer_private_key: {e}")
            self.__class__.all_tests_passed = False
            self.obtained_result = "Error"
            self.__class__.table_2 += f"""
\\rowcolor{{{self.error_row_color}}}
"""        
        self.test_scenario = "test_certify_with_gen_keypair_from_issuer_private_key".replace("_", "\\_")
        self.expected_result = "Pass"
        self.__class__.table_2 += f"""
{self.test_scenario} & {self.expected_result} & {self.obtained_result} \\\\
\\hline
"""        
        logging.info("Finishing test case: test_certify_with_gen_keypair_from_issuer_private_key")

    # def test_recertify_certificate(self):
    #     None

from datetime import datetime
date_of_execution = datetime.now().timestamp()  # This gives you the timestamp
timestamp = datetime.fromtimestamp(date_of_execution).strftime("%Y-%m-%d %H:%M:%S")
tester = "Unknown"
status = "Fail"
row_color = "red!30"

if __name__ == '__main__':
    # Create a test suite
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestCkmsCertificatesCertify)

    # Run the test suite
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    TestCkmsCertificatesCertify.table_2 += f"""
    \\end{{tabularx}}
\\end{{table}}
"""

    table_2 = TestCkmsCertificatesCertify.table_2
    with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
            f.write(table_2)

    # Check the result and print a message accordingly
    if TestCkmsCertificatesCertify.all_tests_passed:
        print("All tests passed!")
        status = "Pass"
        row_color = "green!30"        
    else:
        print("Some tests failed!")
        
    # LaTeX table for overall result of test case
    table_3 = latex_content.generate_latex_table_3(timestamp, tester, status, row_color)

    with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
        f.write(table_3)
