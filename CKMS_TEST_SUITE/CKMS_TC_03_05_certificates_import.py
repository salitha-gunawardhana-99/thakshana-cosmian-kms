"""

3.5 ckms certificates import

Import one of the following:

    a certificate: formatted as a X509 PEM (pem), X509 DER (der) or JSON TTLV (json-ttlv)
    a certificate chain as a PEM-stack (chain)
    a PKCS12 file containing a certificate, a private key and possibly a chain (pkcs12)
    the Mozilla Common CA Database (CCADB - fetched by the CLI before import) (ccadb)

Usage

ckms certificates import [options] [CERTIFICATE_FILE] [CERTIFICATE_ID]

Arguments

<CERTIFICATE_FILE> The input file in PEM, KMIP-JSON-TTLV or PKCS#12 format

<CERTIFICATE_ID> The unique id of the leaf certificate; a unique id based on the key material is generated if not specified. When importing a PKCS12, the unique id will be that of the private key.

--format [-f] <INPUT_FORMAT> Import the certificate in the selected format

Possible values: "json-ttlv", "pem", "der", "chain", "ccadb", "pkcs12" [default: "json-ttlv"]

--private-key-id [-k] <PRIVATE_KEY_ID> The corresponding private key id if any. Ignored for PKCS12 and CCADB formats

--public-key-id [-q] <PUBLIC_KEY_ID> The corresponding public key id if any. Ignored for PKCS12 and CCADB formats

--issuer-certificate-id [-i] <ISSUER_CERTIFICATE_ID> The issuer certificate id if any. Ignored for PKCS12 and CCADB formats

--pkcs12-password [-p] <PKCS12_PASSWORD> PKCS12 password: only available for PKCS12 format

--replace [-r] <REPLACE_EXISTING> Replace an existing certificate under the same id

Possible values: "true", "false" [default: "false"]

--tag [-t] <TAG> The tag to associate with the certificate. To specify multiple tags, use the option multiple times

--key-usage <KEY_USAGE> For what operations should the certificate be used

Possible values: "sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"

"""

import unittest
import os
import logging
import CKMS_certificates
import CKMS_general

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestCkmsCertificatesImport(unittest.TestCase):
    def setUp(self):
        print("")
        
        logging.info("Setting up KMS server.")
        CKMS_general.start_kms_server()
        
        # Set up variables for testing
        self.certificate_file_pem = "certificate_for_import.pem"
        self.certificate_file_json = "certificate_for_import.json"
        self.certificate_file_pkcs12 = "certificate_for_import.p12"
        self.private_key_file_pem = "private_key_for_import.pem"
        
        self.certificate_name = "MyCertfor_import"
        self.pkcs12_password = "testpassword"
        
        self.import_cert_tags = ["test-import-cert"]
        self.imported_private_key_id = None
        self.imported_certificate_id = None
        
        print("")

    def tearDown(self):
        print("")
        
        # Remove created test certificate after every test scenario
        CKMS_certificates.revoke_certificate(revocation_reason="testing",tags=self.import_cert_tags)
        CKMS_certificates.destroy_certificate(tags=self.import_cert_tags)
        
        # Clean up test certificate files
        # if os.path.exists(self.certificate_file_pem):
        #     os.remove(self.certificate_file_pem)
        # if os.path.exists(self.certificate_file_json):
        #     os.remove(self.certificate_file_json)
        # if os.path.exists(self.certificate_file_pkcs12):
        #     os.remove(self.certificate_file_pkcs12)
        # if os.path.exists(self.private_key_file_pem):
        #     os.remove(self.private_key_file_pem)
            
        print("")
        print("=" * 120)

    def test_import_certificate_as_pem(self):
        logging.info("Starting test case: test_import_certificate_as_pem")
        
        CKMS_certificates.generate_pem_certificate(common_name=self.certificate_name, private_key_filename=self.private_key_file_pem, certificate_filename=self.certificate_file_pem)
        
        self.imported_private_key_id = CKMS_certificates.import_certificate(
            certificate_file=self.certificate_file_pem,
            input_format="pem",
            tags=self.import_cert_tags,
        )[1]
        
        self.imported_certificate_id = CKMS_general.extract_cert_id(self.import_cert_tags[0])
        
        # Assert the icertificate is imported successfully
        self.assertIsNotNone(self.imported_certificate_id, "Failed to import the certificate.")

        logging.info("Finishing test case: test_import_certificate_as_pem")

    def test_import_certificate_as_json(self):
        logging.info("Starting test case: test_import_certificate_as_json")
        
        CKMS_certificates.generate_json_certificate(common_name=self.certificate_name, private_key_filename=self.private_key_file_pem, certificate_filename=self.certificate_file_pem, json_filename=self.certificate_file_json)
        
        self.imported_private_key_id = CKMS_certificates.import_certificate(
            certificate_file=self.certificate_file_json,
            input_format="json-ttlv",
            tags=self.import_cert_tags,
        )[1]
        
        self.imported_certificate_id = CKMS_general.extract_cert_id(self.import_cert_tags[0])
        
        # Assert the icertificate is imported successfully
        self.assertIsNotNone(self.imported_certificate_id, "Failed to import the certificate.")

        logging.info("Finishing test case: test_import_certificate_as_json")

    def test_import_certificate_as_pkcs12(self):
        logging.info("Starting test case: test_import_certificate_as_pkcs12")
        
        # Generate and import an issuer certificate and private key
        CKMS_certificates.generate_pkcs12_certificate(
            common_name=self.certificate_name,
            private_key_filename=self.private_key_file_pem,
            certificate_filename=self.certificate_file_pem,
            pkcs12_filename=self.certificate_file_pkcs12,
            pkcs12_password=self.pkcs12_password
        )
        
        
        self.imported_private_key_id = CKMS_certificates.import_certificate(
            certificate_file=self.certificate_file_pkcs12,
            input_format="pkcs12",
            pkcs12_password=self.pkcs12_password,
            tags=self.import_cert_tags,
        )[1]
        
        self.imported_certificate_id = CKMS_general.extract_cert_id(self.import_cert_tags[0])
        
        # Assert the icertificate is imported successfully
        self.assertIsNotNone(self.imported_certificate_id, "Failed to import the certificate.")

        logging.info("Finishing test case: test_import_certificate_as_pkcs12")

    # def test_import_certificate_chain(self):
    #     None

    # def test_import_certificate_with_replace(self):
    #     None

    # def test_import_certificate_with_missing_id(self):
    #     None

    # def test_import_certificate_with_wrong_format(self):
    #     None

if __name__ == '__main__':
    unittest.main()
