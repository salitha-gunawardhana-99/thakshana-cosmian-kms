import unittest
import os
import logging
import CKMS_certificates
import CKMS_general
import CKMS_keys

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class TestCkmsCertificatesExport(unittest.TestCase):
    def setUp(self):
        print("")
        
        logging.info("Setting up KMS server and generating RSA key pair.")
        CKMS_general.start_kms_server()
        
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

    def test_export_certificate_as_pem(self):
        logging.info("Starting test case: test_export_certificate_as_pem")

        # Check that the export has been done correctly
        CKMS_certificates.export_certificate(certificate_file = self.export_file_pem, tags=self.test_cert_tags + ["_cert"], output_format = "pem")

        self.assertTrue(os.path.exists(self.export_file_pem), "PEM certificate export failed.")

        logging.info("Finishing test case: test_export_certificate_as_pem")

    def test_export_certificate_as_json(self):
        logging.info("Starting test case: test_export_certificate_as_json")

        # Check that the export has been done correctly
        CKMS_certificates.export_certificate(certificate_file = self.export_file_json, tags=self.test_cert_tags + ["_cert"], output_format = "json-ttlv")

        self.assertTrue(os.path.exists(self.export_file_json), "JSON certificate export failed.")

        logging.info("Finishing test case: test_export_certificate_as_json")

    # def test_export_certificate_as_pkcs12(self):
    #    logging.info("Starting test case: test_export_certificate_as_pkcs12")
       
    #    # Check that the export has been done correctly
    #    CKMS_certificates.export_certificate(certificate_file = self.export_file_pkcs12, tags=self.test_cert_tags + ["_cert"], output_format = "pkcs12")
       
    #    self.assertTrue(os.path.exists(self.export_file_pkcs12), "PKCS12 certificate export failed.")
       
    #    logging.info("Finishing test case: test_export_certificate_as_pkcs12")


    # def test_export_revoked_certificate(self):
    #     None

    # def test_export_certificate_with_wrong_id(self):
    #     None

    # def test_export_certificate_with_missing_id_and_tag(self):
    #     None

if __name__ == '__main__':
    
    unittest.main()
