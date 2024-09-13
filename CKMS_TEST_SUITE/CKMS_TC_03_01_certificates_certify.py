import unittest
import logging
import os
import CKMS_general
import CKMS_keys
import CKMS_certificates

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

"""
Cosmian has extended the specifications and offers 4 possibilities to generate a certificate:
  1. Providing a Certificate Signing Request (CSR)
  2. Providing a public key ID to certify, as well as a subject name
  3. Providing an existing certificate ID to re-certify
  4. Generating a key pair, then signing the public key to generate a certificate by specifying a subject name and an algorithm
"""

class TestCkmsCertificatesCertify(unittest.TestCase):

    def setUp(self):
        print("")
        
        logging.info("Setting up KMS server and generating RSA key pair.")
        CKMS_general.start_kms_server()  # Ensure the KMS server is running
        
        # Generate an RSA key pair for testing
        self.test_rsa_key_tags = ["test_rsa_key_id"]
        test_rsa_key_id = CKMS_keys.generate_rsa_key(tags=self.test_rsa_key_tags)
        self.test_public_key_id = test_rsa_key_id[1]

        # Tags for the certificate and issuer
        self.test_cert_tags = ["test_cert"]
        self.test_issuer_tags = ["test_cert_issuer"]
        
        # Store issuer private key and certificate IDs
        self.issuer_private_key_id = None
        self.issuer_certificate_id = None
        
        print("")

    def tearDown(self):
        print("")
        
        CKMS_keys.revoke_key(revocation_reason="Testing", tags=self.test_rsa_key_tags)
        CKMS_keys.destroy_key(tags=self.test_rsa_key_tags)
        CKMS_certificates.revoke_certificate(revocation_reason="testing",tags=self.test_cert_tags+ ["_cert"])
        CKMS_certificates.destroy_certificate(tags=self.test_cert_tags+ ["_cert"])
        CKMS_certificates.revoke_certificate(revocation_reason="testing",tags=self.test_issuer_tags+ ["_cert"])
        CKMS_certificates.destroy_certificate(tags=self.test_issuer_tags+ ["_cert"])
        
        print("")
        print("=" * 120)

    # def test_self_sign_public_key(self):
    #     logging.info("Starting test case: test_self_sign_public_key")

    #     # Perform a self-signing operation
    #     CKMS_certificates.certify_certificate(
    #         public_key_id_to_certify=self.test_public_key_id,
    #         tags=self.test_cert_tags
    #     )
        
    #     # Check that the certificate has been created and extracted correctly
    #     cert_id = CKMS_certificates.export_certificate(tags=self.test_cert_tags + ["_cert"])
    #     self.assertIsNotNone(cert_id, "Failed to certify the public key.")

    #     logging.info("Finishing test case: test_self_sign_public_key")

    def test_import_issuer(self):
        logging.info("Starting test case: test_import_issuer")
        
        # Generate and import an issuer certificate and private key
        CKMS_certificates.generate_certificate_issuer(
            common_name="TestIssuer",
            private_key_filename="test_issuer_private_key.pem",
            certificate_filename="test_issuer_certificate.pem",
            pkcs12_filename="test_my_ca.p12",
            pkcs12_password="testpassword"
        )

        self.issuer_private_key_id = CKMS_certificates.import_certificate_issuer_to_kms(
            pkcs12_filename="test_my_ca.p12", 
            pkcs12_password="testpassword", 
            tag=self.test_issuer_tags[0]
        )
        
        # Assert the issuer private key ID is imported successfully
        self.assertIsNotNone(self.issuer_private_key_id, "Failed to import the issuer private key.")

        logging.info("Finishing test case: test_import_issuer")

    # def test_certify_with_issuer_private_key(self):
    #     logging.info("Starting test case: test_certify_with_issuer_private_key")

    #     # Import the issuer first if not already done
    #     if not self.issuer_private_key_id:
    #         self.test_import_issuer()
            
    #     print(self.issuer_private_key_id)
    #     print(self.issuer_certificate_id)

    #     # Certify using the issuer private key
    #     CKMS_certificates.certify_certificate(
    #         public_key_id_to_certify=self.test_public_key_id,
    #         issuer_private_key_id=self.issuer_private_key_id,
    #         tags=self.test_cert_tags
    #     )
        
    #     # Check if certification succeeded
    #     cert_id = CKMS_certificates.export_certificate(tags=self.test_cert_tags + ["_cert"])
    #     self.assertIsNotNone(cert_id, "Failed to certify the public key with issuer private key.")

    #     logging.info("Finishing test case: test_certify_with_issuer_private_key")

    def test_certify_with_issuer_certificate(self):
        logging.info("Starting test case: test_certify_with_issuer_certificate")

        # Import the issuer first if not already done
        if not self.issuer_private_key_id:
            self.test_import_issuer()
            
        print(self.issuer_private_key_id)
        print(self.issuer_certificate_id)

        # Certify using the issuer certificate
        CKMS_certificates.certify_certificate(
            public_key_id_to_certify=self.test_public_key_id,
            issuer_certificate_id=self.issuer_certificate_id,
            tags=self.test_cert_tags
        )
        
        # Check if certification succeeded
        cert_id = CKMS_certificates.export_certificate(tags=self.test_cert_tags + ["_cert"])
        self.assertIsNotNone(cert_id, "Failed to certify the public key with issuer certificate.")

        logging.info("Finishing test case: test_certify_with_issuer_certificate")

    # # Stub for test_certify_with_public_key
    # def test_certify_with_public_key(self):
    #     logging.info("Test certify with public key is a placeholder.")

    # # Stub for test_certify_with_invalid_public_key
    # def test_certify_with_invalid_public_key(self):
    #     logging.info("Test certify with invalid public key is a placeholder.")

    # # Stub for test_certify_with_csr
    # def test_certify_with_csr(self):
    #     logging.info("Test certify with CSR is a placeholder.")

    # # Stub for test_certify_with_invalid_csr
    # def test_certify_with_invalid_csr(self):
    #     logging.info("Test certify with invalid CSR is a placeholder.")

    # # Stub for test_certify_with_gen_keypair
    # def test_certify_with_gen_keypair(self):
    #     logging.info("Test certify with generated keypair is a placeholder.")

    # # Stub for test_recertify_certificate
    # def test_recertify_certificate(self):
    #     logging.info("Test recertify certificate is a placeholder.")

if __name__ == '__main__':
    unittest.main()
