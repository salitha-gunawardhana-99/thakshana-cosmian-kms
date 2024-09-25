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

class TestCkmsCertificatesRevoke(unittest.TestCase):
    def setUp(self):
        print("")
        
        logging.info("Setting up KMS server and generating RSA key pair.")
        CKMS_general.start_kms_server()
        
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

    def test_revoke_certificate_by_id(self):
        logging.info("Starting test case: test_revoke_certificate_by_id")

        status = CKMS_certificates.revoke_certificate(
            certificate_id=self.certificate_id,
            revocation_reason=self.revocation_reason
        )

        self.assertIn("pass", status, "Failed to revoke certificate by ID.")

        logging.info("Starting test case: test_revoke_certificate_by_id")

    def test_revoke_certificate_by_tag(self):
        logging.info("Starting test case: test_revoke_certificate_by_tag")

        status = CKMS_certificates.revoke_certificate(
            revocation_reason=self.revocation_reason,
            tags=self.test_cert_tags
        )

        self.assertIn("pass", status, "Failed to revoke certificate by ID.")

        logging.info("Starting test case: test_revoke_certificate_by_tag")

    def test_revoke_certificate_without_reason(self):
        logging.info("Starting test case: test_revoke_certificate_without_reason")

        status = CKMS_certificates.revoke_certificate(
            certificate_id=self.certificate_id
        )

        self.assertIn("fail", status, "Invalid revocation occured.")

        logging.info("Starting test case: test_revoke_certificate_without_reason")

    def test_revoke_certificate_without_id_or_tag(self):
        logging.info("Starting test case: test_revoke_certificate_without_id_or_tag")

        status = CKMS_certificates.revoke_certificate(
            revocation_reason=self.revocation_reason
        )

        self.assertIn("fail", status, "Invalid revocation occured.")

        logging.info("Starting test case: test_revoke_certificate_without_id_or_tag")

if __name__ == '__main__':
    unittest.main()
