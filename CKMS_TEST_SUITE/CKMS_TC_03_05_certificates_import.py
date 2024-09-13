import unittest
import os
import CKMS_certificates

class TestCkmsCertificatesImport(unittest.TestCase):
    def setUp(self):
        # Set up variables for testing
        self.certificate_file_pem = "test_cert.pem"
        self.certificate_file_json = "test_cert.json"
        self.certificate_file_pkcs12 = "test_cert.p12"
        self.certificate_id = "test-cert-id"
        self.private_key_id = "test-private-key-id"
        self.public_key_id = "test-public-key-id"
        self.issuer_certificate_id = "test-issuer-cert-id"
        self.pkcs12_password = "testpassword"
        self.tag = "test-cert-tag"
        self.key_usage = "sign"

        # Create dummy certificate files for testing (in actual cases, these should be real files)
        with open(self.certificate_file_pem, 'w') as f:
            f.write("-----BEGIN CERTIFICATE-----\nDummy PEM Certificate\n-----END CERTIFICATE-----\n")
        with open(self.certificate_file_json, 'w') as f:
            f.write("{\"cert\": \"Dummy JSON TTLV Certificate\"}")
        with open(self.certificate_file_pkcs12, 'w') as f:
            f.write("Dummy PKCS#12 Certificate")

    def tearDown(self):
        # Clean up test certificate files
        if os.path.exists(self.certificate_file_pem):
            os.remove(self.certificate_file_pem)
        if os.path.exists(self.certificate_file_json):
            os.remove(self.certificate_file_json)
        if os.path.exists(self.certificate_file_pkcs12):
            os.remove(self.certificate_file_pkcs12)

    def test_import_certificate_as_pem(self):
        print("\nStarting test case: test_import_certificate_as_pem")

        output = CKMS_certificates.import_certificate(
            certificate_file=self.certificate_file_pem,
            certificate_id=self.certificate_id,
            format="pem",
            private_key_id=self.private_key_id,
            public_key_id=self.public_key_id,
            issuer_certificate_id=self.issuer_certificate_id,
            tag=self.tag,
            key_usage=self.key_usage
        )

        self.assertIn("success", output, "Failed to import certificate as PEM.")

        print("Finishing test case: test_import_certificate_as_pem\n")

    def test_import_certificate_as_json(self):
        print("\nStarting test case: test_import_certificate_as_json")

        output = CKMS_certificates.import_certificate(
            certificate_file=self.certificate_file_json,
            certificate_id=self.certificate_id,
            format="json-ttlv",
            private_key_id=self.private_key_id,
            public_key_id=self.public_key_id,
            issuer_certificate_id=self.issuer_certificate_id,
            tag=self.tag,
            key_usage=self.key_usage
        )

        self.assertIn("success", output, "Failed to import certificate as JSON.")

        print("Finishing test case: test_import_certificate_as_json\n")

    def test_import_certificate_as_pkcs12(self):
        print("\nStarting test case: test_import_certificate_as_pkcs12")

        output = CKMS_certificates.import_certificate(
            certificate_file=self.certificate_file_pkcs12,
            certificate_id=self.certificate_id,
            format="pkcs12",
            pkcs12_password=self.pkcs12_password,
            tag=self.tag
        )

        self.assertIn("success", output, "Failed to import certificate as PKCS12.")

        print("Finishing test case: test_import_certificate_as_pkcs12\n")

    def test_import_certificate_chain(self):
        print("\nStarting test case: test_import_certificate_chain")

        # Assuming a PEM-stack for the chain format
        chain_file = self.certificate_file_pem
        output = CKMS_certificates.import_certificate(
            certificate_file=chain_file,
            certificate_id=self.certificate_id,
            format="chain",
            tag=self.tag
        )

        self.assertIn("success", output, "Failed to import certificate chain.")

        print("Finishing test case: test_import_certificate_chain\n")

    def test_import_certificate_with_replace(self):
        print("\nStarting test case: test_import_certificate_with_replace")

        output = CKMS_certificates.import_certificate(
            certificate_file=self.certificate_file_pem,
            certificate_id=self.certificate_id,
            format="pem",
            replace=True,
            tag=self.tag
        )

        self.assertIn("success", output, "Failed to replace existing certificate.")

        print("Finishing test case: test_import_certificate_with_replace\n")

    def test_import_certificate_with_missing_id(self):
        print("\nStarting test case: test_import_certificate_with_missing_id")

        output = CKMS_certificates.import_certificate(
            certificate_file=self.certificate_file_pem,
            format="pem",
            tag=self.tag
        )

        self.assertIn("success", output, "Failed to import certificate without specifying certificate ID.")

        print("Finishing test case: test_import_certificate_with_missing_id\n")

    def test_import_certificate_with_wrong_format(self):
        print("\nStarting test case: test_import_certificate_with_wrong_format")

        wrong_format = "invalid-format"
        output = CKMS_certificates.import_certificate(
            certificate_file=self.certificate_file_pem,
            certificate_id=self.certificate_id,
            format=wrong_format
        )

        self.assertIn("error", output, "Import should fail with an invalid format.")
        print("Finishing test case: test_import_certificate_with_wrong_format\n")

if __name__ == '__main__':
    unittest.main()
