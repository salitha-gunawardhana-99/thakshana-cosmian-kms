import unittest
import os
import CKMS_certificates

class TestCkmsCertificatesExport(unittest.TestCase):
    def setUp(self):
        # Set up variables for testing
        self.certificate_id = "test-cert-id"
        self.export_file_pem = "exported_cert.pem"
        self.export_file_json = "exported_cert.json"
        self.export_file_pkcs12 = "exported_cert.p12"
        self.tag = "test-cert-tag"
        self.pkcs12_password = "testpassword"

    def tearDown(self):
        # Clean up exported files
        if os.path.exists(self.export_file_pem):
            os.remove(self.export_file_pem)
        if os.path.exists(self.export_file_json):
            os.remove(self.export_file_json)
        if os.path.exists(self.export_file_pkcs12):
            os.remove(self.export_file_pkcs12)

    def test_export_certificate_as_pem(self):
        print("\nStarting test case: test_export_certificate_as_pem")

        output = CKMS_certificates.export_certificate(
            certificate_file=self.export_file_pem,
            certificate_id=self.certificate_id,
            format="pem"
        )

        self.assertTrue(os.path.exists(self.export_file_pem), "PEM certificate export failed.")
        self.assertIn("success", output, "Failed to export certificate as PEM.")

        print("Finishing test case: test_export_certificate_as_pem\n")

    def test_export_certificate_as_json(self):
        print("\nStarting test case: test_export_certificate_as_json")

        output = CKMS_certificates.export_certificate(
            certificate_file=self.export_file_json,
            certificate_id=self.certificate_id,
            format="json-ttlv"
        )

        self.assertTrue(os.path.exists(self.export_file_json), "JSON certificate export failed.")
        self.assertIn("success", output, "Failed to export certificate as JSON.")

        print("Finishing test case: test_export_certificate_as_json\n")

    def test_export_certificate_as_pkcs12(self):
        print("\nStarting test case: test_export_certificate_as_pkcs12")

        output = CKMS_certificates.export_certificate(
            certificate_file=self.export_file_pkcs12,
            certificate_id=self.certificate_id,
            format="pkcs12",
            pkcs12_password=self.pkcs12_password
        )

        self.assertTrue(os.path.exists(self.export_file_pkcs12), "PKCS#12 certificate export failed.")
        self.assertIn("success", output, "Failed to export certificate as PKCS#12.")

        print("Finishing test case: test_export_certificate_as_pkcs12\n")

    def test_export_certificate_by_tag(self):
        print("\nStarting test case: test_export_certificate_by_tag")

        output = CKMS_certificates.export_certificate(
            certificate_file=self.export_file_pem,
            tag=self.tag,
            format="pem"
        )

        self.assertTrue(os.path.exists(self.export_file_pem), "Certificate export by tag failed.")
        self.assertIn("success", output, "Failed to export certificate using tag.")

        print("Finishing test case: test_export_certificate_by_tag\n")

    def test_export_revoked_certificate(self):
        print("\nStarting test case: test_export_revoked_certificate")

        output = CKMS_certificates.export_certificate(
            certificate_file=self.export_file_pem,
            certificate_id=self.certificate_id,
            format="pem",
            allow_revoked=True
        )

        self.assertTrue(os.path.exists(self.export_file_pem), "Revoked certificate export failed.")
        self.assertIn("success", output, "Failed to export revoked certificate.")

        print("Finishing test case: test_export_revoked_certificate\n")

    def test_export_certificate_with_wrong_id(self):
        print("\nStarting test case: test_export_certificate_with_wrong_id")

        wrong_cert_id = "nonexistent-cert-id"
        output = CKMS_certificates.export_certificate(
            certificate_file=self.export_file_pem,
            certificate_id=wrong_cert_id,
            format="pem"
        )

        self.assertNotIn("success", output, "Export should fail with a wrong certificate ID.")
        self.assertFalse(os.path.exists(self.export_file_pem), "File should not be created with a wrong certificate ID.")

        print("Finishing test case: test_export_certificate_with_wrong_id\n")

    def test_export_certificate_with_missing_id_and_tag(self):
        print("\nStarting test case: test_export_certificate_with_missing_id_and_tag")

        output = CKMS_certificates.export_certificate(
            certificate_file=self.export_file_pem,
            format="pem"
        )

        self.assertIn("error", output, "Export should fail when both certificate ID and tag are missing.")
        self.assertFalse(os.path.exists(self.export_file_pem), "File should not be created when both ID and tag are missing.")

        print("Finishing test case: test_export_certificate_with_missing_id_and_tag\n")

if __name__ == '__main__':
    unittest.main()
