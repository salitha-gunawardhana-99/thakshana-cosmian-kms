import unittest
import CKMS_certificates

class TestCkmsCertificatesDestroy(unittest.TestCase):
    def setUp(self):
        # Set up variables for testing
        self.certificate_id = "test-cert-id"
        self.tag = "test-cert-tag"

    def test_destroy_certificate_by_id(self):
        print("\nStarting test case: test_destroy_certificate_by_id")

        output = CKMS_certificates.destroy_certificate(
            certificate_id=self.certificate_id
        )

        self.assertIn("success", output, "Failed to destroy certificate by ID.")

        print("Finishing test case: test_destroy_certificate_by_id\n")

    def test_destroy_certificate_by_tag(self):
        print("\nStarting test case: test_destroy_certificate_by_tag")

        output = CKMS_certificates.destroy_certificate(
            tag=self.tag
        )

        self.assertIn("success", output, "Failed to destroy certificate by tag.")

        print("Finishing test case: test_destroy_certificate_by_tag\n")

    def test_destroy_certificate_without_id_or_tag(self):
        print("\nStarting test case: test_destroy_certificate_without_id_or_tag")

        output = CKMS_certificates.destroy_certificate()

        self.assertIn("error", output, "Destruction should fail without certificate ID or tag.")

        print("Finishing test case: test_destroy_certificate_without_id_or_tag\n")

if __name__ == '__main__':
    unittest.main()
