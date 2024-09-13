import unittest
import CKMS_certificates

class TestCkmsCertificatesRevoke(unittest.TestCase):
    def setUp(self):
        # Set up variables for testing
        self.certificate_id = "test-cert-id"
        self.tag = "test-cert-tag"
        self.revocation_reason = "KeyCompromise"

    def test_revoke_certificate_by_id(self):
        print("\nStarting test case: test_revoke_certificate_by_id")

        output = CKMS_certificates.revoke_certificate(
            certificate_id=self.certificate_id,
            revocation_reason=self.revocation_reason
        )

        self.assertIn("success", output, "Failed to revoke certificate by ID.")

        print("Finishing test case: test_revoke_certificate_by_id\n")

    def test_revoke_certificate_by_tag(self):
        print("\nStarting test case: test_revoke_certificate_by_tag")

        output = CKMS_certificates.revoke_certificate(
            tag=self.tag,
            revocation_reason=self.revocation_reason
        )

        self.assertIn("success", output, "Failed to revoke certificate by tag.")

        print("Finishing test case: test_revoke_certificate_by_tag\n")

    def test_revoke_certificate_without_reason(self):
        print("\nStarting test case: test_revoke_certificate_without_reason")

        with self.assertRaises(ValueError):
            CKMS_certificates.revoke_certificate(
                certificate_id=self.certificate_id,
                revocation_reason=""
            )

        print("Finishing test case: test_revoke_certificate_without_reason\n")

    def test_revoke_certificate_without_id_or_tag(self):
        print("\nStarting test case: test_revoke_certificate_without_id_or_tag")

        output = CKMS_certificates.revoke_certificate(
            revocation_reason=self.revocation_reason
        )

        self.assertIn("error", output, "Revocation should fail without certificate ID or tag.")

        print("Finishing test case: test_revoke_certificate_without_id_or_tag\n")

if __name__ == '__main__':
    unittest.main()
