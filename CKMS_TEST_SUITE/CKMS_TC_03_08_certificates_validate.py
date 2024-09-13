import unittest
import CKMS_certificates
from datetime import datetime

class TestCkmsCertificatesValidate(unittest.TestCase):
    def setUp(self):
        # Set up variables for testing
        self.certificate = "path/to/test-certificate.pem"
        self.unique_identifier = "test-cert-uid"
        self.validity_time = datetime.now().isoformat()

    def test_validate_certificate_by_file(self):
        print("\nStarting test case: test_validate_certificate_by_file")

        output = CKMS_certificates.validate_certificate(
            certificate=self.certificate
        )

        self.assertIn("success", output, "Failed to validate certificate by file.")

        print("Finishing test case: test_validate_certificate_by_file\n")

    def test_validate_certificate_by_unique_identifier(self):
        print("\nStarting test case: test_validate_certificate_by_unique_identifier")

        output = CKMS_certificates.validate_certificate(
            unique_identifier=self.unique_identifier
        )

        self.assertIn("success", output, "Failed to validate certificate by unique identifier.")

        print("Finishing test case: test_validate_certificate_by_unique_identifier\n")

    def test_validate_certificate_with_validity_time(self):
        print("\nStarting test case: test_validate_certificate_with_validity_time")

        output = CKMS_certificates.validate_certificate(
            certificate=self.certificate,
            validity_time=self.validity_time
        )

        self.assertIn("success", output, "Failed to validate certificate with validity time.")

        print("Finishing test case: test_validate_certificate_with_validity_time\n")

    def test_validate_certificate_without_parameters(self):
        print("\nStarting test case: test_validate_certificate_without_parameters")

        output = CKMS_certificates.validate_certificate()

        self.assertIn("error", output, "Validation should fail without any parameters.")

        print("Finishing test case: test_validate_certificate_without_parameters\n")

if __name__ == '__main__':
    unittest.main()
