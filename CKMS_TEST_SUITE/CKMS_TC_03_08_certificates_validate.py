"""

3.8 ckms certificates validate

Validate a certificate

Usage

ckms certificates validate [options]

Arguments

--certificate [-v] <CERTIFICATE> One or more Certificates filepath

--unique-identifier [-k] <UNIQUE_IDENTIFIER> One or more Unique Identifiers of Certificate Objects

--validity-time [-t] <VALIDITY_TIME> A Date-Time object indicating when the certificate chain needs to be valid. If omitted, the current date and time SHALL be assumed

"""

import unittest

class TestCkmsCertificatesValidate(unittest.TestCase):
    pass

if __name__ == '__main__':
    unittest.main()
