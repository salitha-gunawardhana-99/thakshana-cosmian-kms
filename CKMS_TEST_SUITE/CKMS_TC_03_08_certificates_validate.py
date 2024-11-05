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

"""

This following re-certify command should be enough: 
ckms certificates certify -n 1a95b1af-3a30-4884-a4dc-6161c58637de

No option is provided since all required information to renew the certificate is already present in the KMS database. Indeed the KMS already has the Subject Name, public key, private key and X509 extensions. 
However, some options can be overridden like --days or --certificate-extensions.
    
"""

import unittest

class TestCkmsCertificatesValidate(unittest.TestCase):
    pass

if __name__ == '__main__':
    unittest.main()
