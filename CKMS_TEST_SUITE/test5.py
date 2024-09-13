import re

def extract_key_identifiers(output):
    # Define regex patterns for public and private key unique identifiers
    public_key_pattern = r"Public key unique identifier:\s([a-f0-9\-]+)"
    private_key_pattern = r"Private key unique identifier:\s([a-f0-9\-]+)"
    
    # Search for public key unique identifier
    public_key_match = re.search(public_key_pattern, output)
    
    # Search for private key unique identifier
    private_key_match = re.search(private_key_pattern, output)
    
    # Extract public and private key identifiers if found, else None
    public_key_id = public_key_match.group(1) if public_key_match else None
    private_key_id = private_key_match.group(1) if private_key_match else None
    
    return public_key_id, private_key_id

# Example usage
output_text1 = """
The RSA key pair has been created.
	  Public key unique identifier: dba007f4-ff29-4509-8fca-23e01dce3aa4
	  Private key unique identifier: 6406ecd7-1ec7-4824-9b65-85de48c4d8b8

  Tags:
    - MyRsaKey
"""

output_text2 = """
The EC key pair has been created.
	  Public key unique identifier: 197d872c-d9cf-4251-829c-33cb48c38b24
	  Private key unique identifier: 57a89dbe-b4c8-4dad-b080-ba6d53cc9914

  Tags:
    - MyEcKey
"""

public_key_id, private_key_id = extract_key_identifiers(output_text2)
print(f"Public Key Unique Identifier: {public_key_id}")
print(f"Private Key Unique Identifier: {private_key_id}")
