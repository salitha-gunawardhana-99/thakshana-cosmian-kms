import re

def extract_unique_identifier(output):
    # Define the regex pattern to find the unique identifier (UUID)
    pattern = r"Unique identifier:\s([a-f0-9\-]+)"
    
    # Search for the pattern in the output
    match = re.search(pattern, output)
    
    # If a match is found, return the unique identifier
    if match:
        return match.group(1)
    
    # If no match is found, return None or handle it accordingly
    return None

# Example usage
output_text1 = """
The private key in the PKCS12 file was successfully imported!
          Unique identifier: 91e2e2bb-5da5-4b57-bef8-82138408b1b9

  Tags:
    - test
"""

# Example usage
output_text2 = """
The symmetric key was successfully generated.
	  Unique identifier: 93c19b1e-70f9-4390-8a4e-0e3314b94ee6

  Tags:
    - MySymmetricKey
"""

# Example usage
output_text3 = """
The certificate was successfully generated.
	  Unique identifier: 5f018899-122e-456a-8fa1-d4e75ee1a9a0

  Tags:
    - Bob1
"""

# Example usage
output_text4 = """
The certificate was successfully generated.
	  Unique identifier: 1e8afb21-5dba-4190-b0fe-58b0d1d2f56d

  Tags:
    - Bob2
"""

# Example usage
output_text5 = """
The certificate ["test_cert_issuer","_cert"] of type Certificate was exported to "cert_exported.json"
          Unique identifier: ["test_cert_issuer","_cert"]
"""    
unique_id = extract_unique_identifier(output_text5)
print(f"Extracted Unique Identifier: {unique_id}")