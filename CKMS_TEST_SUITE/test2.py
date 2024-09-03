import CKMS_sym

import re

# Example output string
output = CKMS_sym.run_command(
    "ckms sym keys create --algorithm aes --number-of-bits 128 --tag my_key")

print(output)

# Regular expression to match the UUID (unique identifier)
match = re.search(r"Unique identifier:\s+([a-f0-9\-]+)", output)

if match:
    unique_id = match.group(1)
    print(f"Extracted Unique ID: {unique_id}")
else:
    print("Unique identifier not found.")
