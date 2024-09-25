import os
import logging
from typing import Optional, List
import CKMS_general


# Set up logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")


# Function to generate a key using ckms
def generate_key(
    tags: str,
    key_type: str = "aes",
    key_length: Optional[int] = 256,
    key_bytes_base64: Optional[str] = None,
    temp_key_file: str = "temp_key_check.key",
) -> list:
    result = CKMS_general.run_command(
        f"ckms sym keys export --tag {tags} --key-format raw {temp_key_file}")
    if result:
        logging.info(
            f"Key '{tags}' already exists. Skipping key generation.")
        os.remove(temp_key_file)
        return ["pass", result]

    if key_bytes_base64:
        command = f"ckms sym keys create --algorithm {key_type} --bytes-b64 {key_bytes_base64} --tag {tags}"
        
    if key_length:
        command = f"ckms sym keys create --algorithm {key_type} --number-of-bits {key_length} --tag {tags}"

    status = CKMS_general.run_command(command)
    if status:
        logging.info(f"Key '{tags}' generated successfully.")
        identifire = CKMS_general.extract_unique_identifier(status)
        return ["pass", identifire]
    else:
        logging.error(f"Failed to generate key '{tags}'.")
        return ["fail", status]
    
    
# Function to generate a rsa key using ckms
def generate_rsa_key(
    size_in_bits: Optional[int] = None,
    tags: Optional[List[str]] = None,
    temp_key_file: str = "temp_key_check.key"
) -> list:
    result = CKMS_general.run_command(
        f"ckms rsa keys export --tag {tags[0]} --tag _sk --key-format raw {temp_key_file}")
    if result:
        logging.info(
            f"Key '{tags[0]}' already exists. Skipping key generation.")
        os.remove(temp_key_file)
        return [result, "pass"]

    # Initialize base command
    command = "ckms rsa keys create"
    
    if size_in_bits:
        command += f" --size_in_bits {size_in_bits}"

    # Add tags if provided
    if tags:
        for tag in tags:
            command += f" --tag {tag}"

    # Execute the CKMS command and check the result
    status = CKMS_general.run_command(command)

    # Log the result and return status
    if status:
        logging.info("RSA key pair creation successful.")
        identifiers = CKMS_general.extract_key_identifiers(status)
        return ["pass"] + identifiers
    else:
        logging.error("RSA key pair creation failed.")
        return ["fail", status]
    

# Function to export a key from the KMS using ckms
def export_key(
    key_type: str = "sym",
    key_file: str = "key_exported.json",
    key_id: Optional[str] = None,
    key_format: str = "json-ttlv",
    tags: Optional[List[str]] = None,
    unwrap: str = "false",
    wrap_key_id: Optional[str] = None,
    allow_revoked: str = "false",
) -> Optional[bytes]:
    # Start building the base command
    command = f"ckms {key_type} keys export -f {key_format}"

    # Handle key ID or tags
    if key_id:
        command += f" -k {key_id}"
    elif tags:
        for tag in tags:
            command += f" -t {tag}"

    # Add the rest of the parameters
    if unwrap.lower() == "true":
        command += f" -u true"
    if wrap_key_id:
        command += f" -w {wrap_key_id}"
    if allow_revoked.lower() == "true":
        command += f" -i true"

    # Append the key file at the end
    command += f" {key_file}"

    # Execute the command
    result = CKMS_general.run_command(command)

    if result:
        # Read the exported key from the file if the command succeeds
        with open(key_file, "rb") as f:
            key_data = f.read()
        # os.remove(key_file)
        logging.info(f"Successfully export the key to '{key_file}'.")
        return key_data

    logging.error(f"Failed to export the key to '{key_file}'.")
    return None


# Function to import a key into the KMS using ckms
def import_key(
    key_file: str,
    key_type: str = "sym",
    key_format: str = "json-ttlv",
    key_id: Optional[str] = None,
    public_key_id: Optional[str] = None,
    private_key_id: Optional[str] = None,
    certificate_id: Optional[str] = None,
    unwrap: str = None,
    replace_existing: str = None,
    tags: Optional[List[str]] = None,
    key_usage: Optional[List[str]] = None,
) -> list:
    
    # Check if the key file exists
    if not os.path.exists(key_file):
        logging.info(f"key file {key_file} not found. Please generate or provide the file.")
        return [None, None]
    
    # Check if a key with the same tag already exists in the KMS
    check_command = f"ckms sym keys export -t {tags[0]} -t _kk -f json-ttlv key_exported.json"
       
    result = CKMS_general.run_command(check_command)
    if result:
        logging.info(f"A key with tag '{tags[0]}' already exists in the KMS. Import aborted.")
        if os.path.exists("key_exported.json"):
            os.remove("key_exported.json")
        return ["pass", None]
        
    logging.info(f"No key with tag '{tags[0]}' found in the KMS. Proceeding with import.")
    
    command = f"ckms {key_type} keys import -f {key_format}"

    if key_id:
        command += f" {key_id}"
    if public_key_id:
        command += f" -p {public_key_id}"
    if private_key_id:
        command += f" -k {private_key_id}"
    if certificate_id:
        command += f" -c {certificate_id}"
    if unwrap:
        command += f" -u {unwrap}"
    if replace_existing:
        command += f" -r {replace_existing}"
    if tags:
        for tag in tags:
            command += f" -t {tag}"
    if key_usage:
        for usage in key_usage:
            command += f" --key-usage {usage}"

    # Append the key file at the end
    command += f" {key_file}"

    result = CKMS_general.run_command(command)
    
    # Log the result and return status    
    if result:
            logging.info(f"Key file {key_file} imported successfully into the KMS with tag '{tags[0]}'.")
            identifier = CKMS_general.extract_unique_identifier(result)
            return ["pass", identifier]
        
    logging.error(f"Key import failed: {key_file}")
        
    return [None, None]


# Function to revoke a key in the KMS using ckms
def revoke_key(revocation_reason: Optional[str] = None, key_type: Optional[str] = "sym", key_id: Optional[str] = None, tags: Optional[List[str]] = None) -> str:
    if not key_id and not tags:
        logging.error(
            "Either key_id or tags must be provided to revoke a key.")
        return "fail"

    command = f"ckms {key_type} keys revoke"
    
    if revocation_reason:
        command += f" {revocation_reason}"

    if key_id:
        command += f" --key-id {key_id}"
        
    if tags:
        for tag in tags:
            command += f" --tag {tag}"

    result = CKMS_general.run_command(command)
    if result:
        logging.info(f"Key revoked successfully. Reason: {revocation_reason}")
        return "pass"
    else:
        logging.error(f"Failed to revoke the key. Reason: {revocation_reason}")
        return "fail"


# Function to destroy a key in the KMS using ckms
def destroy_key(key_type: str = "sym", key_id: Optional[str] = None, tags: Optional[List[str]] = None) -> str:
    if not key_id and not tags:
        logging.error(
            "Either key_id or tags must be provided to destroy a key.")
        return "fail"

    command = f"ckms {key_type} keys destroy"

    if key_id:
        command += f" --key-id {key_id}"
    if tags:
        for tag in tags:
            command += f" --tag {tag}"

    result = CKMS_general.run_command(command)
    if result:
        logging.info("Key destroyed successfully.")
        return "pass"
    else:
        logging.error("Failed to destroy the key.")
        return "fail"
