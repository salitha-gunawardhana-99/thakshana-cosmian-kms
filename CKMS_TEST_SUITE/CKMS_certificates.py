import logging
from typing import Optional, List
import os
import json
import base64
import CKMS_general

# Set up logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")


def ensure_openssl_installed():
    try:
        CKMS_general.run_command("openssl version")
        logging.info("OpenSSL is already installed.")
    except Exception:
        logging.info("OpenSSL not found. Installing...")
        CKMS_general.run_command("sudo apt-get update")
        CKMS_general.run_command("sudo apt-get install openssl -y")

def generate_json_certificate(common_name="MyCert", private_key_filename="private_key.pem", certificate_filename="certificate.pem", json_filename="certificate.json"):
    ensure_openssl_installed()

    # Check if the private key already exists
    if not os.path.exists(private_key_filename):
        CKMS_general.run_command(f"openssl genpkey -algorithm RSA -out {private_key_filename} -pkeyopt rsa_keygen_bits:2048")
        logging.info(f"Private key generated: {private_key_filename}")
    else:
        logging.info(f"Private key already exists: {private_key_filename}")

    # Check if the certificate already exists
    if not os.path.exists(certificate_filename):
        CKMS_general.run_command(f"openssl req -new -x509 -key {private_key_filename} -out {certificate_filename} -days 365 -subj \"/CN={common_name}\"")
        logging.info(f"Self-signed certificate generated: {certificate_filename}")
    else:
        logging.info(f"Certificate already exists: {certificate_filename}")

    # Convert certificate to JSON format
    if not os.path.exists(json_filename):
        try:
            with open(certificate_filename, 'rb') as cert_file:
                cert_content = cert_file.read()

            # Encode certificate in base64 without newlines
            cert_base64 = base64.b64encode(cert_content).decode('utf-8').replace('\n', '')

            cert_json = {
                "tag": "Certificate",
                "type": "Structure",
                "value": [
                    {
                        "tag": "CertificateType",
                        "type": "Enumeration",
                        "value": "X509"
                    },
                    {
                        "tag": "CertificateValue",
                        "type": "ByteString",
                        "value": cert_base64
                    }
                ]
            }

            with open(json_filename, 'w') as json_file:
                json.dump(cert_json, json_file, indent=4)
            
            logging.info(f"JSON certificate file generated: {json_filename}")
        except Exception as e:
            logging.error(f"Failed to generate JSON certificate file: {str(e)}")
    else:
        logging.info(f"JSON certificate file already exists: {json_filename}")
        

def generate_pem_certificate(common_name="MyCert", private_key_filename="private_key.pem", certificate_filename="certificate.pem"):
    ensure_openssl_installed()

    # Check if the private key already exists
    if not os.path.exists(private_key_filename):
        # Generate private key
        CKMS_general.run_command(f"openssl genpkey -algorithm RSA -out {private_key_filename} -pkeyopt rsa_keygen_bits:2048")
        logging.info(f"Private key generated: {private_key_filename}")
    else:
        logging.info(f"Private key already exists: {private_key_filename}")

    # Check if the certificate already exists
    if not os.path.exists(certificate_filename):
        # Generate self-signed certificate in PEM format
        CKMS_general.run_command(f"openssl req -new -x509 -key {private_key_filename} -out {certificate_filename} "
                    f"-days 365 -subj \"/CN={common_name}\"")
        logging.info(f"PEM certificate generated: {certificate_filename}")
    else:
        logging.info(f"PEM certificate already exists: {certificate_filename}")
        
        
def generate_pkcs12_certificate(common_name="MyCert", private_key_filename = "private_key.pem", certificate_filename = "certificate.pem", pkcs12_filename="certificate.p12", pkcs12_password="password"):
    ensure_openssl_installed()

    # Check if the private key already exists
    if not os.path.exists(private_key_filename):
        # Generate private key
        CKMS_general.run_command(f"openssl genpkey -algorithm RSA -out {private_key_filename} -pkeyopt rsa_keygen_bits:2048")
        logging.info(f"Private key generated: {private_key_filename}")
    else:
        logging.info(f"Private key already exists: {private_key_filename}")

    # Check if the certificate already exists
    if not os.path.exists(certificate_filename):
        # Generate self-signed certificate
        CKMS_general.run_command(f"openssl req -new -x509 -key {private_key_filename} -out {certificate_filename} "
                    f"-days 365 -subj \"/CN={common_name}\"")
        logging.info(f"Self-signed certificate generated: {certificate_filename}")
    else:
        logging.info(f"Certificate already exists: {certificate_filename}")

    # Check if the PKCS12 file already exists
    if not os.path.exists(pkcs12_filename):
        # Create PKCS12 file
        CKMS_general.run_command(f"openssl pkcs12 -export -out {pkcs12_filename} -inkey {private_key_filename} "
                    f"-in {certificate_filename} -password pass:{pkcs12_password}")
        logging.info(f"PKCS12 file generated: {pkcs12_filename}")
    else:
        logging.info(f"PKCS12 file already exists: {pkcs12_filename}")


def import_certificate_issuer_to_kms(pkcs12_filename="issuer.p12", pkcs12_password="password", tag="issuer_tag"):
    
    # Check if the PKCS12 file exists
    if not os.path.exists(pkcs12_filename):
        logging.info(f"PKCS12 file {pkcs12_filename} not found. Please generate or provide the file.")
        return [None, None]

    try:
        # Check if a certificate with the same tag already exists in the KMS
        check_command = f"ckms certificates export -t {tag} -t _cert -f json-ttlv cert_exported.json"
       
        result = CKMS_general.run_command(check_command)
        if result:
            logging.info(f"A certificate with tag '{tag}' already exists in the KMS. Import aborted.")
            # identifier = CKMS_general.extract_unique_identifier(result)
            return ["pass", None]
        
        logging.info(f"No certificate with tag '{tag}' found in the KMS. Proceeding with import.")

        # Import the PKCS12 file into the KMS
        import_command = f"ckms certificates import {pkcs12_filename} --format pkcs12 --pkcs12-password {pkcs12_password} --tag {tag}"
        result = CKMS_general.run_command(import_command)
        if result:
            logging.info(f"PKCS12 file {pkcs12_filename} imported successfully into the KMS with tag '{tag}'.")
            identifier = CKMS_general.extract_unique_identifier(result)
            return ["pass", identifier]
        
    except Exception as e:
        logging.error(f"Failed to import the PKCS12 file into the KMS: {str(e)}")
    finally:
        # Clean up the temporary exported file if it was created
        if os.path.exists("cert_exported.json"):
            os.remove("cert_exported.json")
            

def certify_certificate(
    certificate_id: Optional[str] = None,
    csr_path: Optional[str] = None,
    csr_format: Optional[str] = None,
    public_key_id_to_certify: Optional[str] = None,
    certificate_id_to_recertify: Optional[str] = None,
    generate_key_pair: bool = False,
    subject_name: str = "C=SL, ST=Western, L=Colombo, O=Thakshana, CN=salitha.gunawardhana@thakshana.com",
    algorithm: str = "rsa4096",
    issuer_private_key_id: Optional[str] = None,
    issuer_certificate_id: Optional[str] = None,
    validity_days: Optional[int] = 365,
    extensions_file: Optional[str] = None,
    tags: Optional[list] = None
) -> str:
    
    check_command = f"ckms certificates export -t {tags[0]} -t _cert -f json-ttlv cert_exported.json"
       
    result = CKMS_general.run_command(check_command)
    if result:
        logging.info(f"A certificate with tag '{tags[0]}' already exists in the KMS. Import aborted.")
        return
    
    command = "ckms certificates certify"

    # Add certificate ID if provided
    if certificate_id:
        command += f" -c {certificate_id}"

    # Add CSR path and format if provided
    if csr_path:
        command += f" -r {csr_path}"
        
    if csr_format:
        command += f" -f {csr_format}"
        
    # Add public key to certify or certificate to re-certify
    if public_key_id_to_certify:
        command += f" -p {public_key_id_to_certify}"
    elif certificate_id_to_recertify:
        command += f" -n {certificate_id_to_recertify}"

    # Generate key pair if requested
    if generate_key_pair:
        command += f" -g"
        command += f" -a {algorithm}"
    
    if subject_name:
        command += f" -s '{subject_name}'"

    # Specify issuer private key or certificate
    if issuer_private_key_id:
        command += f" -k {issuer_private_key_id}"
    
    if issuer_certificate_id:
        command += f" -i {issuer_certificate_id}"

    # Set validity period if provided
    if validity_days:
        command += f" -d {validity_days}"

    # Add certificate extensions file if provided
    if extensions_file:
        command += f" -e {extensions_file}"

    # Add tags if provided
    if tags:
        for tag in tags:
            command += f" -t {tag}"

    # Execute the CKMS command and check the result
    status = CKMS_general.run_command(command)

    if status:
        logging.info("Certificate generation successful.")
        identifire = CKMS_general.extract_unique_identifier(status)
        return ["pass", identifire]
    else:
        logging.error("Certificate generation failed.")
        return ["fail", status]
    

def export_certificate(
    certificate_file = "cert_exported.json",
    certificate_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
    output_format: str = "json-ttlv",
    pkcs12_password: Optional[str] = None,
    allow_revoked: bool = False
) -> str:

    # Initialize base command
    command = "ckms certificates export"

    # Add certificate ID if provided
    if certificate_id:
        command += f" --certificate-id {certificate_id}"

    # Add tags if provided
    if tags:
        for tag in tags:
            command += f" --tag {tag}"

    # Set the output format
    command += f" --format {output_format}"

    # Add PKCS#12 password if provided and format is pkcs12
    if pkcs12_password and output_format == "pkcs12":
        command += f" --pkcs12-password {pkcs12_password}"

    # Allow revoked certificates if requested
    if allow_revoked:
        command += f" --allow-revoked true"
        
    command += f" {certificate_file}"

    # Execute the CKMS command and check the result
    result = CKMS_general.run_command(command)
    
    if result:
        # Read the exported certificate from the file if the command succeeds
        logging.info(f"Successfully exported the certificate to '{certificate_file}'.")
        with open(certificate_file, "rb") as f:
            cert_data = f.read()
        # os.remove(key_file)
        return cert_data
    
    logging.error(f"Failed to export the certificate to '{certificate_file}'.")
    return None
    

def import_certificate(
    certificate_file: str,
    certificate_id: Optional[str] = None,
    input_format: str = "json-ttlv",
    private_key_id: Optional[str] = None,
    public_key_id: Optional[str] = None,
    issuer_certificate_id: Optional[str] = None,
    pkcs12_password: Optional[str] = None,
    replace_existing: bool = False,
    tags: Optional[List[str]] = None,
    key_usage: Optional[List[str]] = None
) -> str:
    
    # Check if the certificate file exists
    if not os.path.exists(certificate_file):
        logging.info(f"certificate file {certificate_file} not found. Please generate or provide the file.")
        return [None, None]
    
    # Check if a certificate with the same tag already exists in the KMS
    check_command = f"ckms certificates export -t {tags[0]} -t _cert -f json-ttlv cert_exported.json"
       
    result = CKMS_general.run_command(check_command)
    if result:
        logging.info(f"A certificate with tag '{tags[0]}' already exists in the KMS. Import aborted.")
        if os.path.exists("cert_exported.json"):
            os.remove("cert_exported.json")
        return ["pass", None]
        
    logging.info(f"No certificate with tag '{tags[0]}' found in the KMS. Proceeding with import.")

    # Initialize base command
    command = f"ckms certificates import {certificate_file}"

    # Add certificate ID if provided
    if certificate_id:
        command += f" {certificate_id}"

    # Set the input format
    command += f" --format {input_format}"

    # Add private key ID if provided and format is not PKCS#12 or CCADB
    if private_key_id and input_format not in ["pkcs12", "ccadb"]:
        command += f" --private-key-id {private_key_id}"

    # Add public key ID if provided and format is not PKCS#12 or CCADB
    if public_key_id and input_format not in ["pkcs12", "ccadb"]:
        command += f" --public-key-id {public_key_id}"

    # Add issuer certificate ID if provided and format is not PKCS#12 or CCADB
    if issuer_certificate_id and input_format not in ["pkcs12", "ccadb"]:
        command += f" --issuer-certificate-id {issuer_certificate_id}"

    # Add PKCS#12 password if format is PKCS#12
    if pkcs12_password and input_format == "pkcs12":
        command += f" --pkcs12-password {pkcs12_password}"

    # Add replace flag if replacing an existing certificate
    if replace_existing:
        command += f" --replace true"

    # Add tags if provided
    if tags:
        for tag in tags:
            command += f" --tag {tag}"

    # Add key usages if provided
    if key_usage:
        for usage in key_usage:
            command += f" --key-usage {usage}"

    # Execute the CKMS command and check the result
    result = CKMS_general.run_command(command)

    # Log the result and return status    
    if result:
            logging.info(f"Certificate file {certificate_file} imported successfully into the KMS with tag '{tags[0]}'.")
            identifier = CKMS_general.extract_unique_identifier(result)
            return ["pass", identifier]
        
    logging.error(f"Certificate import failed: {certificate_file}")
        
    return [None, None]
    
    
def revoke_certificate(
    revocation_reason: Optional[str] = None,
    certificate_id: Optional[str] = None,
    tags: Optional[List[str]] = None
) -> str:

    # Initialize base command
    command = "ckms certificates revoke"
    
    if revocation_reason:
        command += f" {revocation_reason}"

    # Add certificate ID if provided
    if certificate_id:
        command += f" --certificate-id {certificate_id}"

    # Add tags if provided
    if tags:
        for tag in tags:
            command += f" --tag {tag}"

    # Execute the CKMS command and check the result
    status = CKMS_general.run_command(command)

    # Log the result and return status
    if status:
        logging.info(f"Certificate revocation successful.")
        return "pass"
    else:
        logging.error(f"Certificate revocation failed.")
        return "fail"
    
    
def destroy_certificate(
    certificate_id: Optional[str] = None,
    tags: Optional[List[str]] = None
) -> str:
    
    # Initialize base command
    command = "ckms certificates destroy"

    # Add certificate ID if provided
    if certificate_id:
        command += f" --certificate-id {certificate_id}"

    # Add tags if provided
    if tags:
        for tag in tags:
            command += f" --tag {tag}"

    # Execute the CKMS command and check the result
    status = CKMS_general.run_command(command)

    # Log the result and return status
    if status:
        logging.info(f"Certificate destruction successful.")
        return "pass"
    else:
        logging.error(f"Certificate destruction failed.")
        return "fail"
    
    
def validate_certificate(
    certificates: Optional[List[str]] = None,
    unique_identifiers: Optional[List[str]] = None,
    validity_time: Optional[str] = None
) -> str:
    
    # Initialize base command
    command = "ckms certificates validate"

    # Add certificate paths if provided
    if certificates:
        for cert in certificates:
            command += f" --certificate {cert}"

    # Add unique identifiers if provided
    if unique_identifiers:
        for uid in unique_identifiers:
            command += f" --unique-identifier {uid}"

    # Add validity time if provided
    if validity_time:
        command += f" --validity-time {validity_time}"

    # Execute the CKMS command and check the result
    status = CKMS_general.run_command(command)

    # Log the result and return status
    if status:
        logging.info(f"Certificate validation successful.")
        return "pass"
    else:
        logging.error(f"Certificate validation failed.")
        return "fail"
