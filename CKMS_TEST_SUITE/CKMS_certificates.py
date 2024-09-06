import logging
from typing import Optional, List
import CKMS_general

# Set up logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def certify_certificate(
    certificate_id: Optional[str] = None,
    csr_path: Optional[str] = None,
    csr_format: Optional[str] = None,
    public_key_id_to_certify: Optional[str] = None,
    certificate_id_to_recertify: Optional[str] = None,
    generate_key_pair: bool = False,
    subject_name: Optional[str] = None,
    algorithm: str = None,
    issuer_private_key_id: Optional[str] = None,
    issuer_certificate_id: Optional[str] = None,
    validity_days: Optional[int] = None,
    extensions_file: Optional[str] = None,
    tags: Optional[list] = None
) -> str:
    
    command = "ckms certificates certify"

    # Add certificate ID if provided
    if certificate_id:
        command += f" --certificate-id {certificate_id}"

    # Add CSR path and format if provided
    if csr_path:
        command += f" --certificate-signing-request {csr_path} --certificate-signing-request-format {csr_format}"

    # Add public key to certify or certificate to re-certify
    if public_key_id_to_certify:
        command += f" --public-key-id-to-certify {public_key_id_to_certify}"
    elif certificate_id_to_recertify:
        command += f" --certificate-id-to-re-certify {certificate_id_to_recertify}"

    # Generate key pair if requested
    if generate_key_pair:
        command += f" --generate-key-pair true"
        if subject_name:
            command += f" --subject-name '{subject_name}'"
        command += f" --algorithm {algorithm}"

    # Specify issuer private key or certificate
    if issuer_private_key_id:
        command += f" --issuer-private-key-id {issuer_private_key_id}"
    elif issuer_certificate_id:
        command += f" --issuer-certificate-id {issuer_certificate_id}"

    # Set validity period if provided
    if validity_days:
        command += f" --days {validity_days}"

    # Add certificate extensions file if provided
    if extensions_file:
        command += f" --certificate-extensions {extensions_file}"

    # Add tags if provided
    if tags:
        for tag in tags:
            command += f" --tag {tag}"

    # Execute the CKMS command and check the result
    status = CKMS_general.run_command(command)

    if status:
        logging.info(f"Certificate generation successful: {certificate_id or subject_name}")
        return "pass"
    else:
        logging.error(f"Certificate generation failed: {certificate_id or subject_name}")
        return "fail"
    

def export_certificate(
    certificate_file: str,
    certificate_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
    output_format: str = "json-ttlv",
    pkcs12_password: Optional[str] = None,
    allow_revoked: bool = False
) -> str:

    # Initialize base command
    command = f"ckms certificates export {certificate_file}"

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

    # Execute the CKMS command and check the result
    status = CKMS_general.run_command(command)

    # Log the result and return status
    if status:
        logging.info(f"Certificate export successful: {certificate_file}")
        return "pass"
    else:
        logging.error(f"Certificate export failed: {certificate_file}")
        return "fail"
    

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
    """
    Function to import a certificate into the KMS using CKMS CLI.

    Args:
        certificate_file (str): The input file path in PEM, JSON-TTLV, or PKCS#12 format.
        certificate_id (str): The unique ID of the certificate.
        input_format (str): The format of the input certificate file (default: "json-ttlv").
        private_key_id (str): The corresponding private key ID, if any (ignored for PKCS#12 and CCADB).
        public_key_id (str): The corresponding public key ID, if any (ignored for PKCS#12 and CCADB).
        issuer_certificate_id (str): The issuer's certificate ID, if any (ignored for PKCS#12 and CCADB).
        pkcs12_password (str): Password to unlock the PKCS#12 file (only for PKCS#12 format).
        replace_existing (bool): Whether to replace an existing certificate under the same ID (default: False).
        tags (List[str]): Tags to associate with the certificate.
        key_usage (List[str]): A list of key usages for the certificate.

    Returns:
        status (str): "pass" or "fail" based on the import status.
    """

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
    status = CKMS_general.run_command(command)

    # Log the result and return status
    if status:
        logging.info(f"Certificate import successful: {certificate_file}")
        return "pass"
    else:
        logging.error(f"Certificate import failed: {certificate_file}")
        return "fail"
    
    
def revoke_certificate(
    revocation_reason: str,
    certificate_id: Optional[str] = None,
    tags: Optional[List[str]] = None
) -> str:
    """
    Function to revoke a certificate in the KMS using CKMS CLI.

    Args:
        revocation_reason (str): The reason for revocation.
        certificate_id (Optional[str]): The unique ID of the certificate to revoke.
        tags (Optional[List[str]]): Tags to use to retrieve the certificate if no certificate ID is specified.

    Returns:
        status (str): "pass" or "fail" based on the revocation status.
    """

    # Initialize base command
    command = f"ckms certificates revoke {revocation_reason}"

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
        logging.info(f"Certificate revocation successful: {certificate_id or ', '.join(tags) if tags else 'Unknown certificate'}")
        return "pass"
    else:
        logging.error(f"Certificate revocation failed: {certificate_id or ', '.join(tags) if tags else 'Unknown certificate'}")
        return "fail"
    
    
def destroy_certificate(
    certificate_id: Optional[str] = None,
    tags: Optional[List[str]] = None
) -> str:
    """
    Function to destroy a certificate in the KMS using CKMS CLI.

    Args:
        certificate_id (Optional[str]): The unique ID of the certificate to destroy.
        tags (Optional[List[str]]): Tags to use to retrieve the certificate if no certificate ID is specified.

    Returns:
        status (str): "pass" or "fail" based on the destruction status.
    """

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
        logging.info(f"Certificate destruction successful: {certificate_id or ', '.join(tags) if tags else 'Unknown certificate'}")
        return "pass"
    else:
        logging.error(f"Certificate destruction failed: {certificate_id or ', '.join(tags) if tags else 'Unknown certificate'}")
        return "fail"
    
    
def validate_certificate(
    certificates: Optional[List[str]] = None,
    unique_identifiers: Optional[List[str]] = None,
    validity_time: Optional[str] = None
) -> str:
    """
    Function to validate one or more certificates in the KMS using CKMS CLI.

    Args:
        certificates (Optional[List[str]]): Paths to one or more certificates to validate.
        unique_identifiers (Optional[List[str]]): Unique identifiers of certificate objects.
        validity_time (Optional[str]): Date-Time string indicating when the certificate chain should be valid.

    Returns:
        status (str): "pass" or "fail" based on the validation result.
    """

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
        logging.info(f"Certificate validation successful for: {certificates or unique_identifiers}")
        return "pass"
    else:
        logging.error(f"Certificate validation failed for: {certificates or unique_identifiers}")
        return "fail"
