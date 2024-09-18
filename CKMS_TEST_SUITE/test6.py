import os
import CKMS_general

def generate_csr(
    common_name: str = "example.com",
    country: str = "US",
    state: str = "California",
    locality: str = "San Francisco",
    organization: str = "Example Inc.",
    organizational_unit: str = "IT",
    email: str = "admin@example.com",
    private_key_filename: str = "private_key.pem",
    csr_filename: str = "request.csr",
) -> bool:
    """
    Simplified function to generate a CSR and overwrite the CSR file if it exists.
    
    :param common_name: The common name (usually domain name or IP) for the CSR.
    :param country: The two-letter country code.
    :param state: The full name of the state or province.
    :param locality: The city or locality.
    :param organization: The legal name of the organization.
    :param organizational_unit: The division or unit within the organization.
    :param email: The email address of the responsible party.
    :param private_key_filename: Filename to save the private key (if not already created).
    :param csr_filename: The output filename for the CSR (will be overwritten if it exists).
    :param run_command: A function to run shell commands.
    :return: True if CSR generation is successful, False otherwise.
    """
    
    if not CKMS_general.run_command:
        raise ValueError("run_command function is required")

    # Check if private key already exists, otherwise create it
    if not os.path.exists(private_key_filename):
        private_key_cmd = f"openssl genpkey -algorithm RSA -out {private_key_filename} -pkeyopt rsa_keygen_bits:2048"
        if CKMS_general.run_command(private_key_cmd):
            print(f"Private key generated: {private_key_filename}")
        else:
            print(f"Failed to generate private key.")
            return False
    else:
        print(f"Private key already exists: {private_key_filename}")

    # Generate the CSR (overwrite if file already exists)
    subject = f"/C={country}/ST={state}/L={locality}/O={organization}/OU={organizational_unit}/CN={common_name}/emailAddress={email}"
    
    csr_cmd = f"openssl req -new -key {private_key_filename} -out {csr_filename} -subj '{subject}'"
    
    if CKMS_general.run_command(csr_cmd):
        print(f"CSR generated successfully: {csr_filename} (overwritten if it existed)")
        return True
    else:
        print(f"Failed to generate CSR. Check for errors in the subject format or openssl installation.")
        return False


generate_csr()
