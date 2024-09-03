# CKMS_sym.py
import os
import subprocess
import time
import logging
from typing import Optional, List

# Constants
KMS_PORT = 9998
KMS_CONTAINER_NAME = "kms"
KMS_IMAGE = "ghcr.io/cosmian/kms:4.17.0"

# Set up logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")


# Function to run a shell command
def run_command(command: str) -> Optional[str]:
    try:
        result = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT)
        return result.decode("utf-8").strip()
    except subprocess.CalledProcessError:
        return None


# Function to start the Cosmian KMS server
def start_kms_server():
    existing_container = run_command(
        f"docker ps -q -f name={KMS_CONTAINER_NAME}")
    if existing_container:
        logging.info("KMS server is already running.")
        return

    existing_container = run_command(
        f"docker ps -aq -f name={KMS_CONTAINER_NAME}")
    if existing_container:
        logging.info("KMS container found. Starting the KMS server...")
        run_command(f"docker start {KMS_CONTAINER_NAME}")
    else:
        logging.info(
            "KMS container not found. Starting a new KMS container...")
        run_command(
            f"docker run -d -p {KMS_PORT}:{KMS_PORT} --name {KMS_CONTAINER_NAME} {KMS_IMAGE}")

    logging.info("Waiting for KMS server to start...")
    for _ in range(10):
        if run_command(f"docker ps -q -f name={KMS_CONTAINER_NAME}"):
            logging.info("KMS server started.")
            return
        time.sleep(1)
    logging.error("KMS server failed to start.")


# Function to generate a key using ckms
def generate_key(
    key_name: str,
    key_type: str = "aes",
    key_length: Optional[int] = None,
    key_bytes_base64: Optional[str] = None,
    temp_key_file: str = "temp_key_check.key",
) -> str:
    result = run_command(
        f"ckms sym keys export --tag {key_name} --key-format raw {temp_key_file}")
    if result:
        logging.info(
            f"Key '{key_name}' already exists. Skipping key generation.")
        os.remove(temp_key_file)
        return [result, "pass"]

    if key_bytes_base64:
        command = f"ckms sym keys create --algorithm {key_type} --bytes-b64 {key_bytes_base64} --tag {key_name}"
    elif key_length:
        command = f"ckms sym keys create --algorithm {key_type} --number-of-bits {key_length} --tag {key_name}"
    else:
        logging.error(
            "Key length or key bytes must be provided if not using an existing key.")
        return [result, "fail"]

    status = run_command(command)
    if status:
        logging.info(f"Key '{key_name}' generated successfully.")
        return [status, "pass"]
    else:
        logging.error(f"Failed to generate key '{key_name}'.")
        return [status, "fail"]


# Function to retrieve the key from the KMS using ckms
def retrieve_key(key_name: str, key_file: str = "key_exported.key") -> Optional[bytes]:
    logging.info(f"Retrieving key '{key_name}'...")
    result = run_command(
        f"ckms sym keys export --tag {key_name} --key-format raw {key_file}")
    if result:
        with open(key_file, "rb") as f:
            key_data = f.read()
        os.remove(key_file)
        return key_data
    logging.error(f"Failed to retrieve the key '{key_name}'.")
    return None


# Function to export a key from the KMS using ckms
def export_key(
    key_file: str,
    key_id: Optional[str] = None,
    key_format: str = "json-ttlv",
    tags: Optional[List[str]] = None,
    unwrap: str = "false",
    wrap_key_id: Optional[str] = None,
    allow_revoked: str = "false",
) -> Optional[bytes]:
    command = f"ckms sym keys export -f {key_format} {key_file}"

    if key_id:
        command += f" -k {key_id}"
    if tags:
        for tag in tags:
            command += f" -t {tag}"
    if unwrap:
        command += f" -u {unwrap}"
    if wrap_key_id:
        command += f" -w {wrap_key_id}"
    if allow_revoked:
        command += f" -i {allow_revoked}"

    logging.info(f"Exporting key to '{key_file}'...")
    result = run_command(command)

    if result:
        with open(key_file, "rb") as f:
            key_data = f.read()
        os.remove(key_file)
        return key_data
    logging.error(f"Failed to export the key to '{key_file}'.")
    return None


# Function to import a key into the KMS using ckms
def import_key(
    key_file: str,
    key_format: str = "json-ttlv",
    key_id: Optional[str] = None,
    public_key_id: Optional[str] = None,
    private_key_id: Optional[str] = None,
    certificate_id: Optional[str] = None,
    unwrap: str = "false",
    replace_existing: str = "false",
    tags: Optional[List[str]] = None,
    key_usage: Optional[List[str]] = None,
) -> str:
    command = f"ckms sym keys import -f {key_format} {key_file}"

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

    result = run_command(command)
    return "pass" if result else "fail"


# Function to revoke a key in the KMS using ckms
def revoke_key(revocation_reason: str, key_id: Optional[str] = None, tags: Optional[List[str]] = None) -> bool:
    if not key_id and not tags:
        logging.error(
            "Either key_id or tags must be provided to revoke a key.")
        return False

    command = f"ckms sym keys revoke '{revocation_reason}'"

    if key_id:
        command += f" --key-id {key_id}"
    if tags:
        for tag in tags:
            command += f" --tag {tag}"

    result = run_command(command)
    if result:
        logging.info(f"Key revoked successfully. Reason: {revocation_reason}")
        return True
    else:
        logging.error(f"Failed to revoke the key. Reason: {revocation_reason}")
        return False


# Function to destroy a key in the KMS using ckms
def destroy_key(key_id: Optional[str] = None, tags: Optional[List[str]] = None) -> bool:
    if not key_id and not tags:
        logging.error(
            "Either key_id or tags must be provided to destroy a key.")
        return False

    command = "ckms sym keys destroy"

    if key_id:
        command += f" --key-id {key_id}"
    if tags:
        for tag in tags:
            command += f" --tag {tag}"

    result = run_command(command)
    if result:
        logging.info("Key destroyed successfully.")
        return True
    else:
        logging.error("Failed to destroy the key.")
        return False
