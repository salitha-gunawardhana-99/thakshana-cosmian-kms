import subprocess
import time
import logging
from typing import Optional, List
import re
import csv
import os

# Constants
KMS_PORT = 9998
KMS_CONTAINER_NAME = "kms"
# KMS_IMAGE = "ghcr.io/cosmian/kms:4.17.0"
KMS_IMAGE = "ghcr.io/cosmian/kms:4.19.1"

SUT = "COSMIAN KMS"
VERSION = "4.19.1"

# Print hex mode
def print_hex(label: str, data: bytes):
    hex_data = data.hex()
    logging.info(f'{label}: {hex_data}')


# Set up logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")


# Function to run a shell command
def run_command(command: str) -> Optional[str]:
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result.decode("utf-8").strip()
    except subprocess.CalledProcessError:
        return None


# Function to start the Cosmian KMS server
def start_kms_server():
    existing_container = run_command(f"docker ps -q -f name={KMS_CONTAINER_NAME}")
    if existing_container:
        logging.info("KMS server is already running.")
        return

    existing_container = run_command(f"docker ps -aq -f name={KMS_CONTAINER_NAME}")
    if existing_container:
        logging.info("KMS container found. Starting the KMS server...")
        run_command(f"docker start {KMS_CONTAINER_NAME}")
    else:
        logging.info("KMS container not found. Starting a new KMS container...")
        run_command(f"docker run -d -p {KMS_PORT}:{KMS_PORT} --name {KMS_CONTAINER_NAME} {KMS_IMAGE}")

    logging.info("Waiting for KMS server to start...")
    for _ in range(10):
        if run_command(f"docker ps -q -f name={KMS_CONTAINER_NAME}"):
            logging.info("KMS server started.")
            return
        time.sleep(1)
    logging.error("KMS server failed to start.")
    

def clear_database():
    # Define the container name
    container_name = "kms"

    try:
        # Step 1: Enter the Docker container and check if sqlite3 is installed
        exec_command = f"docker exec {container_name} /bin/bash -c"
        
        # Step 2: Check if sqlite3 is installed
        check_sqlite = f"{exec_command} 'sqlite3 --version'"
        result = subprocess.run(check_sqlite, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode != 0:
            # logging.info("sqlite3 not found. Installing sqlite3 inside the container.")
            
            # Step 3: Install sqlite3 if not available
            install_sqlite = f"{exec_command} 'apt-get update && apt-get install -y sqlite3'"
            subprocess.run(install_sqlite, shell=True, check=True)
        else:
            # logging.info("sqlite3 is already installed.")
            pass
        
        # Step 4: Execute SQLite queries in one step (non-interactive)
        # logging.info("Navigating to cosmian-kms/sqlite-data directory and executing queries.")
        
        # Combine the SQL commands to execute them in one subprocess call
        sqlite_commands = "DELETE FROM objects; DELETE FROM tags;"
        
        execute_sql = f"{exec_command} 'cd cosmian-kms/sqlite-data && sqlite3 kms.db \"{sqlite_commands}\"'"
        subprocess.run(execute_sql, shell=True, check=True)

        logging.info("KMS cleaned up successfully.")

    except subprocess.CalledProcessError as e:
        logging.error(f"An error occurred: {e}")
        raise


# Extract unique identifier from the output
def extract_unique_identifier(output: str) -> Optional[str]:
    pattern = r"Unique identifier:\s([a-f0-9\-]+)"
    match = re.search(pattern, output)
    return match.group(1) if match else None


# Extract certificate ID based on a tag
def extract_cert_id(tag: str) -> Optional[str]:
    output = run_command(f"ckms attributes get -t {tag} -t _cert")
    return extract_unique_identifier(output)


# Extract public and private key identifiers
def extract_key_identifiers(output: str) -> List[Optional[str]]:
    public_key_pattern = r"Public key unique identifier:\s([a-f0-9\-]+)"
    private_key_pattern = r"Private key unique identifier:\s([a-f0-9\-]+)"
    
    public_key_match = re.search(public_key_pattern, output)
    private_key_match = re.search(private_key_pattern, output)
    
    public_key_id = public_key_match.group(1) if public_key_match else None
    private_key_id = private_key_match.group(1) if private_key_match else None
    
    return [public_key_id, private_key_id]


# Append data to a CSV file
def append_to_csv(filename: str, data: list):
    file_exists = os.path.isfile(filename)

    with open(filename, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(data)
    
    if file_exists:
        print(f"Appended new data to {filename}: {data}")
    else:
        print(f"Created new CSV file {filename} and added the first row: {data}")
        
        
def stop_kms_container():
    # Command to stop the KMS container using ckms
    stop_command = "ckms stop kms"
        
    # Execute the command
    run_command(stop_command)

    logging.info("KMS Docker container stopped successfully.")

