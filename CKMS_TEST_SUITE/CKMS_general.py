import subprocess
import time
import logging
from typing import Optional


# Constants
KMS_PORT = 9998
KMS_CONTAINER_NAME = "kms"
KMS_IMAGE = "ghcr.io/cosmian/kms:4.17.0"


def print_hex(label: str, data: bytes):
    hex_data = data.hex()
    logging.info(f'{label}: {hex_data}')


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