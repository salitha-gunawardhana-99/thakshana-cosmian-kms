import subprocess

# List of test case scripts to be executed sequentially
test_scripts = [
    "CKMS_TC_03_01_certificates_certify.py",
    "CKMS_TC_03_04_certificates_export.py",
    "CKMS_TC_03_05_certificates_import.py",
    "CKMS_TC_03_06_certificates_revoke.py",
    "CKMS_TC_03_07_certificates_destroy.py",
    "CKMS_TC_03_08_certificates_validate.py",
    "CKMS_TC_04_01_01_ec_keys_create.py",
    "CKMS_TC_04_01_02_ec_keys_export.py",
    "CKMS_TC_04_01_03_ec_keys_import.py",
    "CKMS_TC_04_01_04_ec_keys_revoke.py",
    "CKMS_TC_04_01_05_ec_keys_destroy.py",
    "CKMS_TC_08_01_01_rsa_keys_create.py",
    "CKMS_TC_08_01_02_rsa_keys_export.py",
    "CKMS_TC_08_01_03_rsa_keys_import.py",
    "CKMS_TC_08_01_04_rsa_keys_revoke.py",
    "CKMS_TC_08_01_05_rsa_keys_destroy.py",
    "CKMS_TC_10_01_01_sym_keys_create.py",
    "CKMS_TC_10_01_02_sym_keys_rekey.py",
    "CKMS_TC_10_01_03_sym_keys_export.py",
    "CKMS_TC_10_01_04_sym_keys_import.py",
    "CKMS_TC_10_01_05_sym_keys_revoke.py",
    "CKMS_TC_10_01_06_sym_keys_destroy.py"
]

# Function to run each test script sequentially
def run_test_scripts():
    for script in test_scripts:
        print(f"Running {script}...")
        result = subprocess.run(["python3", script], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"{script} executed successfully.\n")
        else:
            print(f"Error in executing {script}. Error details:\n{result.stderr}")
            break  # Stop execution if any script fails

if __name__ == "__main__":
    run_test_scripts()
