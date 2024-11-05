import subprocess
import latex_content
import CKMS_general
import logging

# Set up logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

latex_begining = latex_content.latex_begining

# Write the LaTeX content to a .tex file
with open('test_report_of_cosmian_kms_test_suite.tex', 'w') as f:
    f.write(latex_begining)

test_scripts_suggested = [
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

# List of test case scripts to be executed sequentially
test_scripts_written = [
    "CKMS_TC_03_01_certificates_certify.py",
    "CKMS_TC_03_04_certificates_export.py",
    "CKMS_TC_03_05_certificates_import.py",
    "CKMS_TC_03_06_certificates_revoke.py",
    "CKMS_TC_03_07_certificates_destroy.py",
    "CKMS_TC_10_01_01_sym_keys_create.py",
    "CKMS_TC_10_01_03_sym_keys_export.py",
    "CKMS_TC_10_01_04_sym_keys_import.py",
    "CKMS_TC_10_01_05_sym_keys_revoke.py",
    "CKMS_TC_10_01_06_sym_keys_destroy.py"
]

# Function to run each test script sequentially
def run_test_scripts():
    print("")
    for script in test_scripts_written:
        print(f"Running {script}...")
        result = subprocess.run(["python3", script], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"{script} executed successfully.\n")
        else:
            print(f"Error in executing {script}. Error details:\n{result.stderr}")
            break  # Stop execution if any script fails
    
    CKMS_general.clear_database()
    CKMS_general.stop_kms_container()

if __name__ == "__main__":
    run_test_scripts()

latex_end = latex_content.latex_end

with open('test_report_of_cosmian_kms_test_suite.tex', 'a') as f:
        f.write(latex_end)
     
print("")
   
# Convert .tex file to .pdf using pdflatex
subprocess.run(["pdflatex", "test_report_of_cosmian_kms_test_suite.tex"], check=True)
