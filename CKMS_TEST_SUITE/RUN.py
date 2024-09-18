import subprocess

# Define the run_command function if not already defined
def run_command(command):
    """
    Executes a command using subprocess and prints the output in real-time.
    
    :param command: The command to be executed (e.g., 'python test1.py').
    """
    try:
        # Execute the command and print output in real-time
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Print stdout and stderr as they are generated
        for stdout_line in iter(process.stdout.readline, ""):
            print(stdout_line, end='')  # Print output in the same console
        
        # Wait for process to finish and capture exit code
        process.stdout.close()
        process.wait()

        # Capture any errors
        for stderr_line in iter(process.stderr.readline, ""):
            print(stderr_line, end='')

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing command '{command}': {e}")

def main():
    # List of commands to run sequentially
    commands = ['python3 CKMS_TC_03_01_certificates_certify.py', 'python3 test8.py']
    
    for command in commands:
        print(f"\nRunning command: {command}")
        run_command(command)

if __name__ == "__main__":
    main()
