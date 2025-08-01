import os
import subprocess

def start_msys2_ucrt64():
    current_dir = os.getcwd()

    # Convert Windows path to MSYS2-compatible path
    msys2_compatible_path = current_dir.replace("\\", "/").replace("C:", "/c")

    print(f"Starting MSYS2 UCRT64 in directory: {msys2_compatible_path}")
    
    # Path to the MSYS2 bash executable
    msys2_bash_path = r"C:\msys64\usr\bin\bash.exe"  # General MSYS2 bash path
    
    # Set environment variable for UCRT64
    env = os.environ.copy()
    env["MSYSTEM"] = "UCRT64"
    
    # Start MSYS2 UCRT64 and change to the current directory
    subprocess.run([msys2_bash_path, "--login", "-i", "-c", f"cd {msys2_compatible_path} && exec bash"], env=env)

if __name__ == "__main__":
    start_msys2_ucrt64()