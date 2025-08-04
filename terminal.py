import os
import subprocess

def windows_to_unix_path(windows_path):
    # Convert Windows path to Unix-style path
    unix_path = windows_path.replace("\\", "/").replace("C:", "/c")
    return unix_path

def start_msys2_ucrt64():
    current_dir = os.getcwd()
    unix_dir = windows_to_unix_path(current_dir)

    print(f"Starting MSYS2 UCRT64 in directory: {current_dir} (Unix path: {unix_dir})")
    
    # Path to the MSYS2 bash executable
    msys2_bash_path = r"C:\msys64\usr\bin\bash.exe"  # Update this path if necessary
    
    if not os.path.exists(msys2_bash_path):
        print(f"Error: MSYS2 bash not found at {msys2_bash_path}")
        return
    
    # Set environment variable for UCRT64
    env = os.environ.copy()
    env["MSYSTEM"] = "UCRT64"
    
    try:
        # Start MSYS2 UCRT64 and change to the current directory
        subprocess.run(
            [msys2_bash_path, "--login", "-i", "-c", f"cd {unix_dir} && exec bash"],
            env=env,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error: MSYS2 bash failed to start. {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    start_msys2_ucrt64()