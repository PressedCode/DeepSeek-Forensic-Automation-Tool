import os

file_paths = []

while True:
    path = input("  File path: ").strip()
    if path.lower() == "done":
        break
    
    # Remove quotes from the input path
    path = path.strip('"')
    
    # Replace forward slashes with backslashes for Windows compatibility
    path = path.replace('/', '\\')
    
    # Convert to absolute path
    path = os.path.abspath(path)
    
    print(f"Checking path: {path}")
    
    if os.path.exists(path):
        if os.path.isfile(path):
            file_paths.append(path)
        else:
            print(f"[ERROR] Path is not a file: {path}")
    else:
        print(f"[ERROR] File not found: {path}")

print("Collected file paths:", file_paths)

file_paths[0] = path.strip('"')

# Replace backslashes with forward slashes
file_paths[0] = file_paths[0].replace("\\", "/")

# Check if the path is a Windows drive path (e.g., "C:/" or "F:/")
if ":/" in file_paths[0]:
    drive_letter = file_paths[0][0].lower()  # Extract the drive letter
    wsl_path = file_paths[0].replace(f"{drive_letter}:/", f"/mnt/{drive_letter}/")
    print(wsl_path)
else:
    # If it's not a drive path, assume it's already in WSL format
    print(file_paths[0])

print("Collected file paths:", file_paths)