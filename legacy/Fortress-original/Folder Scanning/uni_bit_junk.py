import hashlib
import os

# Global Variables
malware_hashes = list(open("virusHash.unibit", "r").read().split('\n'))
virusInfo = list(open("virusInfo.unibit", "r").read().split('\n'))

# Get hash of file
def sha256_hash(filename):
    with open(filename, "rb") as f:
        bytes = f.read()
        sha256hash = hashlib.sha256(bytes).hexdigest()
    return sha256hash

# Malware detection by hashing
def malware_checker(pathOfFile):
    global malware_hashes
    global virusInfo

    hash_malware_check = sha256_hash(pathOfFile)
    counter = 0

    for i in malware_hashes:
        if i == hash_malware_check:
            return virusInfo[counter]
        counter += 1
    return 0

# Junk file detection and removal
def junk_file_remover(path):
    # Define file extensions or patterns for junk files
    junk_extensions = ['.tmp', '.temp', '.bak','.cgv']
    
    removed_files = []  # Store removed file paths
    
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            # Check if file extension matches junk file extensions
            if any(file.lower().endswith(ext) for ext in junk_extensions):
                # Remove the junk file
                os.remove(file_path)
                removed_files.append(file_path)  # Add removed file to list
                print(f"Junk file removed: {file_path}")
    
    return removed_files  # Return list of removed files

# Malware detection in folder
def folderScanner(path):
    virus_detections = []  # Store virus detections
    junk_files_removed = []  # Store removed junk files
    
    # Scan for malware
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            virus_info = malware_checker(file_path)
            if virus_info != 0:
                virus_detections.append(virus_info + " :: File :: " + file)
    
    # Remove junk files
    junk_files_removed = junk_file_remover(path)
    
    return virus_detections, junk_files_removed

# Take folder path as input from the user
folder_path = input("Enter the path of the folder to be scanned: ")

# Call folderScanner function with user input path
virus_detections, junk_files_removed = folderScanner(folder_path)

# Print virus detections
print("Virus Detected:")
for virus_detection in virus_detections:
    print(virus_detection)


