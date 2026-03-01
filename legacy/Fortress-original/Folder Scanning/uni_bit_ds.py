import hashlib
import os
from concurrent.futures import ThreadPoolExecutor

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

    for i, hash_value in enumerate(malware_hashes):
        if hash_value == hash_malware_check:
            return virusInfo[i]
    return None

# Malware detection in folder (deep scanning)
def folder_scanner(folder_path):
    detected_viruses = []
    scanned_files = []

    def scan_file(file_path):
        nonlocal detected_viruses
        virus_info = malware_checker(file_path)
        if virus_info:
            detected_viruses.append((file_path, virus_info))
        scanned_files.append(file_path)

    with ThreadPoolExecutor() as executor:
        for root, dirs, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                executor.submit(scan_file, file_path)

    return scanned_files, detected_viruses

def format_output(scanned_files, detected_viruses):
    formatted_output = ""
    for file_path in scanned_files:
        if (file_path, "") in detected_viruses:
            formatted_output += f"[Malicious] {file_path}\n"
        else:
            formatted_output += f"[Clean] {file_path}\n"

    formatted_output += "\nDetected Viruses:\n"
    for file_path, virus_info in detected_viruses:
        formatted_output += f"File: {file_path} - Virus Info: {virus_info}\n"

    return formatted_output

if __name__ == "__main__":
    folder_path = input("Enter the path of the folder to scan: ")
    scanned_files, detected_viruses = folder_scanner(folder_path)
    output = format_output(scanned_files, detected_viruses)
    print(output)
