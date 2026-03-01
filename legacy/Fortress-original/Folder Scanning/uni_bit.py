import hashlib
import os

#Global Variable
malware_hashes = list(open("virusHash.unibit","r").read().split('\n'))
virusInfo = list(open("virusInfo.unibit","r").read().split('\n'))

#Get hash of file
def sha256_hash(filename):
    with open(filename,"rb") as f:
        bytes =f.read()
        sha256hash = hashlib.sha256(bytes).hexdigest()

        f.close()
    return sha256hash

#Malware detection by hashing
def malware_checker(pathOfFile):
    global malware_hashes
    global virusInfo

    hash_malware_check= sha256_hash(pathOfFile)
    counter = 0

    for i in malware_hashes:
        if i == hash_malware_check:
            return virusInfo[counter]
        counter +=1
    return 0

#Malware detection in folder
virusName = []
def folderScanner():
    #Normal Folder Scanner 
    #get list of all files and directories  
    path =(r"C:\Users\Chiranjeev\The CV\Code Playground\College Projects Repo\Cyber Project 4th Sem\Antivirus updated\Folder Scanning\misc")
    dir_list=os.listdir(path) 

    fileN="" 
    for i in dir_list: 
        fileN = path+"\\"+i 
        if malware_checker(fileN) != 0: 
            virusName.append(malware_checker(fileN)+" :: File :: "+i)

folderScanner()
print(virusName)

#Virus Remover
