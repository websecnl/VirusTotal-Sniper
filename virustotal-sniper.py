import hashlib
import time
import requests

# MEMORY BOOLEANS
state = False

# VIRUSTOTAL API KEY (You can get this for free from VirusTotal)
virustotal = ""

filename = raw_input("Enter the input file name: ")
sha256_hash = hashlib.sha256()
with open(filename, "rb") as f:
    # Read and update hash string value in blocks of 4K
    for byte_block in iter(lambda: f.read(4096), b""):
        sha256_hash.update(byte_block)
    print("SHA256: " + str(sha256_hash.hexdigest()))
    mem = (sha256_hash.hexdigest())

def get():
    url = ("http://www.virustotal.com/api/v3/files/" + str(mem))
    header = {"x-apikey": "" + str(virustotal) + ""}
    global code
    code = requests.get(url, headers=header).status_code

get()
print("[+] Monitoring VirusTotal...")
while state == False:
    if code == 200:
        print("\n[!] WARNING: A virustotal submittion has been detected.")
        state = True
        quit(0)
    else:
        print("[+] NO SUBMITTIONS DETECTED.")
        get()
        time.sleep(60)
