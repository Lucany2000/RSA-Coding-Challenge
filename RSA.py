from pydoc import plain
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from os.path import exists
import os.path
import os
from os import path
import subprocess
from subprocess import Popen, PIPE
import sys
import shamir_mnemonic

# plain_text = input()

def RSA_encrypt(plain_text,k,n):
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    private_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(b'$ThEb3sTpa$sw0rd%Om3gaLamDa6Xl9'))#bytes(plain_text,"UTF-8"))                         
    
    hexdecimal = private_bytes.hex()

    if exists(f"Shard[{k}].txt") == False:
        for file in os.listdir("/RSA-Coding-Challenge"):
            if file.startswith("Shard"):
                os.remove(file)
        private = open(f"Shard[{k}].txt", "x")
        private.close()

    subprocess.call(f'cmd /c "shamir create {k}of{n} --master-secret={hexdecimal} > Shard[{k}].txt"', shell=False)

    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)

    ciphertext = public_key.encrypt(
    bytes(plain_text,"UTF-8"), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None)
    )

    with open(f"Shard[{k}].txt", "r") as private:
        file = private.readlines()
    
    with open(f"Shard[{k}].txt", "w") as private:
        for i in range(2, len(file)):
            private.write(file[i])

    private.close()    


    if exists("Public.txt") == False:
        public = open("Public.txt","x")
    else:
        public = open("Public.txt","w")

    public.write(str(public_bytes))

    public.close()

    return ciphertext, plain_text

def RSA_decrypt(ciphertext, Shardk):
    if path.exists(Shardk) and str(Shardk).endswith(".txt"):
        k = ""
        for m in Shardk:
            if m.isdigit():
                k = k + m
        k = int(k)        
        private = open(f"Shard[{k}].txt", 'r')
        shards = private.readlines()
        private.close() 
        if len(shards) > k:
            process = Popen(['shamir', 'recover'], stdout=PIPE, stderr=PIPE, stdin=PIPE) 
            for i in range(k):
                process.stdin.write(bytes(shards[i],"UTF-8"))
        else:
            return "There are not enough shards to reconstuct the private key"

        clean = str(process.stdout.read().strip())
        pos = str(clean).find("Your master secret is: ")
        key = bytes.fromhex((clean[pos:-1].replace("Your master secret is: ", "")))

        private_key = load_pem_private_key(key, password=b'$ThEb3sTpa$sw0rd%Om3gaLamDa6Xl9', backend=default_backend())

        plain_text = private_key.decrypt(
        ciphertext,
        padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
        return plain_text.decode()
    else:
        return "This isn't the correct file."    

def test():
    plaintext = "hahsaahjfdahiashflafaohfhfwhw" 
    if RSA_decrypt(RSA_encrypt(plaintext, 2, 5)[0], "Shard[2].txt") == plaintext:
        return True
    else:
        return False

print(test())
