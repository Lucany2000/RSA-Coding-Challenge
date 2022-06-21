from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
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
                    encryption_algorithm=serialization.BestAvailableEncryption(bytes(plain_text,"UTF-8")))
    key = bytes("".join(private_bytes.decode().splitlines()[1:-1]), "UTF-8")
    hexdecimal = key.hex()
    #decimal = int.from_bytes(key, byteorder=sys.byteorder)

    if exists(f"Shard[{k}].txt") == False:
        for file in os.listdir("/RSA-Coding-Challenge"):
            if file.startswith("Shard"):
                os.remove(file)
        private = open(f"Shard[{k}].txt", "x")
        private.close()

    subprocess.call(f'cmd /c "shamir create {k}of{n} --master-secret={hexdecimal} > Shard[{k}].txt"', shell=False)
    # shares = generate_shares(n,k,decimal)
    # print(shares)
    # secret = reconstruct_secret(shares)
    # print(secret)

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

    return ciphertext

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
        # interpreter = sys.executable
        # print(interpreter)   
        if len(shards) > k:
            # hexkey = subprocess.run(['cmd /c "python -m shamir_mnemonic.cli recover "'], capture_output=True, shell=False)
            # os.system('cmd /c "python -m shamir_mnemonic.cli recover > test.txt"')
            for i in range(k):
                # process = subprocess.call('cmd /c "python -m shamir_mnemonic.cli recover"', shell=False)
                
                # os.system(f'cmd /c "python -m shamir_mnemonic.cli recover < {shards[i]}"' )
                process = Popen(['shamir', 'recover'], stdout=PIPE, stderr=PIPE, stdin=PIPE) 
                hexkey = process.communicate(bytes(shards[i],"UTF-8"))   
        else:
            return "There are not enough shards to reconstuct the private key"

        print(hexkey)    
        # str(hexkey).replace("Your master secret is: ","")
        # print(hexkey)    
        # key = bytes.fromhex(str(hexkey))
        # print(key)          
        # shards = shares
        # print(shards)
        # for shard in shards:
        #     shards[shards.index(shard)] = shard.strip()
        # print(shards)
    else:
        return "This isn't the correct file."    

RSA_encrypt("figkgkglig",2,5)

RSA_decrypt(RSA_encrypt("figkgkglig", 2, 5), "Shard[2].txt")



#def test():