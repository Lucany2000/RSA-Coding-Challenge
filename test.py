from RSA import RSA_encrypt, RSA_decrypt

#tests with a random plain text.  
#checks if the plain text being inputted is the same as the decryption output

def main():
    plain_text = "hahsaahjfdahiashflafaohfhfwhw"
    if RSA_decrypt(RSA_encrypt(plain_text, 2, 5), "Shard[2].txt") == plain_text:
        print(True)
    else:
        print(False)

main()