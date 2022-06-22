from RSA import RSA_encrypt, RSA_decrypt

def main():
    plain_text = "hahsaahjfdahiashflafaohfhfwhw"
    if RSA_decrypt(RSA_encrypt(plain_text, 2, 5), "Shard[2].txt") == plain_text:
        print(True)
    else:
        print(False)

main()