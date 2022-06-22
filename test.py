from RSA import RSA_encrypt, RSA_decrypt

def main():
    plain_text = "hahsaahjfdahiashflafaohfhfwhw"
    RSA_encrypt(plain_text,2,5)
    if RSA_decrypt(RSA_encrypt(plain_text, 2, 5)[0], "Shard[2].txt") == plain_text:
        return True
    else:
        return False

print(main())