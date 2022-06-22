from RSA import RSA_decrypt, RSA_encrypt

#A series of questions that obtains information based off what is required with checks to 
# make sure the information being entered is correct.

decision = input("Woud you like to encrypt or decrypt? ")
if decision.lower() == "encrypt":
    print("This encryption algorithm will utilize a form of the Shamir Secret Sharing Algorithm which splits the encryption key into many shards.")
    plain_text = input("Insert plain text ")
    k = input("Enter the minimum number of shards needed to reconstruct private key ")
    while k.isdigit() == False:
        k = input("That's not a number please, enter the minimum number of shards needed to reconstruct private key ")    
    n = input("Enter the number of shards the encryption is to be split into (cannot be less than minimum) ")
    while n.isdigit() == False or n <= k:
        n = input("That's incorrect, please enter the number of shards the encryption is to be split into (cannot be less than minimum) ")
    RSA_encrypt(plain_text, k, n)
elif decision.lower() == "decrypt": 
    ciphertext = input("Please enter the cipher text ")
    shardk = input("Please enter the file: Shard[number].txt ")
    digitcheck = [char for char in shardk]
    check = False
    for x in digitcheck:
        if x.isdigit() == True:
           check = True
        else:
            continue   
    while shardk.endswith("].txt") == False and shardk.startswith("Shard[") == False and check == False:
        shardk = input("Please enter the file: Shard[number].txt ")

    RSA_decrypt(ciphertext,shardk)
else:
    while decision.lower() != "encrypt" or decision.lower() != "decrypt":
        decision = input("Woud you like to encrypt or decrypt? ")
