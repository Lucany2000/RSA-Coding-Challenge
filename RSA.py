# from __future__ import division
# from __future__ import print_function
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
# import shamir
import random
from math import ceil
from decimal import Decimal
# import functools
from Shamir import make_random_shares, recover_secret
from os.path import exists
import os
import sys
import random
from math import ceil
from decimal import Decimal

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
    
    key = [char.decode() for char in private_bytes.splitlines()[1:-1]] 
    key = "".join(key)
    keys = [str(ord(char)) for char in key]
    keys = "".join(keys)
    # print(keys)
    shares = make_random_shares(int(keys), k, n)
    # print(shares)
    secret = recover_secret(shares)
    print(len(str(secret)))
    secret = bytes(str(secret), "UTF-8")
    # print(bytes(str(secret), "UTF-8"))
    # shares = generate_shares(2,5,key)
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
    
    if exists(f"Shard[{k}].txt") == False:
        for file in os.listdir("/RSA-Coding-Challenge"):
            if file.startswith("Shard"):
                os.remove(file)
        private = open(f"Shard[{k}].txt", "x")
    else:
        private = open(f"Shard[{k}].txt", "w")

    for shard in shares:
        private.write(str(shard)+"\n")

    if exists("Public.txt") == False:
        public = open("Public.txt","x")
    else:
        public = open("Public.txt","w")

    public.write(str(public_bytes))

    public.close()
    private.close()

    return ciphertext, k, shares

def RSA_decrypt(ciphertext, k, shares):
    private = open(f"Shard[{k}].txt", 'r')
    shards = private.readlines()
    private.close()

    shards = shares
    print(shards)
    # for shard in shards:
    #     shards[shards.index(shard)] = shard.strip()
    # print(shards)
    secret = recover_secret(shards)
    print(secret)


# RSA_decrypt(RSA_encrypt("figkgkglig",2,5)[0], RSA_encrypt("figkgkglig",2,5)[1], RSA_encrypt("figkgkglig",2,5)[2])

FIELD_SIZE = 10**5


def reconstruct_secret(shares):
	"""
	Combines individual shares (points on graph)
	using Lagranges interpolation.

	`shares` is a list of points (x, y) belonging to a
	polynomial with a constant of our key.
	"""
	sums = 0
	prod_arr = []

	for j, share_j in enumerate(shares):
		xj, yj = share_j
		prod = Decimal(1)

		for i, share_i in enumerate(shares):
			xi, _ = share_i
			if i != j:
				prod *= Decimal(Decimal(xi)/(xi-xj))

		prod *= yj
		sums += Decimal(prod)

	return int(round(Decimal(sums), 0))


def polynom(x, coefficients):
	"""
	This generates a single point on the graph of given polynomial
	in `x`. The polynomial is given by the list of `coefficients`.
	"""
	point = 0
	# Loop through reversed list, so that indices from enumerate match the
	# actual coefficient indices
	for coefficient_index, coefficient_value in enumerate(coefficients[::-1]):
		point += x ** coefficient_index * coefficient_value
	return point


def coeff(t, secret):
	"""
	Randomly generate a list of coefficients for a polynomial with
	degree of `t` - 1, whose constant is `secret`.

	For example with a 3rd degree coefficient like this:
		3x^3 + 4x^2 + 18x + 554

		554 is the secret, and the polynomial degree + 1 is
		how many points are needed to recover this secret.
		(in this case it's 4 points).
	"""
	coeff = [random.randrange(0, FIELD_SIZE) for _ in range(t - 1)]
	coeff.append(secret)
	return coeff


def generate_shares(n, m, secret):
	"""
	Split given `secret` into `n` shares with minimum threshold
	of `m` shares to recover this `secret`, using SSS algorithm.
	"""
	coefficients = coeff(m, secret)
	shares = []

	for i in range(1, n+1):
		x = random.randrange(1, FIELD_SIZE)
		shares.append((x, polynom(x, coefficients)))

	return shares

RSA_encrypt("figkgkglig",2,5)

#def test():