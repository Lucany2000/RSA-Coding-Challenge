# from __future__ import division
# from __future__ import print_function
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
# import shamir
import random
# from math import ceil
# from decimal import Decimal
# import functools
from Shamir import make_random_shares, recover_secret


# plain_text = input()

def RSA_encrypt(plain_text):
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    shares = make_random_shares(private_key, 2, 5)
    print(shares)
    secret = recover_secret(shares)
    print(secret)

    public_key = private_key.public_key()
    ciphertext = public_key.encrypt(
    bytes(plain_text,"UTF-8"), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None)
    )
    
    # print(ciphertext)   

# def RSA_decrypt():


# def SSS(secret):
#     FIELD_SIZE = 10**5
#     def reconstruct_secret(shares):
#         """
#         Combines individual shares (points on graph)
#         using Lagranges interpolation.
    
#         `shares` is a list of points (x, y) belonging to a
#         polynomial with a constant of our key.
#         """
#         sums = 0
#         prod_arr = []
    
#         for j, share_j in enumerate(shares):
#             xj, yj = share_j
#             prod = Decimal(1)
    
#             for i, share_i in enumerate(shares):
#                 xi, _ = share_i
#                 if i != j:
#                     prod *= Decimal(Decimal(xi)/(xi-xj))
    
#             prod *= yj
#             sums += Decimal(prod)
    
#         return int(round(Decimal(sums), 0))
    
    
#     def polynom(x, coefficients):
#         """
#         This generates a single point on the graph of given polynomial
#         in `x`. The polynomial is given by the list of `coefficients`.
#         """
#         point = 0
#         # Loop through reversed list, so that indices from enumerate match the
#         # actual coefficient indices
#         for coefficient_index, coefficient_value in enumerate(coefficients[::-1]):
#             point += x ** coefficient_index * coefficient_value
#         return point
    
    
#     def coeff(t, secret):
#         """
#         Randomly generate a list of coefficients for a polynomial with
#         degree of `t` - 1, whose constant is `secret`.
    
#         For example with a 3rd degree coefficient like this:
#             3x^3 + 4x^2 + 18x + 554
    
#             554 is the secret, and the polynomial degree + 1 is
#             how many points are needed to recover this secret.
#             (in this case it's 4 points).
#         """
#         coeff = [random.randrange(0, FIELD_SIZE) for _ in range(t - 1)]
#         coeff.append(secret)
#         return coeff
    
    
#     def generate_shares(n, m, secret):
#         """
#         Split given `secret` into `n` shares with minimum threshold
#         of `m` shares to recover this `secret`, using SSS algorithm.
#         """
#         coefficients = coeff(m, secret)
#         shares = []
    
#         for i in range(1, n+1):
#             x = random.randrange(1, FIELD_SIZE)
#             shares.append((x, polynom(x, coefficients)))
    
#         return shares

RSA_encrypt("figkgkglig")

#def test():