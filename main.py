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

def RSA():
    plain_text = input()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    public_key = private_key.public_key()
    ciphertext = public_key.encrypt(
    bytes(plain_text,"UTF-8"), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None)
    )
    
    print(ciphertext)   

def SSS(secret):
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
#     _PRIME = 2 ** 127 - 1
#     _RINT = functools.partial(random.SystemRandom().randint, 0)
#     def _eval_at(poly, x, prime):
#         accum = 0
#         for coeff in reversed(poly):
#             accum *= x
#             accum += coeff
#             accum %= prime
#         return accum

#     def make_random_shares(secret, minimum, shares, prime=_PRIME):
#         if minimum > shares:
#             raise ValueError("Pool secret would be irrecoverable.")
#         poly = [secret] + [_RINT(prime - 1) for i in range(minimum - 1)]
#         points = [(i, _eval_at(poly, i, prime))
#                 for i in range(1, shares + 1)]
#         return points

#     def _extended_gcd(a, b):
#         x = 0
#         last_x = 1
#         y = 1
#         last_y = 0
#         while b != 0:
#             quot = a // b
#             a, b = b, a % b
#             x, last_x = last_x - quot * x, x
#             y, last_y = last_y - quot * y, y
#         return last_x, last_y

#     def _divmod(num, den, p):
#         inv, _ = _extended_gcd(den, p)
#         return num * inv

#     def _lagrange_interpolate(x, x_s, y_s, p):
#         k = len(x_s)
#         assert k == len(set(x_s)), "points must be distinct"
#         def PI(vals):  # upper-case PI -- product of inputs
#             accum = 1
#             for v in vals:
#                 accum *= v
#             return accum
#         nums = []  # avoid inexact division
#         dens = []
#         for i in range(k):
#             others = list(x_s)
#             cur = others.pop(i)
#             nums.append(PI(x - o for o in others))
#             dens.append(PI(cur - o for o in others))
#         den = PI(dens)
#         num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p)
#                 for i in range(k)])
#         return (_divmod(num, den, p) + p) % p

#     def recover_secret(shares, prime=_PRIME):
#         if len(shares) < 3:
#             raise ValueError("need at least three shares")
#         x_s, y_s = zip(*shares)
#         return _lagrange_interpolate(0, x_s, y_s, prime)    

#     shares = make_random_shares(secret, minimum=2, shares=5)
#     print('Secret:                                                     ',
#           secret)
#     print('Shares:')
#     if shares:
#         for share in shares:
#             print('  ', share)

#     print('Secret recovered from minimum subset of shares:             ',
#           recover_secret(shares[:3]))
#     print('Secret recovered from a different minimum subset of shares: ',
#           recover_secret(shares[-3:]))

RSA()

#def test():