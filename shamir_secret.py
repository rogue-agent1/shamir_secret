#!/usr/bin/env python3
"""Shamir's Secret Sharing — split secrets into k-of-n shares."""
import random, sys

# Use a prime field
PRIME = 2**127 - 1

def _mod_inv(a, p=PRIME):
    return pow(a, p - 2, p)

def split_secret(secret, k, n):
    if isinstance(secret, str): secret = int.from_bytes(secret.encode(), 'big')
    coeffs = [secret] + [random.randrange(1, PRIME) for _ in range(k - 1)]
    shares = []
    for i in range(1, n + 1):
        y = sum(c * pow(i, j, PRIME) for j, c in enumerate(coeffs)) % PRIME
        shares.append((i, y))
    return shares

def recover_secret(shares, as_string=False):
    k = len(shares); secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = den = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num = (num * (-xj)) % PRIME
                den = (den * (xi - xj)) % PRIME
        secret = (secret + yi * num * _mod_inv(den)) % PRIME
    if as_string:
        length = (secret.bit_length() + 7) // 8
        return secret.to_bytes(length, 'big').decode()
    return secret

if __name__ == "__main__":
    secret = "nuclear launch codes"
    print(f"Secret: {secret}")
    shares = split_secret(secret, k=3, n=5)
    print(f"5 shares (need 3):")
    for i, s in shares: print(f"  Share {i}: {s}")
    # Recover with any 3
    recovered = recover_secret(shares[:3], as_string=True)
    print(f"Recovered (shares 1-3): {recovered}")
    recovered2 = recover_secret([shares[1], shares[3], shares[4]], as_string=True)
    print(f"Recovered (shares 2,4,5): {recovered2}")
