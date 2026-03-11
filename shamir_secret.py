#!/usr/bin/env python3
"""shamir_secret - Shamir's Secret Sharing scheme over GF(p).

Usage: python shamir_secret.py [--threshold T] [--shares N] [--secret S]
"""
import sys, random, os

# Large prime for GF(p)
PRIME = 2**127 - 1  # Mersenne prime

def mod_inv(a, p=PRIME):
    return pow(a, p-2, p)

def make_polynomial(secret, threshold):
    """Create random polynomial with secret as constant term."""
    coeffs = [secret]
    for _ in range(threshold - 1):
        coeffs.append(random.randrange(1, PRIME))
    return coeffs

def eval_poly(coeffs, x, p=PRIME):
    result = 0
    for i, c in enumerate(coeffs):
        result = (result + c * pow(x, i, p)) % p
    return result

def split(secret, threshold, num_shares):
    """Split secret into shares. Any `threshold` shares can reconstruct."""
    assert 2 <= threshold <= num_shares
    if isinstance(secret, bytes):
        secret = int.from_bytes(secret, 'big')
    coeffs = make_polynomial(secret, threshold)
    shares = []
    for i in range(1, num_shares + 1):
        y = eval_poly(coeffs, i)
        shares.append((i, y))
    return shares

def reconstruct(shares, p=PRIME):
    """Reconstruct secret using Lagrange interpolation at x=0."""
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = den = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num = num * (-xj) % p
                den = den * (xi - xj) % p
        lagrange = yi * num % p * mod_inv(den, p) % p
        secret = (secret + lagrange) % p
    return secret

def verify_shares(shares, threshold):
    """Verify that different subsets of threshold shares give same secret."""
    from itertools import combinations
    secrets = set()
    for combo in combinations(shares, threshold):
        secrets.add(reconstruct(list(combo)))
    return len(secrets) == 1, secrets.pop() if len(secrets) == 1 else None

def main():
    threshold = 3; num_shares = 5; secret = None
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--threshold" and i+1 < len(args): threshold = int(args[i+1])
        if a == "--shares" and i+1 < len(args): num_shares = int(args[i+1])
        if a == "--secret" and i+1 < len(args): secret = int(args[i+1])

    if secret is None:
        secret = int.from_bytes(os.urandom(16), 'big')

    print(f"=== Shamir's Secret Sharing ===\n")
    print(f"Secret:    {secret}")
    print(f"Threshold: {threshold} of {num_shares}")
    print(f"Prime:     2^127 - 1\n")

    shares = split(secret, threshold, num_shares)
    for i, (x, y) in enumerate(shares):
        print(f"  Share {i+1}: ({x}, {y})")

    # Reconstruct with exactly threshold shares
    print(f"\nReconstruct with {threshold} shares:")
    subset = shares[:threshold]
    recovered = reconstruct(subset)
    print(f"  Recovered: {recovered}")
    print(f"  Match:     {'✓' if recovered == secret else '✗'}")

    # Verify with fewer shares (should fail)
    print(f"\nWith {threshold-1} shares (insufficient):")
    subset2 = shares[:threshold-1]
    recovered2 = reconstruct(subset2)
    print(f"  Recovered: {recovered2}")
    print(f"  Match:     {'✓' if recovered2 == secret else '✗ (expected — insufficient shares)'}")

    # Verify all subsets
    print(f"\nVerify all {threshold}-subsets give same secret:")
    ok, _ = verify_shares(shares, threshold)
    print(f"  All consistent: {'✓' if ok else '✗'}")

    # Practical: share a password
    print(f"\n--- Practical: sharing a password ---")
    password = b"MyS3cr3tP@ssw0rd!"
    pwd_int = int.from_bytes(password, 'big')
    pwd_shares = split(pwd_int, 3, 5)
    print(f"  Password: {password.decode()}")
    recovered_int = reconstruct(pwd_shares[:3])
    recovered_pwd = recovered_int.to_bytes((recovered_int.bit_length()+7)//8, 'big')
    print(f"  Recovered: {recovered_pwd.decode()}")
    print(f"  Match: {'✓' if recovered_pwd == password else '✗'}")

if __name__ == "__main__":
    main()
