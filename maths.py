# Contains implementation of Miller Rabin prime testing, Fast Modular Exponentiation and Extended Euclid's Algorithm.


def miller_rabin(n):
    """
    Deterministic Miller Rabin for upto 64 - bit prime numbers.
    Let n - 1 = 2^s * d
    For base a (1 < a < n - 1), we check either a^d ≡ 1 (mod n)
    OR, a^(2^r * d) ≡ -1 (mod n) for some (0 <= r <= s - 1).
    We need to check all bases <= 2 * (ln(n)^2) only to make it deterministic.
    """
    if n < 2:
        return False
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    s = 0
    d = n - 1
    while d % 2 == 0:
        d /= 2
        s += 1
    for a in primes:
        if a == n:
            return True
        if check_composite(n, a, d, s):
            return False
    return True


def check_composite(n, a, d, s):
    x = mod_exponent(a, d, n)
    if x == 1 or x == n - 1:
        return False
    for r in range(1, s):
        x = (x * x) % n
        if x == n - 1:
            return False
    return True


def mod_exponent(a, b, p):
    """
    Computes (a ^ b) % p in O(LogN).
    """
    x = a
    y = b
    result = 1
    while y > 0:
        if y % 2 == 1:
            result = (result * x) % p
        y //= 2
        x = (x * x) % p
    return result


def extended_euclid(a, b):
    """
    Returns gcd of a and b.
    Also returns x and y such that {ax + by = gcd(a, b)}
    If gcd == 1, x = modular multiplicative inverse of (a)
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_euclid(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

