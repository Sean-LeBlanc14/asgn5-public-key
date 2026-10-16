"""RSA key generation and encryption/decryption implementation"""


from Crypto.Util.number import getPrime


E = 65537


def key_generation(bits: int) -> tuple[tuple[int, int], tuple[int, int]]:
    """Return PU = {e, n} and PR = {d, n}"""
    while True:
        p = getPrime(bits)
        q = getPrime(bits)

        phi = (p - 1) * (q - 1)

        if p != q and phi % E != 0:
            break

    n = p * q
    d = pow(E, -1, phi)
    return (E, n), (d, n)


def encrypt(public_key: tuple[int, int], m: int) -> int:
    """Create a cipher text from a given public key for RSA"""
    e, n = public_key

    if m >= n:
        raise ValueError("Plaintext must be smaller than n")
    return pow(m, e, n)


def decrypt(private_key: tuple[int, int], c: int) -> int:
    """Get back the plaintext using a private key for RSA"""
    d, n = private_key
    return pow(c, d, n)


if __name__ == "__main__":
    pu, pr = key_generation(2048)
    MSG = "Hi Bob!"
    cipher_text = encrypt(pu, int(MSG.encode().hex(), 16))
    recovered = decrypt(pr, cipher_text)
    PLAIN_TEXT = recovered.to_bytes((recovered.bit_length() + 7) // 8 or 1, "big")
    print(f"{MSG} -> {PLAIN_TEXT}")
