"""RSA key generation and encryption/decryption implementation"""


from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes, random
from Crypto.Util.Padding import pad, unpad


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


def derive_key(s: int) -> bytes:
    """Create the key using integer from RSA key generation process"""
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8 or 1, "big")
    return SHA256.new(s_bytes).digest()[:16]


def aes_encrypt(key: bytes, iv: bytes, msg: str) -> bytes:
    """Encrypts using AES-CBC"""
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg.encode(), AES.block_size))


def aes_decrypt(key: bytes, iv: bytes, cipher_text: bytes) -> str:
    """Decrypts using AES-CBC"""
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher_text), AES.block_size).decode()


def mitm_malleability(bits: int) -> None:
    """Mallory replaces Bob's encrypted s with an encryption of a value she chose"""
    public, private = key_generation(bits)
    _, n = public

    r = random.randint(2, n - 1)
    c_prime = encrypt(public, r)

    s_alice = decrypt(private, c_prime)
    k_alice = derive_key(s_alice)

    iv = get_random_bytes(16)
    c0 = aes_encrypt(k_alice, iv, "Hi Bob!")

    k_mallory = derive_key(r)
    print(f"Alice's s equals Mallory's r: {s_alice == r}")
    print(f"Mallory decrypts c0: {aes_decrypt(k_mallory, iv, c0)}")


def transaction_tampering(bits: int) -> None:
    """Another example of how we can exploit RSA's malleability"""
    public, private = key_generation(bits)
    e, n = public

    amount = 500
    c = encrypt(public, amount)

    r = 2
    c_prime = c * pow(r, e, n)

    received = decrypt(private, c_prime)
    print(f"Sent: ${amount}, Received: ${received}")


def signature_forgery(bits: int) -> None:
    """Combine two valid signatures into a third valid signature"""
    public, private = key_generation(bits)
    e, n = public
    d, _ = private

    m1 = int("Hi".encode().hex(), 16)
    m2 = int("Bob".encode().hex(), 16)
    sig1 = pow(m1, d, n)
    sig2 = pow(m2, d, n)

    m3 = m1 * m2
    sig3 = sig1 * sig2

    print(f"Forged signature verifies: {pow(sig3, e, n) == m3}")


if __name__ == "__main__":
    pu, pr = key_generation(2048)
    MSG = "Hi Bob!"
    temp = encrypt(pu, int(MSG.encode().hex(), 16))
    recovered = decrypt(pr, temp)
    PLAIN_TEXT = recovered.to_bytes((recovered.bit_length() + 7) // 8 or 1, "big")
    print(f"{MSG} -> {PLAIN_TEXT}")
    mitm_malleability(2048)
    transaction_tampering(2048)
    signature_forgery(2048)
