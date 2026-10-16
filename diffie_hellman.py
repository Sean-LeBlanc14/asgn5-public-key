"""Diffie-Hellman Key Exchange Implementation"""

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes, random
from Crypto.Util.Padding import pad, unpad


Q = int(
    """
    B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
    9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
    13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
    98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
    A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
    DF1FB2BC 2E4A4371
    """.replace(" ", "").replace("\n", ""),
    16
)

ALPHA = int(
    """
    A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
    D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
    160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
    909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
    D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
    855E6EEB 22B3B2E5
    """.replace(" ", "").replace("\n", ""),
    16
)


def derive_key(s: int) -> bytes:
    """Create the key using integer from DH key generation process"""
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8 or 1, "big")
    return SHA256.new(s_bytes).digest()[:16]


def encrypt(key: bytes, iv: bytes, msg: str) -> bytes:
    """Encrypts using AES-CBC"""
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg.encode(), AES.block_size))


def decrypt(key: bytes, iv: bytes, cipher_text: bytes) -> str:
    """Decrypts using AES-CBC"""
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher_text), AES.block_size).decode()


def key_exchange(q: int, alpha: int) -> None:
    """Run the key generation process"""
    x_a = random.randint(1, q - 2)
    x_b = random.randint(1, q - 2)

    y_a = pow(alpha, x_a, q)
    y_b = pow(alpha, x_b, q)

    s_a = pow(y_b, x_a, q)
    s_b = pow(y_a, x_b, q)

    k_a = derive_key(s_a)
    k_b = derive_key(s_b)

    if k_a == k_b:
        print(f"Key made from a: {k_a}")
        print(f"Key made from b: {k_b}")
        print("KEYS MATCH")
    else:
        print("KEYS DO NOT MATCH")

    iv = get_random_bytes(16)

    c0 = encrypt(k_a, iv, "Hi Bob!")
    c1 = encrypt(k_b, iv, "Hi Alice!")

    print(f"Bob's received message: {decrypt(k_b, iv, c0)}")
    print(f"Alice's received message: {decrypt(k_a, iv, c1)}")


def mitm_key_fixing(q: int, alpha=None) -> None:
    """Key exchange with Mallory replacing values with q or tampering with alpha"""
    x_a = random.randint(1, q - 2)
    x_b = random.randint(1, q - 2)

    if alpha:
        y_a = pow(alpha, x_a, q)
        y_b = pow(alpha, x_b, q)
        s_a = pow(y_b, x_a, q)
        s_b = pow(y_a, x_b, q)
    else:
        s_a = pow(q, x_a, q)
        s_b = pow(q, x_b, q)

    k_a = derive_key(s_a)
    k_b = derive_key(s_b)

    iv = get_random_bytes(16)

    c0 = encrypt(k_a, iv, "Hi Bob!")
    c1 = encrypt(k_b, iv, "Hi Alice!")

    s_mallory = 0
    k_mallory = derive_key(s_mallory)

    print(f"Alice's s: {s_a}")
    print(f"Bob's s: {s_b}")
    print(f"Mallory's s: {s_mallory}")
    print(f"Mallory decrypting c0: {decrypt(k_mallory, iv, c0)}")
    print(f"Mallory decrypting c1: {decrypt(k_mallory, iv, c1)}")


if __name__ == "__main__":
    key_exchange(37, 5)
    key_exchange(Q, ALPHA)
    mitm_key_fixing(Q)
    mitm_key_fixing(Q, Q)
