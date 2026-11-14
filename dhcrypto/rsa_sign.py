"""
rsa_sign.py — Chữ ký số RSA tối giản, dùng để XÁC THỰC khoá công khai DH.

Mục đích: chống tấn công người đứng giữa. Mỗi bên có cặp khoá RSA dài hạn;
khoá công khai RSA của đối phương được biết trước (giống chứng chỉ trong TLS
hoặc "fingerprint" trong SSH). Khi gửi y_A, A ký lên y_A; B kiểm tra chữ ký.
Mallory không có khoá riêng RSA của A nên không ký giả được giá trị của mình.

Ghi chú: đây là bản tối giản phục vụ minh hoạ (đệm kiểu PKCS#1 v1.5 rút gọn,
không có DigestInfo). Hệ thống thật dùng RSA-PSS hoặc ECDSA/Ed25519.
"""
from dataclasses import dataclass

from .modmath import gcd, mod_inverse, mod_pow
from .primes import gen_prime
from .sha256 import sha256, sha256_hex


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int

    def fingerprint(self) -> str:
        """Dấu vân tay ngắn để so sánh bằng mắt."""
        h = sha256_hex(self.n.to_bytes((self.n.bit_length() + 7) // 8, "big") + self.e.to_bytes(4, "big"))
        return ":".join(h[i:i + 4] for i in range(0, 16, 4))


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    d: int
    public: RSAPublicKey


def generate_rsa_keypair(bits: int = 1024, e: int = 65537) -> RSAPrivateKey:
    """Sinh cặp khoá RSA: n = p·q, d = e^(-1) mod φ(n)."""
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits - bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            n = p * q
            d = mod_inverse(e, phi)
            return RSAPrivateKey(n, d, RSAPublicKey(n, e))


def _encode(message: bytes, n: int) -> int:
    """Băm thông điệp rồi đệm: 00 01 FF..FF 00 || SHA-256(message)."""
    k = (n.bit_length() + 7) // 8
    digest = sha256(message)
    padding = b"\xff" * (k - len(digest) - 3)
    return int.from_bytes(b"\x00\x01" + padding + b"\x00" + digest, "big")


def sign(priv: RSAPrivateKey, message: bytes) -> int:
    """s = EM^d mod n."""
    return mod_pow(_encode(message, priv.n), priv.d, priv.n)


def verify(pub: RSAPublicKey, message: bytes, signature: int) -> bool:
    """Đúng khi s^e mod n bằng EM tính lại từ thông điệp."""
    if not (0 <= signature < pub.n):
        return False
    return mod_pow(signature, pub.e, pub.n) == _encode(message, pub.n)
