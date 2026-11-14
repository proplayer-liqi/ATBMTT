"""
kdf.py — HMAC-SHA256 (RFC 2104) và dẫn xuất khoá HKDF (RFC 5869), tự cài đặt.

Vì sao cần dẫn xuất khoá? Khoá chung K_AB của Diffie–Hellman là một số lớn
(2048 bít) và không phân bố đều trên mọi chuỗi bít. Ta "nén" nó qua HKDF để
được các khoá đối xứng 256 bít đồng đều, tách riêng khoá mã hoá và khoá MAC.
"""
from .sha256 import SHA256, sha256

_BLOCK = 64


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))."""
    if len(key) > _BLOCK:
        key = sha256(key)
    key = key.ljust(_BLOCK, b"\x00")
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    inner = SHA256(ipad).update(msg).digest()
    return SHA256(opad).update(inner).digest()


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """So sánh hai chuỗi byte trong thời gian không phụ thuộc vị trí khác nhau."""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def hkdf(ikm: bytes, length: int, salt: bytes = b"", info: bytes = b"") -> bytes:
    """HKDF-SHA256: Extract rồi Expand."""
    if not salt:
        salt = b"\x00" * 32
    prk = hmac_sha256(salt, ikm)                     # Extract
    okm, t, counter = b"", b"", 1
    while len(okm) < length:                         # Expand
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]


def derive_session_keys(shared_secret: bytes, context: bytes = b"DH-demo"):
    """Từ K_AB sinh (khoá mã hoá 32 byte, khoá MAC 32 byte)."""
    material = hkdf(shared_secret, 64, salt=b"ATBMTT-DH-salt", info=context)
    return material[:32], material[32:]
