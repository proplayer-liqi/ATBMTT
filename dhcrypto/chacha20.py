"""
chacha20.py — Mã dòng ChaCha20 (RFC 8439), nhóm tự cài đặt.

Dùng để mã hoá dữ liệu (tệp văn bản, ảnh) bằng khoá đối xứng sinh ra từ khoá
chung Diffie–Hellman. Mã dòng: bản mã = bản rõ XOR dòng khoá, nên giải mã
chính là mã hoá lại một lần nữa với cùng khoá và nonce.
"""
import struct

_MASK = 0xFFFFFFFF
_CONST = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)   # "expand 32-byte k"


def _rotl(x, n):
    return ((x << n) & _MASK) | (x >> (32 - n))


def _quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & _MASK; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _MASK; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK; s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Sinh một khối dòng khoá 64 byte."""
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("khoá phải 32 byte, nonce phải 12 byte")
    state = list(_CONST) + list(struct.unpack("<8I", key)) + [counter & _MASK] + list(struct.unpack("<3I", nonce))
    w = list(state)
    for _ in range(10):                 # 20 vòng = 10 lần (vòng cột + vòng chéo)
        _quarter_round(w, 0, 4, 8, 12)
        _quarter_round(w, 1, 5, 9, 13)
        _quarter_round(w, 2, 6, 10, 14)
        _quarter_round(w, 3, 7, 11, 15)
        _quarter_round(w, 0, 5, 10, 15)
        _quarter_round(w, 1, 6, 11, 12)
        _quarter_round(w, 2, 7, 8, 13)
        _quarter_round(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(x + y) & _MASK for x, y in zip(w, state)])


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    """Mã hoá / giải mã: data XOR dòng khoá."""
    n_blocks = (len(data) + 63) // 64
    stream = b"".join(chacha20_block(key, counter + i, nonce) for i in range(n_blocks))
    stream = stream[:len(data)]
    # XOR toàn bộ một lần bằng phép toán số nguyên lớn (nhanh hơn XOR từng byte)
    x = int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")
    return x.to_bytes(len(data), "big")
