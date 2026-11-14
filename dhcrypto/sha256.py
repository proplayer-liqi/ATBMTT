"""
sha256.py — Hàm băm SHA-256 (FIPS 180-4), nhóm tự cài đặt.

Dùng để: (1) dẫn xuất khoá đối xứng từ khoá chung K_AB, (2) HMAC kiểm tra toàn
vẹn tệp, (3) băm thông điệp trước khi ký RSA, (4) tạo "mã xác nhận" để so sánh.
Không gọi hashlib — hashlib chỉ dùng trong bộ kiểm thử để đối chiếu.
"""
import struct

# 64 hằng số vòng: 32 bít đầu phần thập phân căn bậc ba của 64 số nguyên tố đầu tiên
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Giá trị khởi tạo: 32 bít đầu phần thập phân căn bậc hai của 8 số nguyên tố đầu tiên
_H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

_MASK = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK


def _compress(h, block):
    """Hàm nén: xử lý một khối 512 bít (64 byte)."""
    w = list(struct.unpack(">16I", block))
    for t in range(16, 64):
        s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & _MASK)

    a, b, c, d, e, f, g, hh = h
    for t in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (hh + S1 + ch + _K[t] + w[t]) & _MASK
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _MASK
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK, c, b, a, (t1 + t2) & _MASK

    return [(x + y) & _MASK for x, y in zip(h, [a, b, c, d, e, f, g, hh])]


class SHA256:
    """Giao diện giống hashlib: update() nhiều lần rồi digest()."""
    block_size = 64
    digest_size = 32

    def __init__(self, data: bytes = b""):
        self._h = list(_H0)
        self._buf = b""
        self._len = 0
        if data:
            self.update(data)

    def update(self, data: bytes):
        self._len += len(data)
        data = self._buf + data
        full = len(data) // 64 * 64
        for i in range(0, full, 64):
            self._h = _compress(self._h, data[i:i + 64])
        self._buf = data[full:]
        return self

    def digest(self) -> bytes:
        # Đệm: thêm bít 1, các bít 0, rồi độ dài thông điệp (64 bít)
        bit_len = self._len * 8
        pad = b"\x80" + b"\x00" * ((55 - self._len) % 64) + struct.pack(">Q", bit_len)
        h = list(self._h)
        tail = self._buf + pad
        for i in range(0, len(tail), 64):
            h = _compress(h, tail[i:i + 64])
        return struct.pack(">8I", *h)

    def hexdigest(self) -> str:
        return self.digest().hex()


def sha256(data: bytes) -> bytes:
    return SHA256(data).digest()


def sha256_hex(data: bytes) -> str:
    return SHA256(data).hexdigest()
