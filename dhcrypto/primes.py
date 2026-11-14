"""
primes.py — Kiểm tra và sinh số nguyên tố (nhóm tự cài đặt).

Gồm:
  * is_probable_prime : kiểm tra Miller–Rabin (kèm thử chia các số nguyên tố nhỏ)
  * gen_prime         : sinh số nguyên tố ngẫu nhiên có đúng `bits` bít
  * gen_safe_prime    : sinh số nguyên tố an toàn q = 2r + 1 (r cũng nguyên tố)

Nguồn ngẫu nhiên dùng module `secrets` (thư viện chuẩn, sinh số ngẫu nhiên an
toàn cho mật mã) — đây không phải thư viện mật mã nên được phép dùng.
"""
import secrets

from .modmath import mod_pow


def _small_primes(limit: int):
    """Sàng Eratosthenes: danh sách các số nguyên tố < limit."""
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i in range(limit) if sieve[i]]


SMALL_PRIMES = _small_primes(2000)


def _random_range(low: int, high: int) -> int:
    """Số ngẫu nhiên an toàn trong đoạn [low, high]."""
    return low + secrets.randbelow(high - low + 1)


def miller_rabin(n: int, rounds: int = 40, bases=None) -> bool:
    """Kiểm tra Miller–Rabin.

    Viết n - 1 = 2^s * d với d lẻ. Với mỗi cơ sở a:
      x = a^d mod n; nếu x = 1 hoặc x = n - 1 thì a "đồng ý" n nguyên tố.
      Ngược lại bình phương x tối đa s - 1 lần; nếu gặp n - 1 thì cũng đồng ý.
      Nếu không -> a là "nhân chứng" chứng minh n là hợp số.
    Xác suất kết luận sai (hợp số bị coi là nguyên tố) <= 4^(-rounds).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    if bases is None:
        bases = [_random_range(2, n - 2) for _ in range(rounds)]

    for a in bases:
        a %= n
        if a in (0, 1, n - 1):
            continue
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False          # tìm được nhân chứng -> chắc chắn là hợp số
    return True                   # có thể là số nguyên tố (xác suất rất cao)


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Thử chia các số nguyên tố nhỏ trước (nhanh), sau đó Miller–Rabin."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    return miller_rabin(n, rounds)


def gen_prime(bits: int) -> int:
    """Sinh số nguyên tố ngẫu nhiên có đúng `bits` bít."""
    if bits < 2:
        raise ValueError("bits phải >= 2")
    while True:
        # Bật bít cao nhất (đảm bảo đủ độ dài) và bít thấp nhất (số lẻ)
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if bits == 2:
            n = 3
        if is_probable_prime(n):
            return n


def gen_safe_prime(bits: int, progress=None) -> int:
    """Sinh số nguyên tố an toàn q = 2r + 1 có đúng `bits` bít, với r nguyên tố.

    Số nguyên tố an toàn làm cho q - 1 = 2r chỉ có hai ước nguyên tố là 2 và r,
    chống lại tấn công Pohlig–Hellman. `progress` (tuỳ chọn) là hàm được gọi
    sau mỗi lần thử, để giao diện hiển thị tiến độ.
    """
    if bits < 3:
        raise ValueError("bits phải >= 3")
    attempts = 0
    while True:
        attempts += 1
        r = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        q = 2 * r + 1
        # Lọc nhanh: cả r và q đều không được chia hết cho số nguyên tố nhỏ
        ok = True
        for p in SMALL_PRIMES:
            if p >= r:
                break
            if r % p == 0 or q % p == 0:
                ok = False
                break
        if progress:
            progress(attempts)
        if not ok:
            continue
        if miller_rabin(r, 20) and miller_rabin(q, 20):
            if q.bit_length() == bits:
                return q
