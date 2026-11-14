"""
attacks.py — Các tấn công tính toán lên bài toán logarit rời rạc (DLP).

Bài toán: biết q, α, y = α^x mod q. Tìm x.
  * brute_force_dlog : thử lần lượt x = 1, 2, 3, ...      — O(n) phép nhân
  * bsgs_dlog        : Baby-step Giant-step (Shanks)       — O(√n) thời gian và bộ nhớ
(n là cấp của α.)

Dùng để minh hoạ: với q nhỏ thì phá ngay, nhưng thời gian tăng theo hàm mũ của
số bít — với q 2048 bít thì bất khả thi.
"""
import math
import time

from .modmath import mod_inverse, mod_pow
from .primes import gen_safe_prime
from .primitive_root import find_primitive_root


def brute_force_dlog(alpha: int, y: int, q: int, max_steps: int = None):
    """Vét cạn. Trả về (x, số_bước) hoặc (None, số_bước) nếu vượt max_steps."""
    v = 1
    limit = q - 1 if max_steps is None else min(q - 1, max_steps)
    for x in range(1, limit + 1):
        v = (v * alpha) % q
        if v == y:
            return x, x
    return None, limit


def bsgs_dlog(alpha: int, y: int, q: int, order: int = None):
    """Baby-step Giant-step.

    Đặt m = ceil(√n). Viết x = i·m + j (0 <= i, j < m).
      Baby steps : lưu bảng α^j  -> j   với j = 0..m-1
      Giant steps: tính y·(α^(-m))^i, nếu gặp trong bảng thì x = i·m + j.
    Trả về (x, số_phép_toán) hoặc (None, số_phép_toán).
    """
    n = order if order else q - 1
    m = math.isqrt(n - 1) + 1
    table = {}
    v = 1
    for j in range(m):                       # baby steps
        table.setdefault(v, j)
        v = (v * alpha) % q
    factor = mod_inverse(mod_pow(alpha, m, q), q)    # α^(-m)
    gamma = y % q
    for i in range(m):                       # giant steps
        if gamma in table:
            return i * m + table[gamma], m + i + 1
        gamma = (gamma * factor) % q
    return None, 2 * m


def make_dlp_instance(bits: int, secret_x: int = None):
    """Tạo bài toán DLP ngẫu nhiên với q là số nguyên tố an toàn `bits` bít."""
    import secrets
    q = gen_safe_prime(bits)
    r = (q - 1) // 2
    alpha = find_primitive_root(q, [2, r])
    x = secret_x if secret_x is not None else 2 + secrets.randbelow(q - 4)
    return q, alpha, x, mod_pow(alpha, x, q)


def time_attack(func, *args, **kwargs):
    t0 = time.perf_counter()
    result = func(*args, **kwargs)
    return result, time.perf_counter() - t0
