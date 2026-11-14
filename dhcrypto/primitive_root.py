"""
primitive_root.py — Kiểm tra và tìm căn nguyên thuỷ (phần tử sinh) α modulo q.

Định nghĩa: α là căn nguyên thuỷ modulo q (q nguyên tố) nếu các giá trị
α^1, α^2, ..., α^(q-1) mod q đi qua TẤT CẢ các số 1, 2, ..., q - 1.
(Slide của thầy ghi "căn nguyên tố", thuật ngữ đúng là căn nguyên thuỷ.)

Tiêu chuẩn kiểm tra: α là căn nguyên thuỷ  <=>  với MỌI ước nguyên tố f của
q - 1 ta có  α^((q-1)/f) mod q != 1.
"""
from .modmath import mod_pow
from .primes import is_probable_prime


def prime_factors(n: int):
    """Phân tích n ra các thừa số nguyên tố (chia thử) — chỉ dùng cho số nhỏ.

    Với số lớn (hàng trăm bít) việc này không khả thi; khi đó phải dùng số
    nguyên tố an toàn q = 2r + 1 để biết sẵn q - 1 = 2 * r.
    """
    factors = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def check_primitive_root(alpha: int, q: int, factors=None):
    """Kiểm tra α có phải căn nguyên thuỷ modulo q không.

    Trả về (kết_luận, danh_sách_bước) với mỗi bước là
      (f, (q-1)/f, α^((q-1)/f) mod q).
    `factors`: các ước nguyên tố của q - 1 (nếu đã biết sẵn, ví dụ [2, r]).
    """
    if not (1 < alpha < q):
        return False, []
    if factors is None:
        factors = prime_factors(q - 1)
    steps = []
    ok = True
    for f in factors:
        e = (q - 1) // f
        v = mod_pow(alpha, e, q)
        steps.append((f, e, v))
        if v == 1:
            ok = False
    return ok, steps


def is_primitive_root(alpha: int, q: int, factors=None) -> bool:
    return check_primitive_root(alpha, q, factors)[0]


def find_primitive_root(q: int, factors=None, start: int = 2) -> int:
    """Tìm căn nguyên thuỷ nhỏ nhất >= start."""
    if factors is None:
        factors = prime_factors(q - 1)
    for alpha in range(start, q):
        if is_primitive_root(alpha, q, factors):
            return alpha
    raise ValueError("không tìm được căn nguyên thuỷ")


def safe_prime_factors(q: int):
    """Với số nguyên tố an toàn q = 2r + 1, các ước nguyên tố của q - 1 là [2, r]."""
    r = (q - 1) // 2
    if not (is_probable_prime(q) and is_probable_prime(r)):
        raise ValueError("q không phải số nguyên tố an toàn")
    return [2, r]


def power_table(alpha: int, q: int):
    """Bảng α^k mod q với k = 1..q-1 (chỉ dùng cho q nhỏ, để minh hoạ)."""
    table = []
    v = 1
    for k in range(1, q):
        v = (v * alpha) % q
        table.append((k, v))
    return table
