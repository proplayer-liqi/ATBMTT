"""
modmath.py — Các phép toán số học modulo (nhóm tự cài đặt).

Gồm:
  * mod_pow      : lũy thừa modulo bằng thuật toán "bình phương và nhân"
  * mod_pow_trace: như trên nhưng ghi lại từng bước để in ra khi thuyết trình
  * egcd         : thuật toán Euclid mở rộng
  * mod_inverse  : phần tử nghịch đảo theo modulo

Không dùng hàm pow(a, b, m) có sẵn của Python cho phần lõi; hàm pow chỉ được
dùng trong bộ kiểm thử để ĐỐI CHIẾU kết quả.
"""


def mod_pow(base: int, exp: int, mod: int) -> int:
    """Tính base^exp mod mod bằng thuật toán bình phương và nhân (từ phải sang trái).

    Ý tưởng: viết exp ở dạng nhị phân, exp = sum(b_i * 2^i).
    Khi đó base^exp = tích các base^(2^i) ứng với những bít b_i = 1.
    Ta lần lượt bình phương base để có base^(2^i), và nhân vào kết quả
    khi bít tương ứng bằng 1. Số phép nhân ~ 2 * log2(exp).
    """
    if mod <= 0:
        raise ValueError("modulo phải là số dương")
    if exp < 0:
        raise ValueError("số mũ phải không âm")
    if mod == 1:
        return 0

    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:                       # bít hiện tại bằng 1 -> nhân vào kết quả
            result = (result * base) % mod
        base = (base * base) % mod        # bình phương để có lũy thừa 2^(i+1)
        exp >>= 1                         # chuyển sang bít tiếp theo
    return result


def mod_pow_trace(base: int, exp: int, mod: int):
    """Giống mod_pow nhưng trả về thêm danh sách các bước trung gian.

    Mỗi bước là một dict:
      i        : vị trí bít (tính từ phải, bắt đầu từ 0)
      bit      : giá trị bít thứ i của số mũ
      power    : base^(2^i) mod mod (giá trị đang xét ở bước này)
      result   : kết quả tích luỹ SAU bước này
      used     : True nếu bước này có nhân power vào kết quả
    """
    if mod <= 0 or exp < 0:
        raise ValueError("tham số không hợp lệ")
    steps = []
    result = 1 % mod
    power = base % mod
    i = 0
    e = exp
    while e > 0:
        bit = e & 1
        if bit:
            result = (result * power) % mod
        steps.append({"i": i, "bit": bit, "power": power, "result": result, "used": bool(bit)})
        power = (power * power) % mod
        e >>= 1
        i += 1
    return result, steps


def egcd(a: int, b: int):
    """Euclid mở rộng: trả về (g, x, y) với a*x + b*y = g = gcd(a, b)."""
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y


def gcd(a: int, b: int) -> int:
    """Ước chung lớn nhất."""
    return egcd(a, b)[0]


def mod_inverse(a: int, m: int) -> int:
    """Tìm a^(-1) mod m. Báo lỗi nếu gcd(a, m) != 1."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} không có nghịch đảo modulo {m}")
    return x % m


def int_to_bytes(n: int, length: int = None) -> bytes:
    """Đổi số nguyên không âm sang chuỗi byte big-endian."""
    if length is None:
        length = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    """Đổi chuỗi byte big-endian sang số nguyên."""
    return int.from_bytes(b, "big")
