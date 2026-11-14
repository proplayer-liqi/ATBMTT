"""
dh.py — Giao thức trao đổi khoá Diffie–Hellman (nhóm tự cài đặt).

Ký hiệu theo slide của thầy:
  q      : số nguyên tố lớn (công khai)
  α      : căn nguyên thuỷ / phần tử sinh (công khai)
  x_A    : khoá riêng (bí mật) của A,   1 < x_A < q - 1
  y_A    : khoá công khai của A,  y_A = α^x_A mod q
  K_AB   : khoá chung = y_B^x_A mod q = y_A^x_B mod q = α^(x_A·x_B) mod q
"""
import secrets
from dataclasses import dataclass

from .groups import DHGroup
from .modmath import mod_pow


class InvalidPublicKey(ValueError):
    """Khoá công khai nhận được không hợp lệ (có thể là tấn công)."""


@dataclass
class KeyPair:
    group: DHGroup
    private: int     # x
    public: int      # y = α^x mod q


def generate_private_key(group: DHGroup) -> int:
    """Chọn khoá riêng x ngẫu nhiên an toàn trong [2, cấp_nhóm - 1]."""
    n = group.subgroup_order
    if n <= 3:
        raise ValueError("nhóm quá nhỏ")
    return 2 + secrets.randbelow(n - 2)      # 2 <= x <= n - 1


def compute_public_key(group: DHGroup, private: int) -> int:
    """y = α^x mod q."""
    if not (1 <= private < group.q - 1):
        raise ValueError("khoá riêng phải nằm trong khoảng 1 .. q - 2")
    return mod_pow(group.alpha, private, group.q)


def generate_keypair(group: DHGroup, private: int = None) -> KeyPair:
    """Sinh cặp khoá. Có thể truyền sẵn `private` (để chạy lại ví dụ tính tay)."""
    x = generate_private_key(group) if private is None else private
    return KeyPair(group, x, compute_public_key(group, x))


def validate_public_key(group: DHGroup, y: int) -> None:
    """Kiểm tra khoá công khai nhận từ đối phương trước khi dùng.

    1) 1 < y < q - 1 : loại các giá trị suy biến 0, 1, q - 1 (với y = 1 thì
       khoá chung luôn bằng 1 — kẻ tấn công đoán ngay được).
    2) Nếu biết cấp nhóm con r: y^r ≡ 1 (mod q), tức y thuộc đúng nhóm con
       cấp r — chống tấn công nhóm con nhỏ (small subgroup).
    """
    if not isinstance(y, int):
        raise InvalidPublicKey("khoá công khai phải là số nguyên")
    if not (1 < y < group.q - 1):
        raise InvalidPublicKey(f"khoá công khai phải thoả 1 < y < q - 1 (nhận được y = {y})")
    if group.order is not None and mod_pow(y, group.order, group.q) != 1:
        raise InvalidPublicKey("khoá công khai không thuộc nhóm con cấp r (nghi tấn công nhóm con nhỏ)")


def compute_shared_secret(group: DHGroup, my_private: int, their_public: int,
                          validate: bool = True) -> int:
    """K = (y_đối_phương)^(x_của_mình) mod q."""
    if validate:
        validate_public_key(group, their_public)
    return mod_pow(their_public, my_private, group.q)


def shared_secret_bytes(group: DHGroup, k: int) -> bytes:
    """Biểu diễn K thành chuỗi byte có độ dài cố định bằng độ dài của q."""
    return k.to_bytes((group.bits + 7) // 8, "big")
