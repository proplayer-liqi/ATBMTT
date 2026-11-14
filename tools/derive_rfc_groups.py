"""
Tái tạo các số nguyên tố MODP chuẩn (RFC 2409, RFC 3526) và FFDHE (RFC 7919)
từ CÔNG THỨC được công bố trong chính các RFC đó, rồi in ra dạng hex.

  MODP (RFC 2409/3526):  p = 2^n - 2^(n-64) - 1 + 2^64 * ( floor(2^(n-130) * pi) + k )
  FFDHE (RFC 7919):      p = 2^n - 2^(n-64) + 2^64 * ( floor(2^(n-130) * e) + k ) - 1

Script này chỉ dùng để sinh hằng số trong dhcrypto/groups.py (cần thư viện mpmath).
Chương trình chính không phụ thuộc mpmath.
"""
import mpmath

mpmath.mp.prec = 5000  # đủ chính xác cho 2^4000 * pi


def modp(n, k):
    return 2**n - 2**(n - 64) - 1 + 2**64 * (int(mpmath.floor(mpmath.mpf(2)**(n - 130) * mpmath.pi)) + k)


def ffdhe(n, k):
    return 2**n - 2**(n - 64) + 2**64 * (int(mpmath.floor(mpmath.mpf(2)**(n - 130) * mpmath.e)) + k) - 1


GROUPS = {
    "modp768 (RFC 2409, nhóm 1)": modp(768, 149686),
    "modp1024 (RFC 2409, nhóm 2)": modp(1024, 129093),
    "modp1536 (RFC 3526, nhóm 5)": modp(1536, 741804),
    "modp2048 (RFC 3526, nhóm 14)": modp(2048, 124476),
    "modp3072 (RFC 3526, nhóm 15)": modp(3072, 1690314),
    "ffdhe2048 (RFC 7919)": ffdhe(2048, 560316),
}

if __name__ == "__main__":
    for name, p in GROUPS.items():
        print(name, p.bit_length())
        print(hex(p))
