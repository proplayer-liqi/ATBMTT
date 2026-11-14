"""
file_cipher.py — Mã hoá / giải mã dữ liệu (tệp) bằng khoá sinh từ Diffie–Hellman.

Sơ đồ (encrypt-then-MAC):
    K_AB --HKDF--> (k_enc, k_mac)
    bản mã = ChaCha20(k_enc, nonce, bản rõ)
    tag    = HMAC-SHA256(k_mac, header || bản mã)

Định dạng tệp mã hoá (.dhenc):
    "DHENC1" (6 byte) | độ dài tên (2 byte) | tên tệp gốc (UTF-8)
    | nonce (12 byte) | bản mã | tag (32 byte)
"""
import os
import secrets
import struct

from .chacha20 import chacha20_xor
from .kdf import constant_time_equal, hmac_sha256

MAGIC = b"DHENC1"
TAG_LEN = 32
NONCE_LEN = 12


class IntegrityError(ValueError):
    """Tag HMAC không khớp: dữ liệu bị sửa hoặc dùng sai khoá."""


def encrypt_bytes(k_enc: bytes, k_mac: bytes, plaintext: bytes, filename: str = "") -> bytes:
    name = filename.encode("utf-8")[:65535]
    nonce = secrets.token_bytes(NONCE_LEN)          # nonce mới cho mỗi lần mã hoá
    header = MAGIC + struct.pack(">H", len(name)) + name + nonce
    ciphertext = chacha20_xor(k_enc, nonce, plaintext)
    tag = hmac_sha256(k_mac, header + ciphertext)
    return header + ciphertext + tag


def parse_blob(blob: bytes):
    """Tách các thành phần của dữ liệu đã mã hoá."""
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 2 + NONCE_LEN + TAG_LEN:
        raise ValueError("không phải dữ liệu .dhenc hợp lệ")
    (name_len,) = struct.unpack(">H", blob[6:8])
    pos = 8 + name_len
    name = blob[8:pos].decode("utf-8", errors="replace")
    nonce = blob[pos:pos + NONCE_LEN]
    header = blob[:pos + NONCE_LEN]
    ciphertext = blob[pos + NONCE_LEN:-TAG_LEN]
    tag = blob[-TAG_LEN:]
    return header, name, nonce, ciphertext, tag


def decrypt_bytes(k_enc: bytes, k_mac: bytes, blob: bytes):
    """Trả về (tên_tệp_gốc, bản_rõ). Báo IntegrityError nếu tag sai."""
    header, name, nonce, ciphertext, tag = parse_blob(blob)
    if not constant_time_equal(hmac_sha256(k_mac, header + ciphertext), tag):
        raise IntegrityError("kiểm tra toàn vẹn thất bại (sai khoá hoặc dữ liệu bị sửa)")
    return name, chacha20_xor(k_enc, nonce, ciphertext)


def encrypt_file(k_enc: bytes, k_mac: bytes, in_path: str, out_path: str) -> int:
    with open(in_path, "rb") as f:
        data = f.read()
    blob = encrypt_bytes(k_enc, k_mac, data, os.path.basename(in_path))
    with open(out_path, "wb") as f:
        f.write(blob)
    return len(blob)


def decrypt_file(k_enc: bytes, k_mac: bytes, in_path: str, out_dir: str, prefix: str = "decrypted_") -> str:
    with open(in_path, "rb") as f:
        blob = f.read()
    name, data = decrypt_bytes(k_enc, k_mac, blob)
    out_path = os.path.join(out_dir, prefix + (name or "output.bin"))
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path
