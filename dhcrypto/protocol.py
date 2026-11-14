"""
protocol.py — Mô phỏng phiên trao đổi khoá giữa Alice và Bob qua một kênh
công khai, có thể có kẻ tấn công người đứng giữa (Mallory).

Phần này chỉ chứa LOGIC. Mỗi việc xảy ra được báo ra ngoài dưới dạng sự kiện
(Event) qua hàm callback `emit`; phần giao diện (app/) quyết định cách in.

Các chế độ:
  * mitm=False, auth=False : DH gốc, kênh an toàn trước kẻ nghe lén thụ động
  * mitm=True,  auth=False : Mallory chen giữa -> đọc được toàn bộ dữ liệu
  * mitm=True,  auth=True  : mỗi bên ký số lên khoá công khai DH của mình ->
                             Mallory không ký giả được -> bị phát hiện
"""
from dataclasses import dataclass, field
from typing import Callable, Optional

from .dh import compute_shared_secret, generate_keypair, shared_secret_bytes
from .file_cipher import decrypt_bytes, encrypt_bytes, parse_blob
from .groups import DHGroup
from .kdf import derive_session_keys
from .rsa_sign import RSAPrivateKey, RSAPublicKey, generate_rsa_keypair, sign, verify
from .sha256 import sha256


class AuthenticationError(Exception):
    """Chữ ký trên khoá công khai DH không hợp lệ -> nghi có người đứng giữa."""


@dataclass
class Event:
    actor: str           # "Alice", "Bob", "Mallory", "Kênh"
    kind: str            # "info" | "send" | "compute" | "secret" | "attack" | "ok" | "fail"
    text: str
    data: dict = field(default_factory=dict)


def short_auth_string(k_bytes: bytes) -> str:
    """Mã xác nhận ngắn từ khoá chung, để hai bên đọc cho nhau so sánh."""
    h = sha256(k_bytes).hex()
    return f"{h[0:4]}-{h[4:8]}".upper()


def _pubkey_message(name: str, group: DHGroup, y: int) -> bytes:
    """Nội dung được ký: danh tính + nhóm tham số + khoá công khai DH."""
    return b"DH-PUBKEY|" + name.encode() + b"|" + group.name.encode() + b"|" + str(y).encode()


class Party:
    """Một bên tham gia (Alice hoặc Bob)."""

    def __init__(self, name: str, group: DHGroup, private: int = None,
                 rsa_key: Optional[RSAPrivateKey] = None):
        self.name = name
        self.group = group
        self.kp = generate_keypair(group, private)
        self.rsa_key = rsa_key
        self.trusted = {}                # tên đối phương -> khoá công khai RSA đã biết trước
        self.shared = None               # K_AB (số nguyên)
        self.k_enc = self.k_mac = None
        self.sas = None

    def hello(self, auth: bool) -> dict:
        msg = {"from": self.name, "y": self.kp.public}
        if auth:
            msg["sig"] = sign(self.rsa_key, _pubkey_message(self.name, self.group, self.kp.public))
        return msg

    def accept(self, msg: dict, peer: str, auth: bool):
        """Nhận khoá công khai của đối phương, (kiểm tra chữ ký), tính K và khoá phiên."""
        y = msg["y"]
        if auth:
            pub = self.trusted[peer]
            sig = msg.get("sig")
            if sig is None or not verify(pub, _pubkey_message(peer, self.group, y), sig):
                raise AuthenticationError(
                    f"{self.name}: chữ ký trên khoá công khai của '{peer}' KHÔNG hợp lệ")
        self.shared = compute_shared_secret(self.group, self.kp.private, y)
        kb = shared_secret_bytes(self.group, self.shared)
        self.k_enc, self.k_mac = derive_session_keys(kb)
        self.sas = short_auth_string(kb)
        return self.shared


class Mallory:
    """Kẻ tấn công đứng giữa: thay khoá công khai của hai bên bằng M = α^m."""

    def __init__(self, group: DHGroup, rsa_key: Optional[RSAPrivateKey] = None):
        self.group = group
        self.kp = generate_keypair(group)
        self.rsa_key = rsa_key or None
        self.keys = {}          # tên nạn nhân -> (K, k_enc, k_mac, sas)
        self.stolen = []        # các bản rõ đọc trộm được

    def intercept_hello(self, msg: dict, auth: bool) -> dict:
        victim = msg["from"]
        k = compute_shared_secret(self.group, self.kp.private, msg["y"])
        kb = shared_secret_bytes(self.group, k)
        self.keys[victim] = (k,) + derive_session_keys(kb) + (short_auth_string(kb),)
        forged = {"from": victim, "y": self.kp.public}
        if auth:
            # Mallory không có khoá riêng RSA của nạn nhân -> chỉ ký được bằng khoá của mình
            if self.rsa_key is None:
                self.rsa_key = generate_rsa_keypair(512)
            forged["sig"] = sign(self.rsa_key, _pubkey_message(victim, self.group, self.kp.public))
        return forged

    def intercept_data(self, blob: bytes, sender: str, receiver: str, tamper=None) -> bytes:
        _, k_enc, k_mac, _ = self.keys[sender]
        name, plain = decrypt_bytes(k_enc, k_mac, blob)
        self.stolen.append((sender, name, plain))
        if tamper:
            plain = tamper(plain)
        _, k_enc2, k_mac2, _ = self.keys[receiver]
        return encrypt_bytes(k_enc2, k_mac2, plain, name)


@dataclass
class SessionResult:
    ok: bool
    alice: Party
    bob: Party
    mallory: Optional[Mallory]
    received: Optional[bytes] = None
    received_name: str = ""
    error: str = ""
    blob: bytes = b""          # dữ liệu đã mã hoá mà Bob nhận được


def run_session(group: DHGroup, data: bytes, filename: str = "message.txt",
                mitm: bool = False, auth: bool = False, tamper: Callable = None,
                emit: Callable[[Event], None] = lambda e: None,
                xA: int = None, xB: int = None, rsa_bits: int = 1024) -> SessionResult:
    """Chạy trọn một phiên: trao đổi khoá -> Alice mã hoá `data` gửi Bob -> Bob giải mã."""
    alice_rsa = bob_rsa = None
    if auth:
        emit(Event("Kênh", "info", f"Chuẩn bị: mỗi bên sinh cặp khoá RSA {rsa_bits} bít dài hạn "
                                   "và biết trước khoá công khai RSA của nhau (như chứng chỉ)."))
        alice_rsa, bob_rsa = generate_rsa_keypair(rsa_bits), generate_rsa_keypair(rsa_bits)

    alice = Party("Alice", group, xA, alice_rsa)
    bob = Party("Bob", group, xB, bob_rsa)
    if auth:
        alice.trusted["Bob"] = bob_rsa.public
        bob.trusted["Alice"] = alice_rsa.public
        emit(Event("Alice", "info", f"Vân tay RSA của Alice: {alice_rsa.public.fingerprint()}"))
        emit(Event("Bob", "info", f"Vân tay RSA của Bob:   {bob_rsa.public.fingerprint()}"))

    mallory = Mallory(group) if mitm else None
    emit(Event("Kênh", "info", f"Tham số công khai: {group.name}, q dài {group.bits} bít, α = {group.alpha}"))
    emit(Event("Alice", "secret", "Chọn khoá riêng x_A (bí mật)", {"x": alice.kp.private}))
    emit(Event("Alice", "compute", "Tính y_A = α^x_A mod q", {"y": alice.kp.public}))
    emit(Event("Bob", "secret", "Chọn khoá riêng x_B (bí mật)", {"x": bob.kp.private}))
    emit(Event("Bob", "compute", "Tính y_B = α^x_B mod q", {"y": bob.kp.public}))
    if mallory:
        emit(Event("Mallory", "attack", "Chọn khoá riêng m, tính M = α^m mod q", {"y": mallory.kp.public}))

    # --- Bước 1: Alice gửi y_A ---------------------------------------------
    msg_a = alice.hello(auth)
    emit(Event("Alice", "send", "Gửi y_A" + (" kèm chữ ký RSA" if auth else "") + " → Bob", {"y": msg_a["y"]}))
    if mallory:
        msg_a = mallory.intercept_hello(msg_a, auth)
        emit(Event("Mallory", "attack", "Chặn y_A, giữ lại; gửi M cho Bob và nói đó là của Alice"
                   + (" (kèm chữ ký GIẢ — Mallory chỉ ký được bằng khoá RSA của chính mình)" if auth else ""),
                   {"y": msg_a["y"]}))

    # --- Bước 2: Bob gửi y_B -----------------------------------------------
    msg_b = bob.hello(auth)
    emit(Event("Bob", "send", "Gửi y_B" + (" kèm chữ ký RSA" if auth else "") + " → Alice", {"y": msg_b["y"]}))
    if mallory:
        msg_b = mallory.intercept_hello(msg_b, auth)
        emit(Event("Mallory", "attack", "Chặn y_B, giữ lại; gửi M cho Alice và nói đó là của Bob"
                   + (" (kèm chữ ký GIẢ)" if auth else ""), {"y": msg_b["y"]}))

    # --- Bước 3: mỗi bên tính khoá chung -----------------------------------
    try:
        bob.accept(msg_a, "Alice", auth)
        if auth:
            emit(Event("Bob", "ok", "Chữ ký trên khoá công khai của Alice hợp lệ"))
        alice.accept(msg_b, "Bob", auth)
        if auth:
            emit(Event("Alice", "ok", "Chữ ký trên khoá công khai của Bob hợp lệ"))
    except AuthenticationError as exc:
        emit(Event("Bob" if "Bob:" in str(exc) else "Alice", "fail", str(exc)))
        emit(Event("Kênh", "fail", "PHÁT HIỆN NGƯỜI ĐỨNG GIỮA → huỷ phiên, không gửi dữ liệu."))
        return SessionResult(False, alice, bob, mallory, error=str(exc))

    emit(Event("Alice", "compute", "K = (khoá nhận được)^x_A mod q", {"k": alice.shared, "sas": alice.sas}))
    emit(Event("Bob", "compute", "K = (khoá nhận được)^x_B mod q", {"k": bob.shared, "sas": bob.sas}))
    if mallory:
        emit(Event("Mallory", "attack", "Có khoá K₁ với Alice và K₂ với Bob",
                   {"k1": mallory.keys["Alice"][0], "k2": mallory.keys["Bob"][0]}))

    # --- Bước 4: Alice mã hoá dữ liệu gửi Bob -----------------------------
    blob = encrypt_bytes(alice.k_enc, alice.k_mac, data, filename)
    _, _, nonce, ct, tag = parse_blob(blob)
    emit(Event("Alice", "send", f"Mã hoá '{filename}' ({len(data):,} byte) bằng ChaCha20 + HMAC, gửi cho Bob",
               {"cipher_preview": ct[:24].hex(), "size": len(blob)}))
    if mallory:
        blob = mallory.intercept_data(blob, "Alice", "Bob", tamper)
        _, _, stolen = mallory.stolen[-1]
        emit(Event("Mallory", "attack", "Giải mã bằng K₁, ĐỌC TRỘM nội dung, mã hoá lại bằng K₂ rồi chuyển cho Bob"
                   + (" (đã SỬA nội dung)" if tamper else ""), {"plain_preview": stolen[:120]}))

    # --- Bước 5: Bob giải mã -----------------------------------------------
    try:
        name, plain = decrypt_bytes(bob.k_enc, bob.k_mac, blob)
    except Exception as exc:  # sai khoá / bị sửa
        emit(Event("Bob", "fail", f"Giải mã thất bại: {exc}"))
        return SessionResult(False, alice, bob, mallory, error=str(exc))
    emit(Event("Bob", "ok", f"Giải mã thành công '{name}' ({len(plain):,} byte), kiểm tra HMAC đạt"))
    return SessionResult(True, alice, bob, mallory, plain, name, blob=blob)
