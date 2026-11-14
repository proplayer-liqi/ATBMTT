"""
main.py — Điểm khởi chạy chương trình demo Diffie–Hellman.

Cách chạy:
    python main.py                 # menu tương tác
    python main.py small           # chạy thẳng một demo (xem README.md)
    python main.py test            # chạy bộ kiểm thử
"""
import argparse
import sys

from app import demos, ui
from app.ui import c

MENU = [
    ("Ví dụ số nhỏ — in từng bước (khớp ví dụ tính tay)", lambda: demos.demo_small()),
    ("Trao đổi khoá 2048 bít + mã hoá / giải mã tệp", lambda: demos.demo_exchange()),
    ("Tấn công người đứng giữa (MITM) và cách phòng chống", lambda: demos.demo_mitm()),
    ("Thử phá DH: giải logarit rời rạc, khoá công khai giả", lambda: demos.demo_attack()),
    ("Đo thời gian chạy theo kích thước khoá / dữ liệu", lambda: demos.demo_benchmark()),
    ("Sinh tham số mới (số nguyên tố an toàn q, căn nguyên thuỷ α)", lambda: demos.demo_params()),
    ("Chạy bộ kiểm thử (tự viết + đối chiếu chuẩn)", lambda: _run_tests()),
]


def _run_tests():
    from tests.run_tests import main as run_all
    return run_all()


def interactive_menu():
    while True:
        ui.title("TRAO ĐỔI KHOÁ DIFFIE–HELLMAN — Môn An toàn và bảo mật thông tin")
        for i, (label, _) in enumerate(MENU, 1):
            print(f"    {c(str(i), 'cyan', 'bold')}. {label}")
        print(f"    {c('0', 'cyan', 'bold')}. Thoát")
        choice = ui.ask("Chọn chức năng", 1)
        if choice in ("0", "q", "exit"):
            break
        if choice.isdigit() and 1 <= int(choice) <= len(MENU):
            try:
                MENU[int(choice) - 1][1]()
            except KeyboardInterrupt:
                print()
                ui.note("Đã dừng chức năng, quay lại menu.")
            except Exception as exc:          # không để chương trình sập khi demo
                ui.fail(f"Lỗi: {exc}")
            ui.pause("Nhấn Enter để quay lại menu…")
        else:
            ui.fail("Lựa chọn không hợp lệ.")


def main(argv=None):
    p = argparse.ArgumentParser(description="Demo trao đổi khoá Diffie–Hellman (tự cài đặt)")
    p.add_argument("command", nargs="?", default="menu",
                   choices=["menu", "small", "exchange", "mitm", "attack", "bench", "params", "test"])
    p.add_argument("--preset", type=int, choices=[1, 2, 3],
                   help="small: 1 = Stallings (q=353), 2 = q=23, 3 = tự nhập")
    p.add_argument("--file", help="exchange: đường dẫn tệp cần mã hoá")
    p.add_argument("--bits", type=int, help="params: số bít của q")
    p.add_argument("--no-pause", action="store_true", help="không dừng chờ Enter giữa các bước")
    p.add_argument("--no-color", action="store_true", help="tắt màu")
    args = p.parse_args(argv)
    ui.set_options(color=False if args.no_color else None, pause=not args.no_pause)

    if args.command == "menu":
        interactive_menu()
    elif args.command == "small":
        demos.demo_small(args.preset)
    elif args.command == "exchange":
        if args.file:
            import os
            with open(args.file, "rb") as f:
                data = f.read()
            demos.demo_exchange(demos.G.DEFAULT_GROUP, data, os.path.basename(args.file))
        else:
            demos.demo_exchange()
    elif args.command == "mitm":
        demos.demo_mitm(interactive=not args.no_pause)
    elif args.command == "attack":
        demos.demo_attack()
    elif args.command == "bench":
        demos.demo_benchmark()
    elif args.command == "params":
        demos.demo_params(args.bits)
    elif args.command == "test":
        return 0 if _run_tests() else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
