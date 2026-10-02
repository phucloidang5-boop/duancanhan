import base64
import json
import re
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256


class AxiomQuizSolver:
    def __init__(self, html_file):
        with open(html_file, encoding="utf-8") as f:
            self.html = f.read()
        self.payload = None
        self.plaintext = None

    def extract_payload(self):
        match = re.search(
            r'<script id="payload" type="application/json">(.*?)</script>',
            self.html,
            re.S,
        )
        if not match:
            raise ValueError("Không tìm thấy payload trong file HTML.")
        self.payload = json.loads(match.group(1))
        return self.payload

    def derive_key(self, password: str):
        salt = base64.b64decode(self.payload["s"])
        iterations = self.payload["n"]
        return PBKDF2(
            password, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256
        )

    def decrypt(self, password: str):
        key = self.derive_key(password)
        ciphertext = base64.b64decode(self.payload["c"])
        iv = base64.b64decode(self.payload["i"])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)

        pad_len = decrypted[-1]
        if (
            pad_len < 1
            or pad_len > 16
            or decrypted[-pad_len:] != bytes([pad_len]) * pad_len
        ):
            raise ValueError("Sai mật khẩu hoặc dữ liệu không đúng định dạng.")

        try:
            self.plaintext = decrypted[:-pad_len].decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Sai mật khẩu (giải mã ra dữ liệu không hợp lệ).")
        return self.plaintext

    def parse_questions(self):
        if not self.plaintext:
            raise ValueError("Chưa giải mã.")
        data = json.loads(self.plaintext)
        questions = []
        for q in data.get("questions", []):
            questions.append(
                {
                    "id": q.get("id"),
                    "type": q.get("type"),
                    "question": q.get("question"),
                    "options": q.get("options", []),
                    "answer": q.get("answer"),
                }
            )
        return questions


if __name__ == "__main__":
    solver = AxiomQuizSolver("KiemTra_TiengAnh_1.10. sáng t5.html")
    solver.extract_payload()
    print("Payload:", solver.payload)

    pw = input("Nhập mật khẩu: ").strip()
    if pw:
        try:
            text = solver.decrypt(pw)
            print("=== NỘI DUNG ĐÃ GIẢI MÃ ===")
            print(text)
            print("\n=== CÂU HỎI + ĐÁP ÁN ===")
            for q in solver.parse_questions():
                print(f"[{q['id']}] {q['question']}")
                for o in q["options"]:
                    print("   ", o)
                print("=> Đáp án:", q["answer"])
                print("-" * 40)
        except Exception as e:
            print("Lỗi:", e)