from pathlib import Path
import re
from hashlib import sha256
from Crypto.Cipher import AES


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or (len(data) % block_size) != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")
    return data[:-pad_len]


def parse_output_txt(text: str) -> tuple[str, str, str]:
    iv_m = re.search(r'^iv\s*=\s*"([0-9a-fA-F]+)"\s*$', text, re.M)
    enc_m = re.search(r'^enc\s*=\s*"([0-9a-fA-F]+)"\s*$', text, re.M)
    sk_m = re.search(r"^sk\s*=\s*(.*)\s*$", text, re.M)

    if not (iv_m and enc_m and sk_m):
        raise ValueError("Failed to parse iv/enc/sk from output.txt")

    iv_hex = iv_m.group(1)
    enc_hex = enc_m.group(1)

    # Generator does: key = sha256(str(sk).encode()).digest()
    # output.txt line is: 'sk =  ' + str(sk)
    sk_str = sk_m.group(1)
    first_paren = sk_str.find("(")
    if first_paren == -1:
        raise ValueError("Parsed sk does not look like a tuple")
    sk_str = sk_str[first_paren:]  # exact str(sk) starts at '('

    return iv_hex, enc_hex, sk_str


def main() -> None:
    base_dir = Path(__file__).resolve().parent if "__file__" in globals() else Path(".")
    output_path = base_dir / "output.txt"
    text = output_path.read_text(encoding="utf-8")

    iv_hex, enc_hex, sk_str = parse_output_txt(text)

    key = sha256(sk_str.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv_hex))
    pt = cipher.decrypt(bytes.fromhex(enc_hex))
    pt = pkcs7_unpad(pt, 16)

    try:
        print(pt.decode())
    except UnicodeDecodeError:
        print(pt)


if __name__ == "__main__":
    main()