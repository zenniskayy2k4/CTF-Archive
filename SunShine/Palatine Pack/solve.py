#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Giải bài Palatine Pack (Reverse CTF) — decode flag từ flag.txt

KEY_START = 0x69

def unexpand(data: bytes) -> bytes:
    """
    Giải ngược lại 1 lần expand()
    """
    result = bytearray()
    key = KEY_START
    toggle = False
    for i in range(0, len(data), 2):
        a = data[i]
        b = data[i+1]
        if toggle:
            # encode: 
            #   out[0] = (in & 0xf0) | (key >> 4)
            #   out[1] = (in & 0x0f) | (key << 4)
            orig = (a & 0xf0) | (b & 0x0f)
        else:
            # encode:
            #   out[0] = (in & 0x0f) | (key << 4)
            #   out[1] = (in & 0xf0) | (key >> 4)
            orig = (b & 0xf0) | (a & 0x0f)
        result.append(orig)
        key = (key * 0x0b) & 0xff
        toggle = not toggle
    return bytes(result)

def flipBits(data: bytes) -> bytes:
    """
    Hàm flipBits ngược lại — thực chất giống hệt, vì là involution
    """
    out = bytearray(data)
    key = KEY_START
    toggle = False
    for i in range(len(out)):
        if toggle:
            out[i] ^= key
            key = (key + 0x20) & 0xff
        else:
            out[i] = (~out[i]) & 0xff
        toggle = not toggle
    return bytes(out)

def main():
    with open("flag.txt", "rb") as f:
        data = f.read()

    # Unexpand 3 lần (ngược chiều so với encode)
    for _ in range(3):
        data = unexpand(data)

    # FlipBits ngược
    data = flipBits(data)

    # In flag ra màn hình
    try:
        text = data.decode('utf-8', errors='replace')
    except:
        text = str(data)
    print("Decoded flag:", text)

if __name__ == "__main__":
    main()
