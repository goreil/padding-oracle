#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
from oracle import oracle

# Repeatable
random.seed(123)
BLOCK_SIZE = 16

# Generate key and iv
key = random.randbytes(BLOCK_SIZE)
iv = random.randbytes(BLOCK_SIZE)
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
pt = b'This is some beautiful plaintext <3'
pt_short = b'You win! <3'

print(f"{key=}\n{iv=}")
ct = cipher.encrypt(pad(pt, BLOCK_SIZE))
print(f"{pt=}\n{ct=}")

# Newly generate AES otherwise iv changes
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
ct_short = cipher.encrypt(pad(pt_short, BLOCK_SIZE))
print(f"{pt_short=}\n{ct_short=}")

print(oracle(iv=iv, ct=ct))

