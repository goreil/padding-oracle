from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
BLOCK_SIZE = 16
# python generate.py
__key=b'f\xb3g\r\xb3}\x86D\xae\xddQ\x16|S\xda\xc4'
__iv=b'\x07\xff@h\xf3\xde<D\n>\x92\x1b\x95*\xa8\xd6'

__pt=b'This is some beautiful plaintext <3'
__ct=b'\x7f\xb8.\xb2\xd4\xa1l\xfee\xbf\xd06\x16W\x82y\xc8&T\xf5\xff\x1aa\xe64<\x1b2\x97\xdf\xee\xba\xa06\xdb\x1b\xdb\xad=\xbax\xdc\xc7<\xd0F%\xa5'

def oracle(iv:bytes, ct:bytes, debug=False) -> bytes :
    """Padding oracle, raises error if padding is false"""
    cipher = AES.new(key = __key, mode=AES.MODE_CBC, iv = iv)
    orig_pt = cipher.decrypt(ct)
    if debug:
        print("[DEBUG]", orig_pt)
    pt = unpad(orig_pt, BLOCK_SIZE)

    return pt

def silent_oracle(iv:bytes, ct:bytes, debug=False) -> bool:
    oracle(iv, ct, debug)

if __name__ == "__main__":
    # Correct
    print(oracle(__iv, __ct))
    # ValueError: Padding is incorrect.
    print(oracle(__iv, __ct[:-1] + b'\0'))
