from oracle import oracle, silent_oracle
from Crypto.Util.Padding import pad, unpad
from pwn import xor
from tqdm import trange
BLOCK_SIZE = 16
def forge_block(target:bytes, oracle, ct=b'\0'*BLOCK_SIZE):
    """Attempt to forge a target string
    
    ct is required such that decrypt works nicely
    """
    assert len(target) == BLOCK_SIZE
    known_iv = b'\0' * BLOCK_SIZE

    # Forge
    for i in trange(1, BLOCK_SIZE+1):
        current_padding = bytes([i] * i)
        for c in range(256):
            attempt = bytearray(xor(known_iv, current_padding).rjust(BLOCK_SIZE, b'\0'))
            attempt[-i] = c
            try:
                oracle(iv=attempt, ct=ct)
                known_iv = xor(attempt, current_padding)
                break
            
            except ValueError as e:
                continue
        
    return xor(known_iv, target)

def split_blocks(target):
    assert len(target) % BLOCK_SIZE == 0
    # target in blocks
    blocks = [target[i:i+BLOCK_SIZE] for i in range(0, len(target), BLOCK_SIZE)]
    return blocks


def forge(target:bytes, oracle):
    """Forges a target of any length"""
    blocks = split_blocks(target)

    last_ct = b'\0' * BLOCK_SIZE
    result = [last_ct]
    while blocks:
        current_iv = forge_block(target=blocks.pop(), oracle=oracle, ct=last_ct)
        result = [current_iv] + result
        last_ct = current_iv
    
    iv = result.pop(0)
    ct = b''.join(result)

    return iv, ct

def decrypt_block(iv:bytes, ciphertext:bytes, oracle):
    """Decrypts the ciphertext"""
    assert len(ciphertext) == BLOCK_SIZE
    forge_iv = forge_block(target=b'\0'*BLOCK_SIZE, oracle=oracle, ct=ciphertext)

    return xor(iv, forge_iv)

def decrypt(iv:bytes, ciphertext:bytes, oracle):
    blocks = split_blocks(ciphertext)
    pt = b''
    for prev, ct in zip([iv] + blocks[:-1], blocks):
        pt += decrypt_block(iv=prev, ciphertext=ct, oracle=oracle)
    
    return pt


if __name__ == "__main__":
    target  = pad(b'GET PWNED', BLOCK_SIZE)
    
    print('### FORGE < BLOCK_SIZE ###')
    iv = forge_block(target, oracle)
    print(f"{iv=}")
    print(oracle(iv, b'\0' * BLOCK_SIZE, debug=True))


    print('### FORGE with different ct')
    ct_short=b'Es\xda\x90\x1f\x8a\x05&1\x81\xeeJ\x1c\xa0\x14!'
    iv = forge_block(target, oracle, ct=ct_short)
    print(f"{iv=}")
    print(oracle(iv, ct_short, debug=True))

    # print("### FORGE WITH LONGER Target")
    # target = pad(b'You are a happy unicorn and love cheese and hearts', BLOCK_SIZE)
    # iv, ct = forge(target, oracle)
    # print(f"{iv=}, {ct=}")
    # print(oracle(iv, ct))


    print('### Decrypt SHORT ###')
    iv=b'\x07\xff@h\xf3\xde<D\n>\x92\x1b\x95*\xa8\xd6'
    ct_short=b'$\xe7\xa0P4\xcf\x18\xbf\tu"\xa0\x95c\xda\xa9'
    
    out = (decrypt_block(iv=iv, oracle=silent_oracle, ciphertext=ct_short))
    print(out)

    print('### Decrypt ###')
    ct=ct=b'\x7f\xb8.\xb2\xd4\xa1l\xfee\xbf\xd06\x16W\x82y\xc8&T\xf5\xff\x1aa\xe64<\x1b2\x97\xdf\xee\xba\xa06\xdb\x1b\xdb\xad=\xbax\xdc\xc7<\xd0F%\xa5'
    out = (decrypt(iv=iv, oracle=silent_oracle, ciphertext=ct))

    print(out)
