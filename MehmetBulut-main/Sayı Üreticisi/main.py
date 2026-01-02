import numpy as np
import struct

def rotl(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff; x[d] ^= x[a]; x[d] = rotl(x[d], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff; x[b] ^= x[c]; x[b] = rotl(x[b], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff; x[d] ^= x[a]; x[d] = rotl(x[d], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff; x[b] ^= x[c]; x[b] = rotl(x[b], 7)

def chacha20_block(key, counter, nonce):
    const = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state = const + list(struct.unpack("<8L", key)) + [counter] + list(struct.unpack("<3L", nonce))
    x = state.copy()

    for _ in range(10):
        qr(x, 0,4,8,12); qr(x, 1,5,9,13); qr(x, 2,6,10,14); qr(x, 3,7,11,15)
        qr(x, 0,5,10,15); qr(x, 1,6,11,12); qr(x, 2,7,8,13); qr(x, 3,4,9,14)

    return b"".join(struct.pack("<L", (x[i] + state[i]) & 0xffffffff) for i in range(16))

def chacha20_csprng(n=64, seed=2024):
    key   = (str(seed) * 32).encode()[:32]
    nonce = (str(seed)[::-1] * 12).encode()[:12]

    out, ctr = b"", 1
    while len(out) < n:
        out += chacha20_block(key, ctr, nonce)
        ctr += 1

    return [1 + (b % 255) for b in out[:n]]

if __name__ == "__main__":
    q = np.array(chacha20_csprng()).reshape(8, 8)
    print("ChaCha20 CSPRNG Quantization Table:\n", q)
