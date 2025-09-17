# --- FIPS203 Section 4: Auiliary Algorithms ---

from Crypto.Hash import SHA3_256, SHA3_512, SHAKE128, SHAKE256

q = 3329
n = 256

# === === === === ===  === === === === === ===
# === FIPS203 4.1: Cryptographic Functions ===
# === === === === ===  === === === === === ===

def H(b: bytes) -> bytes:
    return SHA3_256.new(b).digest()

def J(b: bytes) -> bytes:
    return SHAKE256.new(b).read(32)
    
def G(b: bytes) -> tuple[bytes, bytes]:
    h = SHA3_512.new(b).digest()
    return h[:32], h[32:]

def PRF_eta(eta: int, s: bytes, b: bytes) -> bytes:
    assert eta in (2,3) and len(s)==32 and len(b)==1
    return SHAKE256.new(s + b).read(64*eta)
    
class XOF:
    @staticmethod
    def Init():
        return SHAKE128.new()
    @staticmethod
    def Absorb(ctx, data: bytes):
        ctx.update(data)
        return ctx
    @staticmethod
    def Squeeze(ctx, outlen_bytes: int):
        return ctx, ctx.read(outlen_bytes)

# === === === === === === === === === ===
# === FIPS203 4.2: General Algorithms ===
# === === === === === === === === === ===

# === 4.2.1: Conversion and Compression Algorithms ===

# FIPS203 Algorithm 3
def BitsToBytes(bits: list[int]) -> bytes:
    assert len(bits)%8 == 0
    out = bytearray(len(bits)//8)
    for i,bit in enumerate(bits):
        out[i>>3] |= (bit & 1) << (i & 7) # bitwise for out[i//8] += (bit % 2) << (i % 8)
    return bytes(out)
    
# FIPS203 Algorithm 4
def BytesToBits(B: bytes) -> list[int]:
    b = []
    for byte in B:
        for j in range(8):
            b.append(byte & 1)
            byte >>= 1
    return b

def Compress_d(x: list[int], d: int) -> list[int]:
    assert 1 <= d < 12
    def compress_coefficient(x2,d):
        return int(((1<<d) * x2 + q//2) // q) % (1<<d)
    return [compress_coefficient(i, d) for i in x]

def Decompress_d(y: list[int], d: int) -> list[int]:
    assert 1 <= d < 12
    def decompress_coefficient(y2,d):
        return int((q * y2 + (1<<d)//2) // (1<<d)) % q
    return [decompress_coefficient(i,d) for i in y]

# FIPS203 Algorithm 5
def ByteEncode_d(F: list[int], d: int) -> bytes:
    assert len(F)==256
    assert 1<=d<=12
    bits=[]
    if d < 12:
        m = 1 << d
        for a in F:
            assert 0<=a<m
            for j in range(d):
                bits.append(a & 1)      # b[i*d + j] <- a mod 2
                a = (a - (a & 1)) >> 1  # a <- (a - b)/2  (= a >>= 1)
    else:  # d == 12
        for a in F:
            assert 0<=a<q
            for j in range(12):
                bits.append(a & 1)      # b[i*d + j] <- a mod 2
                a = (a - (a & 1)) >> 1  # a <- (a - b)/2  (= a >>= 1)
    return BitsToBytes(bits)

# FIPS203 Algorithm 6
def ByteDecode_d(B: bytes, d: int) -> list[int]:
    assert 1 <= d <= 12
    assert len(B) * 8 == 256 * d  # B ∈ B^{32·d}
    bits = BytesToBits(B)
    m = (1 << d) if d < 12 else q
    F=[]
    for i in range(256):
        a = 0
        base = i * d
        for j in range(d):
            a += (bits[base + j] & 1) << j
        F.append(a % m)     # redundant for d<12, required for d=12
    return F

# === 4.2.1: Conversion and Compression Algorithms ===

# FIPS203 Algorithm 7
def SampleNTT(B: bytes) -> list[int]:
    assert len(B)==34 # B = seed32 || bytes(i) || bytes(j)
    ctx = XOF.Init()
    ctx = XOF.Absorb(ctx, B)
    a_hat=[0]*256
    j=0
    while j<256:
        ctx,C = XOF.Squeeze(ctx, 3)
        d1 = C[0] + 256*(C[1] & 0x0F)
        d2 = (C[1]>>4) + 16*C[2]
        if d1 < q:
            a_hat[j]=d1
            j+=1
        if d2 < q and j<256:
            a_hat[j]=d2
            j+=1
    return a_hat

# FIPS203 Algorithm 8
def SamplePolyCBD_eta(B: bytes, eta: int) -> list[int]:
    assert eta in (2, 3)  # FIPS 203 uses eta ∈ {2,3}
    assert len(B)==64*eta
    f=[0]*256; t = BytesToBits(B)
    for i in range(256):
        x = sum(t[2*eta*i + j] for j in range(eta))
        y = sum(t[2*eta*i + eta + j] for j in range(eta))
        f[i] = (x - y) % q
    return f

# === Precomputed Values for NTT ===
_BitRev7 = lambda i: [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319,
    1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617,
    1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649,
    1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156,
    3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298,
    2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757,
    2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775,
    886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154][i % 128]
    
_2BitRev7_1 = lambda i: [
    17, -17, 2761, -2761, 583, -583, 2649, -2649,
    1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
    1409, -1409, 2662, -2662, 3281, -3281, 233, -233,
    756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
    1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
    1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
    939, -939, 2308, -2308, 2437, -2437, 2388, -2388,
    733, -733, 2337, -2337, 268, -268, 641, -641,
    1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
    375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
    1063, -1063, 319, -319, 2773, -2773, 757, -757,
    2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
    2804, -2804, 1092, -1092, 403, -403, 1026, -1026,
    1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
    1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
    2110, -2110, 2935, -2935, 885, -885, 2154, -2154
][i % 128]

# FIPS203 Algorithm 9
def NTT(f: list[int]) -> list[int]:
    assert len(f) == 256
    f_hat = list(f)
    i = 1
    length = 128
    while length >= 2:
        start = 0
        while start < 256:
            zeta = _BitRev7(i)
            i += 1
            for j in range(start, start + length):
                t = (zeta * f_hat[j + length]) % q
                f_hat[j + length] = (f_hat[j] - t) % q
                f_hat[j] = (f_hat[j] + t) % q
            start += 2 * length
        length //= 2
    return f_hat

# FIPS203 Algorithm 10
def NTT_inv(f_hat: list[int]) -> list[int]:
    assert len(f_hat) == 256
    f = list(f_hat)
    i = 127
    length = 2
    while length <= 128:
        start = 0
        while start < 256:
            zeta = _BitRev7(i)
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % q
                f[j + length] = (zeta * (f[j + length] - t)) % q
            start += 2 * length
        length *= 2
    for j in range(256):
        f[j] = (f[j] * 3303) % q
    return f

# FIPS203 Algorithm 12
def BaseCaseMultiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> (int,int):
    c0 = (a0 * b0 + a1 * b1 * gamma) % q
    c1 = (a0 * b1 + a1 * b0) % q
    return c0, c1

# FIPS203 Algorithm 11
def MultiplyNTTs(f_hat: list[int], g_hat: list[int]) -> list[int]:
    assert len(f_hat) == 256 and len(g_hat) == 256
    h_hat = [0] * 256
    for i in range(128):
        h_hat[2*i], h_hat[2*i + 1] = BaseCaseMultiply(
            f_hat[2*i],
            f_hat[2*i + 1],
            g_hat[2*i],
            g_hat[2*i + 1],
            _2BitRev7_1(i)
        )
    return h_hat
