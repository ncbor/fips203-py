# NÃO USAR ESSES MÉTODOS DE PUBLIC KEY ENCRIPTION POR SI SÓ!!
# É APENAS PARTE DO ML_KEM!!

from auxiliaries import *

q = 3329
n = 256

# FIPS203 Algorithm 13
def KPKE_KeyGen(d: bytes, k: int, eta1: int) -> (bytes,bytes):
    rho, sigma = G(d + bytes([k]))

    A_hat = [[None for _ in range(k)] for _ in range(k)]
  
    for i in range(k):
        for j in range(k):
            A_hat[i][j] = SampleNTT(rho + bytes([i]) + bytes([j]))
    # Vale notar que a matriz A_hat pode ser guardada para poupar a repetição dos passos acima
            
    Nctr = 0
    
    s = []
    for _ in range(k):
        s.append(SamplePolyCBD_eta(
            PRF_eta(
                eta1,
                sigma,
                bytes([Nctr])
                ),
            eta1)
            )
        Nctr += 1
        
    e = []
    for _ in range(k):
        e.append(SamplePolyCBD_eta(
            PRF_eta(
                eta1,
                sigma,
                bytes([Nctr])
                ),
            eta1)
            )
        Nctr += 1

    s_hat = [NTT(poly) for poly in s]
    e_hat = [NTT(poly) for poly in e]

    t_hat = []
    for i in range(k):
        aux = list(e_hat[i])
        for j in range(k):
            a_times_s = MultiplyNTTs(A_hat[i][j], s_hat[j]) #A*s
            aux = [(aux[t] + a_times_s[t]) % q for t in range(256)] #+t
        t_hat.append(aux)

    ek = b"".join(ByteEncode_d(t_hat[i], 12) for i in range(k)) + rho
    dk = b"".join(ByteEncode_d(s_hat[i], 12) for i in range(k))
    return ek, dk

# FIPS203 Algorithm 14
def KPKE_Encrypt(ek: bytes, m: bytes, r: bytes, k: int, eta1: int, eta2: int, du: int, dv: int) -> bytes:
    # t^
    t_hat = []
    for i in range(k):
        off = 384 * i
        t_hat.append(ByteDecode_d(ek[off:off + 384], 12))

    rho = ek[384 * k:384 * k + 32]

    # A^ matrix
    A_hat = [[None for _ in range(k)] for _ in range(k)]
    for i in range(k):
        for j in range(k):
            A_hat[i][j] = SampleNTT(rho + bytes([i]) + bytes([j])) # VERIFICAR

    Nctr = 0
    y = []
    for _ in range(k):
        y.append(SamplePolyCBD_eta(PRF_eta(eta1, r, bytes([Nctr])), eta1))
        Nctr += 1
        
    e1 = []
    for _ in range(k):
        e1.append(SamplePolyCBD_eta(PRF_eta(eta2, r, bytes([Nctr])), eta2))
        Nctr += 1

    e2 = SamplePolyCBD_eta(PRF_eta(eta2, r, bytes([Nctr])), eta2)
    
    y_hat = [NTT(poly) for poly in y]

    u = []
    for i in range(k):
        aux_hat = [0] * 256
        for j in range(k):
            prod = MultiplyNTTs(A_hat[j][i], y_hat[j])  # transpose: column i
            aux_hat = [(aux_hat[t] + prod[t]) % q for t in range(256)] # sage field here
        u_ntt_inv = NTT_inv(aux_hat)
        u.append([(u_ntt_inv[t] + e1[i][t]) % q for t in range(256)]) # sage field here
 
    mu = Decompress_d(ByteDecode_d(m,1), 1)

    aux_hat = [0] * 256
    for j in range(k):
        prod = MultiplyNTTs(t_hat[j], y_hat[j])
        aux_hat = [(aux_hat[t] + prod[t]) % q for t in range(256)] #sfh
    v_ntt_inv = NTT_inv(aux_hat)
    v = [((v_ntt_inv[t] + e2[t]) % q + mu[t]) % q for t in range(256)] #sfh

    
    c1 = b"".join(ByteEncode_d(Compress_d(u[i], du), du) for i in range(k))
    c2 = ByteEncode_d(Compress_d(v, dv), dv)

    c = c1+c2
    return c
    
# FIPS203 Algorithm 15
def KPKE_Decrypt(dk: bytes, c: bytes, k: int, du: int, dv: int) -> bytes:
    c1 = c[0:32 * du * k]
    c2 = c[32 * du * k:32 * du * k + 32 * dv]

    u_ = []
    for i in range(k):
        off = i * (32 * du)
        u_.append(Decompress_d(ByteDecode_d(c1[off:off + 32 * du], du), du))

    v_ = Decompress_d(ByteDecode_d(c2, dv), dv)

    s_hat = []
    for i in range(k):
        off = i * 384
        s_hat.append(ByteDecode_d(dk[off:off + 384], 12))

    aux_hat = [0] * 256
    for j in range(k):
        prod = MultiplyNTTs(s_hat[j], NTT(u_[j]))
        aux_hat = [(aux_hat[t] + prod[t]) % q for t in range(256)]
    w_temp = NTT_inv(aux_hat)
    w = [(v_[t] - w_temp[t]) % q for t in range(256)]

    m = ByteEncode_d(Compress_d(w, 1),1)

    return m

    

