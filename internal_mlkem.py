from auxiliaries import *
from internal_kpke import *

# FIPS203 Algorithm 16
def INTERNAL_MLKEM_KeyGen(d: bytes, z: bytes, params):
    ek_pke, dk_pke = KPKE_KeyGen(d, params.k, params.eta1)
    ek = bytes(ek_pke)
    dk = dk_pke+ ek+ H(ek)+ z
    return ek, dk
    
# FIPS203 Algorithm 17
def INTERNAL_MLKEM_Encaps(ek: bytes, m: bytes, params):
    K, r = G(m + H(ek))
    c = KPKE_Encrypt(ek, m, r, params.k, params.eta1, params.eta2, params.du, params.dv)
    return K, c
    
# FIPS203 Algorithm 18
def INTERNAL_MLKEM_Decaps(dk: bytes, c: bytes, params):
    dk_pke = dk[0:384*params.k]            # PKE decryption key
    ek_pke = dk[384*params.k:768*params.k+32]     # PKE encryption key
    h = dk[768*params.k + 32 : 768*params.k + 64] # hash of PKE_ek
    z = dk[768*params.k + 64 : 768*params.k + 96] # implicit rejection value
    
    m_prime = KPKE_Decrypt(dk_pke, c, params.k, params.du, params.dv)
    K_prime, r_prime = G(m_prime + h)
    K_ = J(z + c)
    
    c_prime = KPKE_Encrypt(ek_pke, m_prime, r_prime, params.k, params.eta1, params.eta2, params.du, params.dv)
    
    if c != c_prime: # implicit rejection
        K_prime = K_
        
    return K_prime
