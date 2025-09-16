from primitives import *
from k_pke import *

def ML_KEM_KeyGen_internal(d: bytes, z: bytes):
    ek_pke, dk_pke = K_PKE_KeyGen(d, k, eta1)
    ek = bytes(ek_pke)
    dk = dk_pke+ ek+ H(ek)+ z
    return ek, dk
    
def ML_KEM_Encaps_internal(ek: bytes, m: bytes):
    K, r = G(m + H(ek))
    c = K_PKE_Encrypt(ek, m, r, k, eta1, eta2, du, dv)
    return K, c
    
def ML_KEM_Decaps_internal(dk: bytes, c: bytes):
    dk_pke = dk[0:384*k]            # PKE decryption key
    ek_pke = dk[384*k:768*k+32]     # PKE encryption key
    h = dk[768*k + 32 : 768*k + 64] # hash of PKE_ek
    z = dk[768*k + 64 : 768*k + 96] # implicit rejection value
    
    m_prime = K_PKE_Decrypt(dk_pke, c, k, du, dv)
    K_prime, r_prime = G(m_prime + h)
    K_ = J(z + c)
    
    c_prime = K_PKE_Encrypt(ek_pke, m_prime, r_prime, k, eta1, eta2, du, dv)
    
    if c != c_prime: # implicit rejection
        K_prime = K_
        
    return K_prime
