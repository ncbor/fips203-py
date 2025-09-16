from internal_mlkem import *
import os

# parameters_512
n = 256
q = 3329
k = 2
eta1 = 3
eta2 = 2
du = 10
dv = 4


def ML_KEM_KeyGen():

    d = os.urandom(32)
    z = os.urandom(32)
    
    assert isinstance(d, bytes) and len(d) == 32
    assert isinstance(z, bytes) and len(z) == 32
    
    ek,dk = ML_KEM_KeyGen_internal(d,z)
    
    return ek, dk
    
'''
Caso você não gerou suas chaves, convém testar sua validez:

1. (Seed consistency) If a seed (𝑑, 𝑧) is available, run ML-KEM.KeyGen_internal(𝑑, 𝑧), and
verify that the output is equal to (ek, dk).

2. (Encapsulation key check) Check ek as specified in Section 7.2 (FIPS203).

3. (Decapsulation key check) Check dk as specified in Section 7.3 (FIPS203).

4. (Pair-wise consistency) Perform the following steps:
    i. Generate an array of 32 random bytes by performing 𝑚 ←− 𝔹32 .
    ii. Perform (𝐾, 𝑐) ← ML-KEM.Encaps_internal(ek, 𝑚).
    iii. Perform 𝐾′ ← ML-KEM.Decaps_internal(dk, 𝑐).
    iv. Reject unless 𝐾 == 𝐾′ .

It is important to note that this checking process does not guarantee that the key pair is a properly
produced output of ML-KEM.KeyGen


Também há testes para checar a validez da chave de encapsulamento.
Ver: FIPS203, página 36

Também há testes para checar a validez da chave de decapsulamento.
Ver: FIPS203, página 37

'''

def ML_KEM_Encaps(ek: bytes):
    # considere ek válido

    m = os.urandom(32)
    assert isinstance(m, bytes) and len(m) == 32
    
    K, c = ML_KEM_Encaps_internal(ek,m)
    
    return K, c
    
    
def ML_KEM_Decaps(dk: bytes, c: bytes):
    return ML_KEM_Decaps_internal(dk,c)
