from dataclasses import dataclass
from internal_mlkem import *
import os

@dataclass
class MLKEM_Parameters:
    q: int
    n: int
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int

class ML_KEM():
    SecurityLevel = {
        512: MLKEM_Parameters(
            q=3329, n=256, k=2, eta1=3, eta2=2, du=10, dv=4,
            ),
        768: MLKEM_Parameters(
            q=3329, n=256, k=3, eta1=2, eta2=2, du=10, dv=4,
            ),
        1024: MLKEM_Parameters(
            q=3329, n=256, k=4, eta1=2, eta2=2, du=11, dv=5,
            ),
    }
    def __init__(self, slevel):
        self.params = self.SecurityLevel[slevel]

    # FIPS203 Algorithm 19
    def KeyGen(self):
        d = os.urandom(32)
        z = os.urandom(32)
        
        assert isinstance(d, bytes) and len(d) == 32
        assert isinstance(z, bytes) and len(z) == 32
        
        ek,dk = INTERNAL_MLKEM_KeyGen(d,z,self.params)
        
        return ek, dk
        
    # FIPS203 Algorithm 20    
    def Encaps(self, ek: bytes):
        # considere ek válido
        m = os.urandom(32)

        assert isinstance(m, bytes) and len(m) == 32
        
        K, c = INTERNAL_MLKEM_Encaps(ek,m,self.params)
        
        return K, c
        
    # FIPS203 Algorithm 21    
    def Decaps(self, dk: bytes, c: bytes):
        K_ = INTERNAL_MLKEM_Decaps(dk,c,self.params)
        return K_ 
