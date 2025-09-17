# ML-KEM (FIPS 203) – Python Reference Implementation

This repository contains a minimal, readable Python implementation of the Module-Lattice-Based Key Encapsulation Mechanism standardized in NIST FIPS 203 (ML-KEM, also known as Kyber).

The public, user-facing API is provided exclusively by `mlkem.py`. The other modules (`internal_mlkem.py`, `internal_kpke.py`, `auxiliaries.py`) are internal building blocks and must not be used directly.

## What this is
- A straightforward Python implementation meant for education, experimentation, and correctness clarity.
- Follows FIPS 203’s algorithm structure and parameter sets (ML-KEM-512/768/1024).
- Uses Python’s `os.urandom` for randomness and `pycryptodome` for SHA3/SHAKE primitives.

## What this is not
- Not production-hardened. Timing behavior, fault resistance, and side-channel mitigations are out of scope.
- Not a drop-in replacement for optimized C libraries.

---

## Installation

Requirements:
- Python 3.10+
- pycryptodome (for SHA3/SHAKE)

Install dependencies:
```bash
pip install pycryptodome
```

Clone and use locally:
```bash
git clone <this-repo>
cd fips203-py
```

---

## Supported Security Levels (FIPS 203 parameter sets)
- `512`  → ML-KEM-512 (k=2)
- `768`  → ML-KEM-768 (k=3)
- `1024` → ML-KEM-1024 (k=4)

These map to the dataclass `MLKEM_Parameters` and are selected when constructing `ML_KEM`.

---

## Quickstart

```python
from mlkem import ML_KEM

# Choose a parameter set: 512, 768, or 1024
kem = ML_KEM(512)

# Key generation (FIPS 203 Algorithm 19)
ek, dk = kem.KeyGen()

# Encapsulation (FIPS 203 Algorithm 20)
# Sender uses the recipient's public key ek to derive a shared key K and ciphertext c
K_sender, c = kem.Encaps(ek)

# Decapsulation (FIPS 203 Algorithm 21)
# Recipient uses the secret key dk to recover the shared key from ciphertext c
K_recipient = kem.Decaps(dk, c)

assert K_sender == K_recipient
print(len(ek), len(dk), len(c), len(K_sender))
```

Expected types/lengths:
- `ek` (public key): `bytes`
- `dk` (secret key): `bytes`
- `c` (ciphertext): `bytes`
- `K` (shared secret): 32 bytes

Note: Exact byte lengths of `ek`, `dk`, and `c` depend on the chosen parameter set (k and compression widths). The shared secret `K` is always 32 bytes.

---

## Public API

All user-facing operations live in `mlkem.py`:

- `class ML_KEM(slevel: int)`
  - Constructs an ML-KEM instance with FIPS 203 parameters for `slevel ∈ {512, 768, 1024}`.
  - `params`: an internal `MLKEM_Parameters` instance.

- `ML_KEM.KeyGen() -> tuple[bytes, bytes]`
  - FIPS 203 Algorithm 19.
  - Randomly samples 32-byte seeds using `os.urandom` to derive a fresh public/secret key pair `(ek, dk)`.

- `ML_KEM.Encaps(ek: bytes) -> tuple[bytes, bytes]`
  - FIPS 203 Algorithm 20.
  - Generates a fresh 32-byte random `m`, derives `(K, c)` given a valid `ek`.
  - Returns the shared secret `K` (32 bytes) and ciphertext `c`.

- `ML_KEM.Decaps(dk: bytes, c: bytes) -> bytes`
  - FIPS 203 Algorithm 21.
  - Returns the shared secret `K` recovered from `dk` and `c`.

---

## FIPS 203 alignment and considerations

This implementation mirrors the structure and intent of FIPS 203 algorithms:

- **Parameterization**
  - The `MLKEM_Parameters` map uses `q=3329`, `n=256`, and FIPS 203-compliant tuples `(k, eta1, eta2, du, dv)` for 512/768/1024.

- **Algorithm mapping**
  - Algorithm 19 (KeyGen): implemented in `ML_KEM.KeyGen()` and calls `INTERNAL_MLKEM_KeyGen(d, z, params)`.
  - Algorithm 20 (Encaps): implemented in `ML_KEM.Encaps()` and calls `INTERNAL_MLKEM_Encaps(ek, m, params)`.
  - Algorithm 21 (Decaps): implemented in `ML_KEM.Decaps()` and calls `INTERNAL_MLKEM_Decaps(dk, c, params)`.
  - Algorithms 13–18 and 3–12 appear across `internal_kpke.py`, `internal_mlkem.py`, and `auxiliaries.py` to support the public API.

- **No direct use of internal functions**
  - Users must import and call only `ML_KEM` methods. Internal modules (`internal_*`, `auxiliaries`) are not stable APIs and can change.

- **Guarantee of the true public key (`ek`) and implicit rejection**
  - Decapsulation unpacks `dk` into: `dk_pke || ek_pke || H(ek_pke) || z` as per FIPS 203.
  - During decapsulation, the implementation recomputes a candidate ciphertext `c'` from `m'` and compares it to the received `c`.
  - If `c != c'`, it performs implicit rejection, setting the shared key to `J(z || c)` to ensure correctness and robustness.
  - The stored `H(ek_pke)` in `dk` ensures the decapsulation uses the true associated public key, binding `dk` to the correct `ek` as required by FIPS 203.

- **Randomness sources**
  - KeyGen uses two independent 32-byte seeds `d` and `z` from `os.urandom`.
  - Encaps samples a fresh 32-byte `m` from `os.urandom`.
  - Internal randomness for polynomials uses SHAKE-based PRFs/XOFs per FIPS 203 (`G`, `PRF_eta`, `XOF`).

- **Output lengths and encoding**
  - Encodings follow FIPS 203 `ByteEncode_d`/`ByteDecode_d` with appropriate compression `d ∈ {1, du, dv, 12}`.
  - The shared secret `K` is 32 bytes.

- **Security notes**
  - Python-level timing behavior has not been analyzed; do not assume constant time.
  - This is for study and functional validation, not production deployment.

---

## Notes on determinism and reproducibility
- Key generation and encapsulation are randomized by design (fresh seeds and messages).
- For deterministic testing, you could temporarily stub `os.urandom` in a test harness; do not do this in real usage.

---

## Minimal example script

```python
from mlkem import ML_KEM

kem = ML_KEM(768)
ek, dk = kem.KeyGen()
K_a, c = kem.Encaps(ek)
K_b = kem.Decaps(dk, c)
assert K_a == K_b
print("Shared secret (hex):", K_a.hex())
```

---

## Internal files (do not import directly)
- `internal_mlkem.py`: ML-KEM internals (Algs. 16–18), calls into KPKE.
- `internal_kpke.py`: Kyber PKE layer (Algs. 13–15).
- `auxiliaries.py`: FIPS 203 primitives and utilities (Algs. 3–12), plus SHA3/SHAKE.

Only `mlkem.py` is the supported public interface.

---

## Troubleshooting
- ImportError for SHA3/SHAKE: install `pycryptodome`.
- Mismatched shared secrets: ensure you use the exact `(ek, dk)` pair, and do not mutate keys.
- Byte types: API expects and returns `bytes`. Avoid `bytearray` or `str`.

---

## License
If this file is missing or unspecified, treat this code as provided for educational use. Consult the repository owner for licensing terms before redistribution.
