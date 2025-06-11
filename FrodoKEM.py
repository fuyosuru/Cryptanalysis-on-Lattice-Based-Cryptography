import os
import hashlib
from sage.all import Matrix, ZZ

n = 40            
nbar = 8            
q = 2**15          
mu_bytes = 16        
seed_bytes = 16     

def sample_error_matrix(rows, cols):
    def sample():
        return sum((1 if os.urandom(1)[0] & (1 << i) else 0) - (1 if os.urandom(1)[0] & (1 << i) else 0) for i in range(6))
    return Matrix(ZZ, rows, cols, [sample() for _ in range(rows * cols)])


def shake128(input_bytes, out_len):
    return hashlib.shake_128(input_bytes).digest(out_len)


def generate_A(seedA):
    buf = shake128(seedA, 2 * n * n)
    vals = [int.from_bytes(buf[2*i:2*i+2], 'little') & (q-1) for i in range(n*n)]
    return Matrix(ZZ, n, n, vals)


def encode_matrix(M):
    return b"".join(int(x).to_bytes(2, 'little') for x in M.list())


def decode_matrix(bstr, rows, cols):
    vals = [int.from_bytes(bstr[2*i:2*i+2], 'little') for i in range(rows*cols)]
    return Matrix(ZZ, rows, cols, vals)


def encode_mu(mu):
    bits = [(mu[i//8] >> (i%8)) & 1 for i in range(mu_bytes*8)]
    vals = [(bits[2*i] | (bits[2*i+1] << 1)) for i in range(nbar*nbar)]
    step = q // 4
    return Matrix(ZZ, nbar, nbar, [v * step for v in vals])


def decode_mu(M):
    step = q // 4
    flat = M.list()
    two_bits = [int(round(v / step)) % 4 for v in flat]
    bits = []
    for tb in two_bits:
        bits.append(tb & 1)
        bits.append((tb >> 1) & 1)
    mu_rec = bytearray(mu_bytes)
    for i, b in enumerate(bits[:mu_bytes*8]):
        mu_rec[i//8] |= (b << (i%8))
    return bytes(mu_rec)

def frodokem_keygen():
    seedA = os.urandom(seed_bytes)
    A = generate_A(seedA)
    S = sample_error_matrix(n, nbar)
    E = sample_error_matrix(n, nbar)
    B = (A * S + E).apply_map(lambda x: x % q)
    pk = seedA + encode_matrix(B)
    sk = (S, B)
    return pk, sk


def frodokem_encapsulate(pk):
    seedA = pk[:seed_bytes]
    B = decode_matrix(pk[seed_bytes:], n, nbar)
    mu = os.urandom(mu_bytes)
    Sp = sample_error_matrix(nbar, n)
    Ep = sample_error_matrix(nbar, n)
    Epp = sample_error_matrix(nbar, nbar)
    A = generate_A(seedA)
    C1 = (Sp * A + Ep).apply_map(lambda x: x % q)
    V = (Sp * B + Epp).apply_map(lambda x: x % q)
    MU = encode_mu(mu)
    C2 = (V[:, :nbar] + MU).apply_map(lambda x: x % q)
    ct = encode_matrix(C1) + encode_matrix(C2)
    ss = hashlib.sha3_256(mu + ct).digest()[:mu_bytes]
    return ct, ss, mu


def frodokem_decapsulate(pk, sk, ct):
    seedA = pk[:seed_bytes]
    S, _ = sk
    len_c1 = 2 * nbar * n
    C1 = decode_matrix(ct[:len_c1], nbar, n)
    C2 = decode_matrix(ct[len_c1:], nbar, nbar)
    Vp = (C1 * S).apply_map(lambda x: x % q)
    Mp = (C2 - Vp).apply_map(lambda x: x % q)
    mu_rec = decode_mu(Mp)
    ss = hashlib.sha3_256(mu_rec + ct).digest()[:mu_bytes]
    return mu_rec, ss

def example():
    pk, sk = frodokem_keygen()
    ct, ss1, mu = frodokem_encapsulate(pk)
    mu_rec, ss2 = frodokem_decapsulate(pk, sk, ct)
    print("Shared secret match:", ss1 == ss2 , mu.hex())
    print("Recovered mu match original:", mu_rec == mu, mu_rec.hex())

if __name__ == '__main__':
    example()
