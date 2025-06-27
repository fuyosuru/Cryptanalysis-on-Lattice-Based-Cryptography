import os
import hashlib
from sage.all import Matrix, ZZ
from sage.all import *
import random

n = 120
m = n+n//2      
nbar = 8          
q = 2**15
mu_bytes = 16
seed_bytes = 16

def sample(e):
    return random.randint(-e, e)

def sample_error_matrix(rows, cols):
    return Matrix(ZZ, rows, cols, [sample(3) for _ in range(rows * cols)])

def shake128(input_bytes, out_len):
    return hashlib.shake_128(input_bytes).digest(out_len)

def generate_A(seedA):
    buf = shake128(seedA, 2 * m * n)
    vals = [int.from_bytes(buf[2*i:2*i+2], 'little') & (q-1) for i in range(m*n)]
    return Matrix(ZZ, m, n, vals)

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
    A = generate_A(seedA)     # A is m × n
    S = sample_error_matrix(n, nbar)   # S is n × nbar
    E = sample_error_matrix(m, nbar)   # E is m × nbar
    #print(E)
    B = (A * S + E).apply_map(lambda x: x % q)   # B is m × nbar
    pk = seedA + encode_matrix(B)
    sk = S
    return pk, sk

def frodokem_encapsulate(pk):
    seedA = pk[:seed_bytes]
    B = decode_matrix(pk[seed_bytes:], m, nbar)
    mu = os.urandom(mu_bytes)
    Sp = sample_error_matrix(nbar, m)  # Sp is nbar × m
    Ep = sample_error_matrix(nbar, n)  # Ep is nbar × n
    Epp = sample_error_matrix(nbar, nbar)
    A = generate_A(seedA)  # m × n
    Bp = (Sp * A + Ep).apply_map(lambda x: x % q)  # nbar × n
    V = (Sp * B + Epp).apply_map(lambda x: x % q)  # nbar × nbar
    MU = encode_mu(mu)
    C2 = (V + MU).apply_map(lambda x: x % q)
    ct = encode_matrix(Bp) + encode_matrix(C2)
    ss = hashlib.sha3_256(mu + ct).digest()[:mu_bytes]
    return ct, ss, mu

def frodokem_decapsulate(pk, sk, ct):
    seedA = pk[:seed_bytes]
    S = sk
    len_c1 = 2 * nbar * n  # Because Bp is nbar × n
    Bp = decode_matrix(ct[:len_c1], nbar, n)
    C2 = decode_matrix(ct[len_c1:], nbar, nbar)
    Vp = (Bp * S).apply_map(lambda x: x % q)  # nbar × nbar
    diff = (C2 - Vp).apply_map(lambda x: x % q)
    mu_rec = decode_mu(diff)
    ss = hashlib.sha3_256(mu_rec + ct).digest()[:mu_bytes]
    return mu_rec, ss

def center_mod_q(vec, q):
    half_q = q // 2
    return [x - q if x > half_q else x for x in vec]

def modq_to_centered_matrix(M, q):
    half_q = q // 2
    return Matrix(ZZ, M.nrows(), M.ncols(),
                  [x - q if x > half_q else x for x in M.list()])



def recover_frodo_secret(A, B, q):
    n, nbar = A.ncols(), B.ncols()
    m = A.nrows()

    recovered_S_cols = []

    for col_idx in range(nbar):
        b_col = list(B.column(col_idx))
        A_list = [list(A.row(i)) for i in range(m)]
        error_vector = recover_error_vector(A_list, b_col, q)
        s_col = recover_secret(A_list, b_col, q, error_vector)
        recovered_S_cols.append(s_col)
     
    S = Matrix(ZZ, n, nbar, [s[i] for s in recovered_S_cols for i in range(n)])
    return S

def recover_error_vector(A_list, b_list, q):
    n = len(A_list[0])
    m = len(A_list)
    M = Matrix(ZZ, n + 1 + m, m + 1)

    for i in range(m):
        M[0, i] = b_list[i]
    M[0, m] = q

    for i in range(n):
        for j in range(m):
            M[i + 1, j] = A_list[j][i] % q

    for i in range(m):
        M[n + 1 + i, i] = q
    L = M.LLL()
    #L = M.BKZ(blocksize = 20)
    err = center_mod_q(L[-1],q)
    if err[-1] < 0:
        err = [-e for e in err]
    
    assert err[-1] == q
    assert all(abs(e) <= 3 for e in err[:-1])
    return err[:-1]

def recover_secret(A_list, b_list, q, error_vector):
    R = IntegerModRing(q)
    A = Matrix(R, [list(map(lambda x: x % q, row)) for row in A_list])
    b_vec = vector(R, [(b - e) % q for b, e in zip(b_list, error_vector)])
    try:
        s = A.solve_right(b_vec)
        return s
    except ValueError:
        ker = A.kernel()
        if ker.dimension() == 0:
            raise ValueError("No solution found")
        particular = A.solve_right(b_vec)
        
        return particular

def matrix_from_row_major(data, rows, cols):
    mat = Matrix(ZZ, rows, cols)
    for i in range(rows):
        for j in range(cols):
            mat[i, j] = data[j*rows + i]
    return mat

def crack(pk):
    seedA = pk[:seed_bytes]
    A = generate_A(seedA)
    B = decode_matrix(pk[seed_bytes:], A.nrows(), nbar)
    S_recovered = recover_frodo_secret(A, B, q)
    #print("[+] Recovered S matrix:")
    #print(S_recovered)
    result = modq_to_centered_matrix(S_recovered,q)
    rotated = matrix_from_row_major(result.list(), n, nbar)
    return rotated


def example():
    pk, sk = frodokem_keygen()
    test_sk = crack(pk)
    ct, ss1, mu = frodokem_encapsulate(pk)
    mu_rec, ss2 = frodokem_decapsulate(pk, test_sk, ct)
    print("Shared secret match:", ss1 == ss2 , mu.hex())
    print("Recovered mu match original:", mu_rec == mu, mu_rec.hex())

if __name__ == '__main__':
    example()
