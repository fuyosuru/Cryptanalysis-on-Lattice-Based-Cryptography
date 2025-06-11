import os
import hashlib
import argparse
from sage.all import *
#23:09 - 10p
m = 80
n = 40
nbar = 8
q = 2**15
message_bytes = 16
seed_bytes = 16

def sample_error_matrix(rows, cols):
    def sample():
        return sum((1 if os.urandom(1)[0] & (1 << i) else 0) - (1 if os.urandom(1)[0] & (1 << i) else 0) for i in range(1))
    return Matrix(ZZ, rows, cols, [sample() for _ in range(rows * cols)])

def shake128(input_bytes, out_len):
    return hashlib.shake_128(input_bytes).digest(out_len)

def generate_A(seedA):
    buf = shake128(seedA, 2 * m * n)
    vals = [int.from_bytes(buf[2*i:2*i+2], 'little') & (q-1) for i in range(m*n)]
    return Matrix(ZZ, m, n, vals)

def encode_matrix(M):
    return b"".join(int((x+q)%q).to_bytes(2, 'little') for x in M.list())

def decode_matrix(bstr, rows, cols):
    vals = [int.from_bytes(bstr[2*i:2*i+2], 'little') for i in range(rows*cols)]
    return Matrix(ZZ, rows, cols, vals)

def encode_message(message):
    bits = [(message[i//8] >> (i%8)) & 1 for i in range(message_bytes*8)]
    vals = [(bits[2*i] | (bits[2*i+1] << 1)) for i in range(nbar*nbar)]
    step = q // 4
    return Matrix(ZZ, nbar, nbar, [v * step for v in vals])

def decode_message(M):
    step = q // 4
    flat = M.list()
    two_bits = [int(round(v / step)) % 4 for v in flat]
    bits = []
    for tb in two_bits:
        bits.append(tb & 1)
        bits.append((tb >> 1) & 1)
    message = bytearray(message_bytes)
    for i, b in enumerate(bits[:message_bytes*8]):
        message[i//8] |= (b << (i%8))
    return bytes(message)

def frodokem_keygen():
    seedA = os.urandom(seed_bytes)
    A = generate_A(seedA)
    S = sample_error_matrix(n, nbar)
    E = sample_error_matrix(m, nbar)
    B = (A * S + E).apply_map(lambda x: x % q)
    pk = seedA + encode_matrix(B)
    return pk, S

def frodokem_encapsulate(pk, message=None):
    seedA = pk[:seed_bytes]
    B = decode_matrix(pk[seed_bytes:], m, nbar)
    if message is None:
        message = os.urandom(message_bytes)
    elif len(message) > message_bytes:
        raise ValueError("Message too long, max 16 bytes")
    message = message.ljust(message_bytes, b'\x00')
    Sp = sample_error_matrix(nbar, m)
    Ep = sample_error_matrix(nbar, n)
    Epp = sample_error_matrix(nbar, nbar)
    A = generate_A(seedA)
    C1 = (Sp * A + Ep).apply_map(lambda x: x % q)
    V = (Sp * B + Epp).apply_map(lambda x: x % q)
    Encode_message = encode_message(message)
    C2 = (V + Encode_message).apply_map(lambda x: x % q)
    ct = encode_matrix(C1) + encode_matrix(C2)
    ss = hashlib.sha3_256(message + ct).digest()[:message_bytes]
    return ct, ss, message

def frodokem_decapsulate(pk, sk, ct):
    seedA = pk[:seed_bytes]
    len_c1 = 2 * nbar * n
    C1 = decode_matrix(ct[:len_c1], nbar, n)
    C2 = decode_matrix(ct[len_c1:], nbar, nbar)
    Vp = (C1 * sk).apply_map(lambda x: x % q)
    Mp = (C2 - Vp).apply_map(lambda x: x % q)
    message = decode_message(Mp)
    ss = hashlib.sha3_256(message + ct).digest()[:message_bytes]
    return message, ss

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
    err = center_mod_q(L[-1],q)
    if err[-1] < 0:
        err = [-e for e in err]
    assert err[-1] == q
    assert all(abs(e) <= 1 for e in err[:-1])
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

def center_mod_q(vec, q):
    half_q = q // 2
    return [x - q if x > half_q else x for x in vec]

def modq_to_centered_matrix(M, q):
    half_q = q // 2
    return Matrix(ZZ, M.nrows(), M.ncols(), [x - q if x > half_q else x for x in M.list()])

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

def matrix_from_row_major(data, rows, cols):
    mat = Matrix(ZZ, rows, cols)
    for i in range(rows):
        for j in range(cols):
            mat[i, j] = data[j*rows + i]
    return mat

def crack_and_recover(pk, ct):
    seedA = pk[:seed_bytes]
    A = generate_A(seedA)
    B = decode_matrix(pk[seed_bytes:], m, nbar)
    S_recovered = recover_frodo_secret(A, B, q)
    S_centered = modq_to_centered_matrix(S_recovered, q)
    sk = matrix_from_row_major(S_centered.list(), n, nbar)
    message, ss = frodokem_decapsulate(pk, sk, ct)
    return message


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    parser_keygen = subparsers.add_parser("keygen")
    parser_keygen.add_argument("pk_file")
    parser_keygen.add_argument("sk_file")

    parser_encaps = subparsers.add_parser("encaps")
    parser_encaps.add_argument("pk_file")
    parser_encaps.add_argument("ct_file")
    parser_encaps.add_argument("message")

    parser_decaps = subparsers.add_parser("decaps")
    parser_decaps.add_argument("pk_file")
    parser_decaps.add_argument("sk_file")
    parser_decaps.add_argument("ct_file")

    parser_crack = subparsers.add_parser("crack")
    parser_crack.add_argument("pk_file")
    parser_crack.add_argument("ct_file")

    args = parser.parse_args()

    if args.command == "keygen":
        pk, sk = frodokem_keygen()
        with open(args.pk_file, "wb") as f: f.write(pk)
        with open(args.sk_file, "wb") as f: f.write(encode_matrix(sk))
        print("Keys generated.")

    elif args.command == "encaps":
        with open(args.pk_file, "rb") as f: pk = f.read()
        message = args.message.encode('utf-8')[:message_bytes]
        ct, _, _ = frodokem_encapsulate(pk, message)
        with open(args.ct_file, "wb") as f: f.write(ct)
        print("Ciphertext saved.")

    elif args.command == "decaps":
        with open(args.pk_file, "rb") as f: pk = f.read()
        with open(args.sk_file, "rb") as f: sk_bytes = f.read()
        sk = decode_matrix(sk_bytes, n, nbar)
        with open(args.ct_file, "rb") as f: ct = f.read()
        message, _ = frodokem_decapsulate(pk, sk, ct)
        print("Recovered message:", message.rstrip(b'\x00').decode('utf-8', errors='ignore'))

    elif args.command == "crack":
        with open(args.pk_file, "rb") as f: pk = f.read()
        with open(args.ct_file, "rb") as f: ct = f.read()
        message = crack_and_recover(pk, ct)
        print("Cracked message:", message.rstrip(b'\x00').decode('utf-8', errors='ignore'))

if __name__ == "__main__":
    main()
