import time
from sage.all import *
from sage.modules.free_module_integer import IntegerLattice
import random

def lwe_generate_instance(n, q, m, p, E_vals=[-3, 0, 3]):
    S = vector(ZZ, [randint(0, p - 1) for _ in range(n)])
    E = vector(ZZ, [random.choice(E_vals) for _ in range(m)])
    A_matrix = Matrix(ZZ, [[randint(0, q - 1) for _ in range(n)] for _ in range(m)])
    B = vector(ZZ, [(A_matrix[i] * S + E[i]) % q for i in range(m)])
    return A_matrix, S, B

def Babai_closest_vector(M, G, target):
    small = target
    for _ in range(1):  
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -= M[i] * c
    return target - small

def lwe_babai_attack(A_matrix, B_vector, q):
    n = A_matrix.ncols()
    m = A_matrix.nrows()
    L = Matrix(ZZ, n + m, m)
    for i in range(m):
        L[i, i] = q
    for x in range(m):
        for y in range(n):
            L[m + y, x] = A_matrix[x][y] % q

    lattice = IntegerLattice(L, lll_reduce=True)
    G = lattice.reduced_basis.gram_schmidt()[0]
    target = vector(ZZ, B_vector)
    res = Babai_closest_vector(lattice.reduced_basis, G, target)
    A_mod = Matrix(ZZ, [[A_matrix[x][y] % q for y in range(n)] for x in range(m)])
    R = IntegerModRing(q)
    try:
        M = Matrix(R, A_mod)
        S_recovered = M.solve_right(res)
        return [int(S_recovered[i]) for i in range(n)]
    except:
        return None  

def benchmark_lwe_babai(parameter_sets, p=257, E=[-3, 0, 3]):
    results = []

    for (n, q, m) in parameter_sets:
        print(f"Running for n={n}, q={q}, m={m}")
        A, S_real, B = lwe_generate_instance(n, q, m, p, E)
        start = time.time()
        recovered = lwe_babai_attack(A, B, q)
        end = time.time()
        success = recovered is not None and all((recovered[i] - S_real[i]) % q == 0 for i in range(n))
        elapsed = end - start
        print(f"  → Success: {success}, Time: {elapsed:.2f} seconds\n")
        results.append({
            'n': n,
            'q': q,
            'm': m,
            'success': success,
            'time_sec': elapsed
        })

    return results

if __name__ == "__main__":
    parameter_sets = [
    (10, 65537, 15)
    ]

    results = benchmark_lwe_babai(parameter_sets)
    print("\nSummary:")
    for r in results:
        print(f"n={r['n']}, q={r['q']}, m={r['m']} → Success={r['success']} | Time={r['time_sec']:.5f} s")
