import time
from sage.all import GF
import random

def arora_ge_attack(q, A, b, E):
    m = len(A)
    n = len(A[0])
    gf = GF(q)
    pr = gf[tuple(f"x{i}" for i in range(n))]
    gens = pr.gens()

    polys = []
    for i in range(m):
        p = 1
        inner = sum(A[i][j] * gens[j] for j in range(n))
        for e in E:
            p *= (b[i] - inner - e)
        polys.append(p)

    I = pr.ideal(polys)
    G = I.groebner_basis()

    s = []
    for p in G:
        if p.nvariables() == 1 and p.degree() == 1:
            root = -p.constant_coefficient()
            s.append(int(root))

    if len(s) == n:
        return s
    else:
        return None


def benchmark_arora_ge(parameter_sets, E=[-1, 0, 1]):
    """
    parameter_sets: list of tuples (n, q, m)
    """
    results = []

    for (n, q, m) in parameter_sets:
        print(f"Running for n={n}, q={q}, m={m}")
        s_real = [random.randint(0, q - 1) for _ in range(n)]
        A = [[random.randint(0, q - 1) for _ in range(n)] for _ in range(m)]
        b = []
        for i in range(m):
            noise = random.choice(E)
            inner = sum(A[i][j] * s_real[j] for j in range(n)) % q
            b.append((inner + noise) % q)

        start = time.time()
        recovered = arora_ge_attack(q, A, b, E)
        end = time.time()

        success = (recovered is not None and len(recovered) == n and all((recovered[i] - s_real[i]) % q == 0 for i in range(n)))
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
        (15, 65537, 15*10),
        (15, 65537, 15*8),
        (15, 65537, 15*4),
        (15, 65537, 15*2)
    ]
    
    """
    n = 15
    q = 65537
    parameter_sets = []
    for i in range(n*50,n+1,-n):
        parameter_sets.append((n,q,i))
    """
    results = benchmark_arora_ge(parameter_sets)
    print("\nSummary:")
    for r in results:
        print(f"n={r['n']}, q={r['q']}, m={r['m']} → Success={r['success']} | Time={r['time_sec']:.5f} s")
