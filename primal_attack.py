import time
from sage.all import *

def generate_key(n=32, q=4093, p=257, samples=64):
    delta = q // p
    R = Integers(q)
    s = vector(ZZ, [randrange(-5, 6) for _ in range(n)])
    A_list = []
    b_list = []
    for _ in range(samples):
        a = vector(ZZ, [randint(0, q - 1) for _ in range(n)])
        e = randint(-3, 3)  
        b = int((a * s + e) % q)
        A_list.append(a)
        b_list.append(b)
    
    return s, A_list, b_list, q

def recover_error(A_list, b_list, q):
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
    err = L[-1]
    if err[-1] < 0:
        err = [-e for e in err]

    if err[-1] != q or not all(abs(e) <= 3 for e in err[:-1]):
        raise ValueError("Error vector recovery failed")

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

def benchmark_primal_attack(parameter_sets):
    results = []
    for (n, q, m) in parameter_sets:
        print(f"[*] Testing n={n}, q={q}, m={m}")
        try:
            t0 = time.time()
            s_real, A_list, b_list, q = generate_key(n=n, q=q, samples=m)
            t1 = time.time()
            error_vector = recover_error(A_list, b_list, q)
            t2 = time.time()
            s_recovered = recover_secret(A_list, b_list, q, error_vector)
            t3 = time.time()

            success = vector(ZZ, s_real) % q == vector(ZZ, s_recovered) % q
            results.append({
                "n": n,
                "q": q,
                "m": m,
                "success": success,
                "gen_time": t1 - t0,
                "error_recovery_time": t2 - t1,
                "secret_recovery_time": t3 - t2,
                "total_time": t3 - t0
            })
            print(f"  → Success: {success} | Total time: {t3 - t0:.2f}s\n")
        except Exception as e:
            print(f"  → Failed: {e}\n")
            results.append({
                "n": n,
                "q": q,
                "m": m,
                "success": False,
                "error": str(e)
            })
    return results

if __name__ == "__main__":
    parameter_sets = [
    (60, 65537, 270),
    (60, 65537, 300),
    (60, 65537, 360)
    ]
    results = benchmark_primal_attack(parameter_sets)
    print("\nSummary:")
    for r in results:
        if r["success"]:
            print(f"n={r['n']}, q={r['q']}, m={r['m']} → ✓ Success | Time: {r['total_time']:.2f}s")
        else:
            print(f"n={r['n']}, q={r['q']}, m={r['m']} → ✗ Failure | Error: {r.get('error', 'Unknown')}")
