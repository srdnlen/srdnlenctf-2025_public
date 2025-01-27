from sage.all import *
from functools import reduce
from operator import mul
from pwn import process, context
import tqdm, itertools, time, subprocess, signal


rounds = 7
F = GF(2**64, "a", list(map(int, reversed(f"{(1 << 64) | 0x1b:064b}"))))


def sbox(x, c=F.from_integer(0x01d_5b ^ 0x_15_ba5ed)):
    if x == 0:
        return c
    return (1 / x) + c


class FeistelGF:
    def __init__(self, round_keys: list, rounds=10) -> None:
        self._rounds = rounds
        self._round_keys = round_keys[:rounds]
        assert len(self._round_keys) == rounds
    
    @staticmethod
    def _f(l, r, key):
        return l + sbox(r + key)
    
    def encrypt_block(self, pt: tuple, start=None, end=None):
        if start is None:
            start = 0
        if end is None:
            end = self._rounds
        assert len(pt) == 2
        l, r = pt
        for i in range(start, end):
            l, r = r, self._f(l, r, self._round_keys[i])
        ct = (l, r)
        return ct
    
    def decrypt_block(self, ct: tuple, start=None, end=None):
        if start is None:
            start = 0
        if end is None:
            end = self._rounds
        assert len(ct) == 2
        l, r = ct
        for i in reversed(range(start, end)):
            l, r = self._f(r, l, self._round_keys[i]), l
        pt = (l, r)
        return pt


def read_matrix(f):
    global F
    nrows = int.from_bytes(f.read(8), "little")
    ncols = int.from_bytes(f.read(8), "little")
    M = Matrix(F, nrows, ncols)
    for i in range(nrows):
        for j in range(ncols):
            b = f.read(8)
            if any(b):
                M[i, j] = F.from_bytes(b, "little")
    return M


def write_matrix(f, M):
    f.write(int(M.nrows()).to_bytes(8, "little"))
    f.write(int(M.ncols()).to_bytes(8, "little"))
    for i in range(M.nrows()):
        for j in range(M.ncols()):
            f.write(M[i, j].to_bytes("little")[:-1])  # drop the padding zero byte


def xl(R, polys):
    if len(R.gens()) == 1:
        roots = set()
        for poly in polys:
            xs = poly.roots()
            for x, _ in xs:
                roots.add(x)
        return [[root] for root in roots]

    seq = Sequence([], universe=R)
    for j in range(len(R.gens()) + 1):
        mons = tuple(map(lambda x: reduce(mul, x) if x else 1, itertools.combinations(R.gens(), j)))
        for poly in polys:
            for mon in mons:
                seq.append(poly * mon)
        if len(seq) < len(seq.monomials()):
            print(f"{len(seq)} < {len(seq.monomials())}")
            continue
        print(f"{len(seq)} >= {len(seq.monomials())}")
        tick = time.time()
        M, v = seq.coefficients_monomials(sparse=False)
        tock = time.time()
        print(f"Elapsed time: {tock - tick:.2f}s (coefficients_monomials)")
        tick = time.time()
        if M.nrows() > 200:
            write_matrix(open("matrix.bin", "wb"), M)
            subprocess.run(["./echelonize", "matrix.bin"], check=True)  # compile with g++ -Ofast -funroll-loops -o echelonize echelonize.cpp -lntl
            M = read_matrix(open("matrix.bin", "rb"))
        else:
            M.echelonize()
        tock = time.time()
        print(f"Elapsed time: {tock - tick:.2f}s (echelonize)")
        for i in reversed(range(M.nrows())):
            poly = M[i] * v
            if poly.is_zero():
                continue
            if poly.is_univariate():
                break
        else:
            continue
        break
    else:
        raise ValueError("no univariate polynomial found")

    X, xs = poly.variable(), poly.univariate_polynomial().roots()
    roots = []
    for x, _ in xs:
        R0 = R.remove_var(X)
        roots0 = xl(R0, [R0(poly.subs({X: x})) for poly in polys])
        roots.extend(root + [x] for root in roots0)
    return roots


round_keys_val = [F.random_element() for _ in range(rounds)]
cipher = FeistelGF(round_keys_val, rounds=rounds)
pt = (F.random_element(), F.random_element())
ct = cipher.encrypt_block(pt)
pt_ = cipher.decrypt_block(ct)
assert pt == pt_

pairs = []
for _ in range(44):  # arbitrary number of pairs for testing purposes
    pt = (F.random_element(), F.random_element())
    ct = cipher.encrypt_block(pt)
    pairs.append((pt, ct))

R = PolynomialRing(F, [f"k{i}" for i in range(rounds)], order="lex")
round_keys = list(R.gens())

cipher = FeistelGF(round_keys, rounds=rounds)

polys = []
for pt, ct in tqdm.tqdm(pairs):
    mid_start = cipher.encrypt_block(pt, end=rounds // 2)
    mid_end = cipher.decrypt_block(ct, start=rounds // 2)
    assert all(mid_start[i](*round_keys_val) == mid_end[i](*round_keys_val) for i in range(2))
    for i in range(2):
        num_start, den_start = mid_start[i].numerator(), mid_start[i].denominator()
        num_end, den_end = mid_end[i].numerator(), mid_end[i].denominator()
        poly = num_start * den_end - num_end * den_start
        polys.append(poly)

tick = time.time()
roots = xl(R, polys)
tock = time.time()
print(f"Elapsed time: {tock - tick:.2f}s")
assert round_keys_val in roots
