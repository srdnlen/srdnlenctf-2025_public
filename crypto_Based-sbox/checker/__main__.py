from sage.all import *
from pwn import process, remote
from functools import reduce
from operator import mul
import os, sys, itertools, time, xoflib, subprocess


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
        start, end = start or 0, end or self._rounds
        assert len(pt) == 2
        l, r = pt
        for i in range(start, end):
            l, r = r, self._f(l, r, self._round_keys[i])
        ct = (l, r)
        return ct
    
    def decrypt_block(self, ct: tuple, start=None, end=None):
        start, end = start or 0, end or self._rounds
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


def xl(R, polys, verbose=False):
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
            if verbose:
                print(f"{len(seq)} < {len(seq.monomials())}")
            continue
        if verbose:
            print(f"{len(seq)} >= {len(seq.monomials())}")
        tick = time.time()
        M, v = seq.coefficients_monomials(sparse=False)
        tock = time.time()
        if verbose:
            print(f"Elapsed time: {tock - tick:.2f}s (coefficients_monomials)")
        tick = time.time()
        if M.nrows() > 200:
            if not os.path.exists("echelonize"):
                raise FileNotFoundError("echelonize binary not found: compile it with g++ -Ofast -funroll-loops -o echelonize echelonize.cpp -lntl")
            write_matrix(open("matrix.bin", "wb"), M)
            subprocess.run(["./echelonize", "matrix.bin"], check=True)  # compile with g++ -Ofast -funroll-loops -o echelonize echelonize.cpp -lntl
            M = read_matrix(open("matrix.bin", "rb"))
            os.remove("matrix.bin")
        else:
            M.echelonize()
        tock = time.time()
        if verbose:
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
        roots0 = xl(R0, [R0(poly.subs({X: x})) for poly in polys], verbose=verbose)
        roots.extend(root + [x] for root in roots0)
    return roots


if len(sys.argv) == 1:
    print("Defaulting to local mode with `process`")
    io = process(["sage", "--python", "server.py"])
else:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    print(f"Connecting to {host}:{port}...")
    io = remote(host, port)

pt = (  # ChatGPT cooked a story for us
    "Once upon a time, after linear and differential cryptanalysis had revolutionized the cryptographic landscape, "
    "and before Rijndael was selected as the Advanced Encryption Standard (AES), the field of cryptography was in a unique state of flux. "
    "New cryptanalytic methods exposed vulnerabilities in many established ciphers, casting doubt on the long-term security of systems "
    "once thought to be invulnerable. In response, the U.S. National Institute of Standards and Technology (NIST) "
    "launched a competition to find a successor to the aging DES. In 2000, Rijndael was chosen, setting a new standard for secure encryption. "
    "But even as AES became widely adopted, new challenges, like quantum computing, loomed on the horizon."
).encode()
pt_enc = bytes.fromhex(io.recvline(False).decode())
assert len(pt_enc) % 16 == 0

xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
pt += bytes([16 - len(pt) % 16] * (16 - len(pt) % 16))  # PKCS#7 padding
assert len(pt) == len(pt_enc) - 16

pts, cts = [], []
for i in range(0, len(pt), 16):
    iv = pt_enc[i:i + 16]
    x = xor(iv, pt[i:i + 16])
    y = pt_enc[i + 16:i + 32]
    pts.append((F.from_bytes(x[:8], "big"), F.from_bytes(x[8:], "big")))
    cts.append((F.from_bytes(y[:8], "big"), F.from_bytes(y[8:], "big")))

R = PolynomialRing(F, [f"k_{i}" for i in range(rounds)], order="lex")
round_keys = list(R.gens())

cipher = FeistelGF(round_keys, rounds=rounds)

polys = []
for pt, ct in zip(pts, cts):
    mid_start = cipher.encrypt_block(pt, end=rounds // 2)
    mid_end = cipher.decrypt_block(ct, start=rounds // 2)
    for i in range(2):
        num_start, den_start = mid_start[i].numerator(), mid_start[i].denominator()
        num_end, den_end = mid_end[i].numerator(), mid_end[i].denominator()
        poly = num_start * den_end - num_end * den_start
        polys.append(poly)

print("Starting XL... (this may take a while)")
tick = time.time()
roots = xl(R, polys, verbose=True)
tock = time.time()
print(f"Elapsed time: {tock - tick:.2f}s")

keys = set()
for root in roots:
    shares = []
    for i in range(rounds):
        x = root[i].to_bytes()
        assert len(x) == 9 and x.startswith(b"\x00")
        share = x[1:]
        shares.append(share)
    key = reduce(xor, shares)
    share_xof = xoflib.shake256(key)
    if all(share_xof.read(8) == share for share in shares[:-1]):
        keys.add(key)
assert len(keys) == 1
key = keys.pop()

io.sendlineafter(b"guess: ", key.hex().encode())

try:
    io.interactive()
except (EOFError, KeyboardInterrupt):
    pass
io.close()
