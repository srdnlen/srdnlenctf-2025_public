from sage.all import *
from typing import Generator
from field import p, F, n, omega, H, P, Z_H, intt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os, secrets, hashlib, json, time, itertools


assert n in AES.key_size
_key = os.urandom(n)
evals = list(_key)
poly = P(intt(evals))
assert all(poly(H[i]) == _key[i] for i in range(n))


def lcg(m: int, a: int, c: int, x: int) -> "Generator[int, None, None]":
    """ Linear Congruential Generator """
    while True:
        x = (a * x + c) % m
        yield x


_a, _c, _x = [secrets.randbelow(p) for _ in range(3)]
rng = lcg(p, _a, _c, _x)

k = 20
_hiding_poly = P([next(rng) for _ in range(k)])
hidden_poly = poly + _hiding_poly * Z_H
assert all(hidden_poly(H[i]) == _key[i] for i in range(n))

oracle = lambda s: int.from_bytes(hashlib.sha256(s.encode()).digest(), "big") % p
xs = [oracle(f"zk-Openings-{i}!") for i in range(k)]
assert all(x not in H for x in xs) and len(set(xs)) == k
claim = (xs, [hidden_poly(x) for x in xs])


def lagrange_evaluations(x: int) -> "list[int]":
    """ Evaluate the Lagrange polynomials of H at x """
    global F, n, omega, H
    x = F(x)
    
    x_pow_n = x**n
    if x_pow_n == 1:
        assert x in H
        i = H.index(x)
        return list(map(F, [0] * i + [1] + [0] * (n - i - 1)))
    
    evals = []
    l = (x_pow_n - 1) // n
    for i in range(n):
        evals.append(l // (x - H[i]))
        l *= omega
    return evals


def lagrange_polynomials(xs: "list[int]", ring=P) -> "list[list[int]]":
    """ Compute the Lagrange polynomials from the given points """
    assert len(set(xs)) == len(xs)
    X = ring.gen()

    polys = []
    for i in range(len(xs)):
        num, den = ring(1), ring(1)
        for j, x in enumerate(xs):
            if i == j:
                continue
            num *= X - x
            den *= xs[i] - x
        poly = num // den
        
        assert all(poly(x) == int(x == xs[i]) for x in xs)
        polys.append(poly)
    return polys


R = PolynomialRing(F, [f"k_{i}" for i in range(n)])
key = R.gens()
bounds = [256] * n

xs, ys = claim
# poly(x_i) for all x_i
poly_evals = [sum(k * l for k, l in zip(key, lagrange_evaluations(x))) for x in xs]
# hiding_poly(x_i) for all x_i
hiding_poly_evals = [(y - poly_eval) // Z_H(x) for x, y, poly_eval in zip(xs, ys, poly_evals)]

RX = PolynomialRing(R, "X")
# hiding_poly = next(rng) + next(rng) * X + ... + next(rng) * X^(k - 1)
hiding_poly = sum(y * l for y, l in zip(hiding_poly_evals, lagrange_polynomials(xs, ring=RX)))
# [next(rng), next(rng), ..., next(rng)]
lcg_outs = list(hiding_poly)

assert all(lcg_outs[i](*_key) == _hiding_poly[i] for i in range(k))

############################################
# orthogonality check

# b_{i + 2} - b_{i + 1} = a * (b_{i + 1} - b_i) for all i in [k - 2]
polys = [lcg_outs[i + 1] - lcg_outs[i] for i in range(k - 1)]

M, mons = Sequence(polys).coefficients_monomials(sparse=False)
assert M.left_nullity() == 0  # I suppose an orthogonal attack is not possible (or is it?)

############################################
# groebner basis check

# XXX take a smaller instance

p = 8380417  # dilithium prime
F = GF(p)
n = 8
assert (p - 1) % n == 0
omega = F.multiplicative_generator()**((p - 1) // n)
H = tuple(omega**i for i in range(n))

P = PolynomialRing(F, 'X')
X = P.gen()

Z_H = X**n - 1
assert all(Z_H(H[i]) == 0 for i in range(n))

_key = os.urandom(n)
evals = [(H[i], _key[i]) for i in range(n)]
poly = P.lagrange_polynomial(evals)
assert all(poly(H[i]) == _key[i] for i in range(n))

_a, _c, _x = [secrets.randbelow(p) for _ in range(3)]
rng = lcg(p, _a, _c, _x)

k = 12  # smaller instance
_hiding_poly = P([next(rng) for _ in range(k)])
hidden_poly = poly + _hiding_poly * Z_H
assert all(hidden_poly(H[i]) == _key[i] for i in range(n))

oracle = lambda s: int.from_bytes(hashlib.sha256(s.encode()).digest(), "big") % p
xs = [oracle(f"zk-Openings-{i}!") for i in range(k)]
assert all(x not in H for x in xs) and len(set(xs)) == k
claim = (xs, [hidden_poly(x) for x in xs])

R = PolynomialRing(F, [f"k_{i}" for i in range(n)])
key = R.gens()
bounds = [256] * n

xs, ys = claim
# poly(x_i) for all x_i
poly_evals = [sum(k * l for k, l in zip(key, lagrange_evaluations(x))) for x in xs]
# hiding_poly(x_i) for all x_i
hiding_poly_evals = [(y - poly_eval) // Z_H(x) for x, y, poly_eval in zip(xs, ys, poly_evals)]

RX = PolynomialRing(R, "X")
# hiding_poly = next(rng) + next(rng) * X + ... + next(rng) * X^(k - 1)
hiding_poly = sum(y * l for y, l in zip(hiding_poly_evals, lagrange_polynomials(xs, ring=RX)))
# [next(rng), next(rng), ..., next(rng)]
lcg_outs = list(hiding_poly)

assert all(lcg_outs[i](*_key) == _hiding_poly[i] for i in range(k))

polys = []
for i, j in itertools.combinations(range(len(lcg_outs) - 2), 2):
    xi_0, xi_1, xi_2 = lcg_outs[i:i + 3]
    xj_0, xj_1, xj_2 = lcg_outs[j:j + 3]
    polys.append((xi_2 - xi_1) * (xj_1 - xj_0) - (xi_1 - xi_0) * (xj_2 - xj_1))

I = R.ideal(polys)
tick = time.time()
G = I.groebner_basis()
tock = time.time()
