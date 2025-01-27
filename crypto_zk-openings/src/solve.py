from sage.all import *
from field import p, F, n, omega, H, P, Z_H
from lbc_toolkit import flatter
from Crypto.Cipher import AES
import json, itertools, time, random


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


opening = json.load(open("opening.json", "r"))
claim, proof = opening["claim"], opening["proof"]
flag_enc = open("flag.enc", "rb").read()

# deg(poly) = n - 1, deg(hiding_poly) = k - 1, deg(Z_H) = n
# hidden_poly = poly + hiding_poly * Z_H
# hidden_poly(x) = poly(x) + hiding_poly(x) * Z_H(x) for all x in F \ H
# poly(x) = k_0 * L_0(x) + k_1 * L_1(x) + ... + k_{n-1} * L_{n-1}(x) for all x in F
# 0 <= k_i < 256 and L_i(omega^i) = 1, L_i(omega^j) = 0 for j != i and i, j in [n]

# We have k points (x_i, y_i) where y_i = hidden_poly(x_i) and x_i not in H, thus
# (y_i - poly(x_i)) / Z_H(x_i) = hiding_poly(x_i) for all i in [k]
# We can express hiding_poly(x_i) as a linear combination of k_j for all i in [k].

# By Lagrange interpolation on the points (x_i, hiding_poly(x_i)), we get a polynomial of degree k - 1,
# with coefficients that are a linear combination of k_j: let b_0, b_1, ..., b_{k-1} be the coefficients of the hiding_poly

# Since every coefficient of the hiding_poly is an output of the LCG, the following holds:
# b_{i + 2} - b_{i + 1} = a * (b_{i + 1} - b_i) for all i in [k - 2]
# and thus:
# (b_{i + 2} - b_{i + 1}) * (b_{j + 1} - b_j) = (b_{i + 1} - b_i) * (b_{j + 2} - b_{j + 1}), for all i, j in [k - 2]

# The above equations are quadratic with terms k_i * k_j for all i, j and k_i for all i
# By linearizing the above equations, we get a system of linear equations in k_i * k_j, k_i
# with bounds 0 <= k_i * k_j < 256^2 and 0 <= k_i < 256

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

polys = []
for i, j in itertools.combinations(range(len(lcg_outs) - 2), 2):
    xi_0, xi_1, xi_2 = lcg_outs[i:i + 3]
    xj_0, xj_1, xj_2 = lcg_outs[j:j + 3]
    polys.append((xi_2 - xi_1) * (xj_1 - xj_0) - (xi_1 - xi_0) * (xj_2 - xj_1))

M, mons = Sequence(polys).coefficients_monomials(sparse=False)
assert 1 in mons
M, rhs = M[:, :-1], -M.column(-1)
print(f"Solving {M.dimensions()} system")
s = M.solve_right(rhs)
print(f"Computing right kernel")
K = M.right_kernel_matrix()

for i, k in enumerate(K):
    s -= s[i] * k
assert all(x == 0 for x in s[:K.nrows()])
assert M * s == rhs

# Drop the identity block
s = Matrix(F, [s[K.nrows():]])
K = K[:, K.nrows():]

W = 2**256
# k = K.ncols()  # full kernel (slower)
k = 128  # kernel subset (faster)
assert k >= n
# by the monomial order, we want to keep the last n columns since they correspond to the linear terms
ids = list(random.sample(range(K.ncols() - n), k - n)) + list(range(K.ncols() - n, K.ncols()))
L = Matrix.block(ZZ, [
    [1, K[:, ids], 0],
    [0, s[:, ids], W],
    [0, p,         0],
])

print(f"Reducing {L.dimensions()} matrix")
tick = time.time()
L = flatter(L)
tock = time.time()
print(f"Reduction took {tock - tick:.2f}s")  # on my machine it took 1320s = 22min with the full kernel

for row in L:
    row *= sign(row[-1])
    if row[-1] == W and all(0 <= int(elem) <= mon(*bounds) for elem, mon in zip(row[:-1], mons)):
        key_guess = bytes(map(int, row[-(n + 1):-1]))
        flag = AES.new(key_guess, AES.MODE_ECB).decrypt(flag_enc)
        print(flag)
