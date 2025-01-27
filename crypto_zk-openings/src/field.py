from sage.all import GF, PolynomialRing
from py_ecc.optimized_bn128 import curve_order as p


F = GF(p)
g = F(2)
while g**((p - 1) // 2) == 1:
    g += 1

n = 32
omega = g**((p - 1) // n)
assert omega**n == 1 and omega**(n // 2) != 1
H = tuple(omega**i for i in range(n))

P = PolynomialRing(F, 'X')
X = P.gen()

Z_H = X**n - 1
assert all(Z_H(H[i]) == 0 for i in range(n))


def ntt(points: "list[int]") -> "list[int]":
    """ DFT as of Cooley-Tukey algorithm """
    global F, n, H
    assert len(points) == n
    points = list(map(F, points))


    def bit_reverse(x: int, n: int) -> int:
        """ Reverse the bits of x, assuming it is represented with n bits """
        y = 0
        for _ in range(n):
            y = (y << 1) | (x & 1)
            x >>= 1
        return y


    for i in range(n):
        j = bit_reverse(i, n.bit_length() - 1)
        if j <= i:
            continue
        points[i], points[j] = points[j], points[i]
    
    m = 1
    for _ in range(n.bit_length() - 1):
        w_m = H[(n // (2 * m)) % n]
        for k in range(0, n, 2 * m):
            w = F(1)
            for j in range(m):
                t = w * points[k + j + m]
                points[k + j + m] = points[k + j] - t
                points[k + j] += t
                w *= w_m
        m *= 2
    return points


def intt(points: "list[int]") -> "list[int]":
    """ INV-DFT as of Cooley-Tukey algorithm """
    global F, p, n
    points = ntt(points)
    n_inv = F(n).inverse()
    return [n_inv * points[0]] + [n_inv * point for point in reversed(points[1:])]


evals = [F.random_element() for _ in range(n)]
assert intt(ntt(evals)) == evals
poly = P(intt(evals))
assert all(poly(H[i]) == evals[i] for i in range(n))
del evals, poly

__all__ = ['F', 'n', 'H', 'fft', 'ifft', 'P', 'X', 'Z_H', 'omega', 'g']
