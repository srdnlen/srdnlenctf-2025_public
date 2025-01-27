from sage.all import *
import time


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


print("Starting test")

start = time.time()

round_keys_val = [F.random_element() for _ in range(rounds)]
cipher = FeistelGF(round_keys_val, rounds=rounds)
pt = (F.random_element(), F.random_element())
ct = cipher.encrypt_block(pt)
pt_ = cipher.decrypt_block(ct)
assert pt == pt_

pairs = []
for _ in range(46):  # arbitrary number of pairs for testing purposes
    pt = (F.random_element(), F.random_element())
    ct = cipher.encrypt_block(pt)
    pairs.append((pt, ct))

R = PolynomialRing(F, [f"k{i}" for i in range(rounds)])
round_keys = list(R.gens())

cipher = FeistelGF(round_keys, rounds=rounds)

polys = []
for pt, ct in pairs:
    mid_start = cipher.encrypt_block(pt, end=rounds // 2)
    mid_end = cipher.decrypt_block(ct, start=rounds // 2)
    assert all(mid_start[i](*round_keys_val) == mid_end[i](*round_keys_val) for i in range(2))
    for i in range(2):
        num_start, den_start = mid_start[i].numerator(), mid_start[i].denominator()
        num_end, den_end = mid_end[i].numerator(), mid_end[i].denominator()
        poly = num_start * den_end - num_end * den_start
        polys.append(poly)

I = R.ideal(polys)
# G = I.groebner_basis("magma:GroebnerBasis")  # magma breaks it in 15s on a i5 of 12th gen (unplugged)
G = I.groebner_basis()  # more than 300s on a i5 of 12th gen
print(f"Elapsed time: {time.time() - start:.2f}s")
assert all(g.degree() == 1 for g in G)
guess = [-g.constant_coefficient() for g in G]
assert set(guess) == set(round_keys_val)  # I'm not sure of the monomial order, so I'm checking the set
