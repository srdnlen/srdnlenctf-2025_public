from typing import Generator
from field import p, n, H, P, Z_H, intt
from kzg import point_to_bytes, point_from_bytes, KZG
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os, secrets, hashlib, json


assert n in AES.key_size
key = os.urandom(n)
evals = list(key)
poly = P(intt(evals))
assert all(poly(H[i]) == key[i] for i in range(n))


def lcg(m: int, a: int, c: int, x: int) -> "Generator[int, None, None]":
    """ Linear Congruential Generator """
    while True:
        x = (a * x + c) % m
        yield x


a, c, x = [secrets.randbelow(p) for _ in range(3)]
rng = lcg(p, a, c, x)

k = 20
hiding_poly = P([next(rng) for _ in range(k)])
hidden_poly = poly + hiding_poly * Z_H
assert all(hidden_poly(H[i]) == key[i] for i in range(n))

oracle = lambda s: int.from_bytes(hashlib.sha256(s.encode()).digest(), "big") % p
kzg = KZG(d=n + k, srs_path="srs.bin")
xs = [oracle(f"zk-Openings-{i}!") for i in range(k)]
assert all(x not in H for x in xs) and len(set(xs)) == k
claim, proof = kzg.open(hidden_poly, xs, verify=True)
cm_poly, cm_hs = proof
proof = (point_to_bytes(cm_poly).hex(), list(map(lambda x: point_to_bytes(x).hex(), cm_hs)))

with open("opening.json", "w") as f:
    json.dump({"claim": claim, "proof": proof}, f, indent=4)

flag = os.getenv("FLAG", "srdnlen{this_is_a_fake_flag}").encode()
flag_enc = AES.new(key, AES.MODE_ECB).encrypt(pad(flag, AES.block_size))

with open("flag.enc", "wb") as f:
    f.write(flag_enc)
