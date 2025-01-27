from py_ecc.optimized_bn128 import (
    curve_order, Z1, G1, Z2, G2, pairing, 
    normalize, add, neg, multiply,
    FQ, FQ2, FQ12, 
)
from field import P, X
import os, secrets, math

FQ_BYTES = int(math.ceil(math.log2(curve_order) / 8))


def point_to_bytes(point: "tuple[FQ, FQ, FQ]") -> bytes:
    if not isinstance(point, tuple):
        raise TypeError(f"Point serialization is not defined for: {type(p)}")
    if len(point) == 3:
        point = normalize(point)
    if len(point) != 2:
        raise ValueError(f"Invalid number of coordinates: {len(point)}")
    
    if all(isinstance(elem, FQ) for elem in point):
        x, y = map(int, point)
        return x.to_bytes(FQ_BYTES, "big") + y.to_bytes(FQ_BYTES, "big")
    if all(isinstance(elem, FQ2) for elem in point):
        (x0, x1), (y0, y1) = map(lambda x: tuple(map(int, x.coeffs)), point)
        return b"".join(map(lambda x: x.to_bytes(FQ_BYTES, "big"), (x0, x1, y0, y1)))
    raise TypeError(f"Point serialization is not defined for: ({type(point[0])}, {type(point[1])})")


def point_from_bytes(data: bytes) -> "tuple[FQ, FQ, FQ]":
    if not isinstance(data, bytes):
        raise TypeError(f"Point deserialization is not defined for: {type(data)}")
    if len(data) != 2 * FQ_BYTES and len(data) != 4 * FQ_BYTES:
        raise ValueError(f"Invalid number of bytes: {len(data)}")
    
    from py_ecc.optimized_bn128 import is_on_curve, b, b2

    if len(data) == 2 * FQ_BYTES:
        if data == b"\x00" * 2 * FQ_BYTES:
            return Z1
        x, y = int.from_bytes(data[:FQ_BYTES], "big"), int.from_bytes(data[FQ_BYTES:], "big")
        point = (FQ(x), FQ(y), FQ.one())
        if not is_on_curve(point, b):
            raise ValueError(f"Point is not on the curve G1: {point}")
        return point
    if data == b"\x00" * 4 * FQ_BYTES:
        return Z2
    x0, x1, y0, y1 = [int.from_bytes(data[i:i + FQ_BYTES], "big") for i in range(0, 4 * FQ_BYTES, FQ_BYTES)]
    point = (FQ2((x0, x1)), FQ2((y0, y1)), FQ2.one())
    if not is_on_curve(point, b2):
        raise ValueError(f"Point is not on the curve G2: {point}")
    return point


class KZG:
    def __init__(self, d=None, srs_path=None) -> None:
        """ Initialize the KZG scheme with a degree d and/or an SRS file path """
        if srs_path and isinstance(srs_path, str) and os.path.exists(srs_path):
            self.import_srs(srs_path)
        elif d and isinstance(d, int):
            self.gen(d, filename=srs_path)
        else:
            raise ValueError("Invalid arguments: either provide a degree d and/or a filename to import the SRS")

    def gen(self, d: int, filename=None) -> None:
        """ Generates the structured reference string (SRS) for the KZG scheme and saves it to a file if a filename is provided """
        self.d = d
        x = secrets.randbelow(curve_order)
        
        x_, self.srs = x, [G1]
        for _ in range(d):
            self.srs.append(multiply(G1, x_))
            x_ *= x
        self.srs.extend([G2, multiply(G2, x)])

        del x, x_  # remove the secret key from memory

        if filename and isinstance(filename, str):
            if os.path.dirname(filename) and not os.path.exists(os.path.dirname(filename)):
                os.makedirs(os.path.dirname(filename))
            with open(filename, "wb") as f:
                f.write(b"".join(map(point_to_bytes, self.srs)))
        
    def commit(self, poly: "list[int]") -> "tuple[FQ, FQ, FQ]":
        """ Commit to a polynomial of degree <= d using the SRS """
        
        if self.srs is None:
            raise ValueError("SRS is not generated")
        
        poly = list(poly) or [0]
        poly = list(map(int, poly))
        
        if len(poly) - 1 > self.d:
            raise ValueError(f"Polynomial degree {len(poly) - 1} exceeds SRS upper bound degree {self.d}")

        cm = Z1
        for i in range(len(poly)):
            cm = add(cm, multiply(self.srs[i], poly[i]))
        return cm

    def open(
            self, poly: "list[int]", xs: "list[int]", verify=False
        ) -> "tuple[tuple[list[int], list[int]], tuple[tuple[FQ, FQ, FQ], list[tuple[FQ, FQ, FQ]]]]":
        """ Open a polynomial at the given points """
        poly = list(poly) or [0]
        poly = list(map(int, poly))
        xs = list(map(int, xs))

        cm_poly = self.commit(poly)

        poly = P(poly)
        ys = [int(poly(x)) for x in xs]
        
        hs = []
        for x, y in zip(xs, ys):
            h = (poly - y) // (X - x)
            hs.append(h)
        
        cm_hs = [self.commit(h) for h in hs]

        if verify:
            r = secrets.randbelow(curve_order)
            cm_batch = Z1
            for y in reversed(ys):
                cm_batch = add(
                    multiply(cm_batch, r),
                    add(cm_poly, neg(multiply(G1, y)))
                )
            
            lhs1 = cm_batch
            for i, x, cm_h in zip(range(len(xs)), xs, cm_hs):
                lhs1 = add(
                    lhs1,
                    multiply(cm_h, (pow(r, i, curve_order) * x) % curve_order)
                )
            rhs1 = Z1
            for i, cm_h in enumerate(cm_hs):
                rhs1 = add(
                    rhs1,
                    neg(multiply(cm_h, pow(r, i, curve_order)))
                )
            lhs2, rhs2 = self.srs[-2:]
            assert pairing(lhs2, lhs1) * pairing(rhs2, rhs1) == FQ12.one()
        
        return (xs, ys), (cm_poly, cm_hs)
    
    def import_srs(self, filename: str) -> None:
        """ Import the SRS from a file """
        if not isinstance(filename, str):
            raise TypeError(f"Import of SRS is not defined for: {type(filename)}")
        
        with open(filename, "rb") as f:
            data = f.read()
        
        if len(data) % (2 * FQ_BYTES) != 0 or len(data) < 2 * 4 * FQ_BYTES:
            raise ValueError(f"Invalid number of bytes: {len(data)}")

        data_G1 = data[:-2 * 4 * FQ_BYTES]
        data_G2 = data[-2 * 4 * FQ_BYTES:]

        self.srs = [point_from_bytes(data_G1[i:i + 2 * FQ_BYTES]) for i in range(0, len(data_G1), 2 * FQ_BYTES)]
        self.srs.extend([point_from_bytes(data_G2[i:i + 4 * FQ_BYTES]) for i in range(0, len(data_G2), 4 * FQ_BYTES)])
        self.d = len(self.srs) - 2


__all__ = ["point_to_bytes", "point_from_bytes", "KZG"]


if __name__ == "__main__":
    assert point_from_bytes(point_to_bytes(G1)) == G1
    assert point_from_bytes(point_to_bytes(G2)) == G2

    d = 2
    kzg = KZG(d=d)
    poly = P.random_element(d)
    xs = [secrets.randbelow(curve_order) for _ in range(d)]
    kzg.open(poly, xs, verify=True)
    del d, kzg, poly, xs
