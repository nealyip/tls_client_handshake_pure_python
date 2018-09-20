from abc import ABC

from cryptography.hazmat.primitives.asymmetric import ec


class ECCurves(ABC):
    curve = None

    @classmethod
    def get_by_code(cls, code):
        g = globals()
        found = next(filter(lambda x: getattr(g[x], 'code', None) == code, g))
        return g[found]()


class SECP256R1(ECCurves):
    code = b'\x00\x17'
    name = 'secp256r1'

    curve = ec.SECP256R1()


class SECP384R1(ECCurves):
    code = b'\x00\x18'
    name = 'secp384r1'

    curve = ec.SECP384R1()


class X25519(ECCurves):
    code = b'\x00\x1d'
    name = 'x25519'
