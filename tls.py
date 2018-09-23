from abc import ABC


class TLS(ABC):
    code = tuple()

    def __str__(self):
        return self.__class__.__name__.replace('_', '.')

    def __bytes__(self):
        return b''.join(self.code)

    def __add__(self, other):
        return self.__bytes__() + other

    def __radd__(self, other):
        return other + self.__bytes__()

    def __eq__(self, other):
        return self.__bytes__() == other

    def __gt__(self, other):
        return self.code > other.code

    def __lt__(self, other):
        return other.code > self.code

    def __ge__(self, other):
        return self.code >= other.code

    def __le__(self, other):
        return other.code >= self.code

    @classmethod
    def get_by_code(cls, code):
        g = globals()
        found = next(filter(lambda x: getattr(g[x], 'code', None) == code, g))
        return g[found]()


class TLSV1(TLS):
    code = (b'\x03', b'\x01')


class TLSV1_1(TLS):
    code = (b'\x03', b'\x02')


class TLSV1_2(TLS):
    code = (b'\x03', b'\x03')


class TLSV1_3(TLS):
    code = (b'\x03', b'\x04')
