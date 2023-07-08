from abc import ABC, abstractmethod

from cryptography import utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import Hash, MD5, SHA1, SHA256, SHA384, SHA512, HashAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec


# @utils.register_interface(HashAlgorithm)
class MD5SHA1(SHA1):
    name = "md5-sha1"
    digest_size = 36
    block_size = 64


class SignatureAlgorithm(ABC):
    code = b''

    def __init__(self, public_key):
        self.public_key = public_key

    @abstractmethod
    def verify(self, signature, content):
        pass

    @abstractmethod
    def sign(self, content):
        pass

    @classmethod
    def get_by_code(cls, code, public_key):
        g = globals()
        found = next(filter(lambda x: getattr(g[x], 'code', None) == code, g))
        return g[found](public_key)


class RsaPkcs1Md5Sha1(SignatureAlgorithm):
    code = b''

    def verify(self, signature, content):
        self.public_key.verify(signature, content, padding.PKCS1v15(), MD5SHA1())

    def sign(self, content):
        pass


class RsaPkcs1Sha1(SignatureAlgorithm):
    code = b'\x02\x01'

    def verify(self, signature, content):
        self.public_key.verify(signature, content, padding.PKCS1v15(), SHA1())

    def sign(self, content):
        pass


class RsaPkcs1Sha256(SignatureAlgorithm):
    code = b'\x04\x01'

    def verify(self, signature, content):
        self.public_key.verify(signature, content, padding.PKCS1v15(), SHA256())

    def sign(self, content):
        pass


class RsaPssRsaeSha256(SignatureAlgorithm):
    code = b'\x08\x09'

    def verify(self, signature, content):
        self.public_key.verify(signature, content, padding.PSS(
            mgf=padding.MGF1(SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), SHA256())

    def sign(self, content):
        pass


class RsaPssRsaeSha384(SignatureAlgorithm):
    code = b'\x08\x05'

    def verify(self, signature, content):
        self.public_key.verify(signature, content, padding.PSS(
            mgf=padding.MGF1(SHA384()),
            salt_length=padding.PSS.MAX_LENGTH
        ), SHA384())

    def sign(self, content):
        pass


class EcdsaSecp256r1Sha256(SignatureAlgorithm):
    code = b'\x04\x03'

    def verify(self, signature, content):
        self.public_key.verify(signature, content, ec.ECDSA(SHA256()))

    def sign(self, content):
        pass


class EcdsaSecp384r1Sha384(SignatureAlgorithm):
    code = b'\x05\x03'

    def verify(self, signature, content):
        self.public_key.verify(signature, content, ec.ECDSA(SHA384()))

    def sign(self, content):
        pass

# b'\x06\x01'  # rsa_pkcs1_sha512
# b'\x06\x02'  # Signature Algorithm: SHA512 DSA (0x0602)
# b'\x06\x03'  # Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)
# b'\x05\x01'  # rsa_pkcs1_sha384
# b'\x05\x02'  # Signature Algorithm: SHA384 DSA (0x0502)
# b'\x05\x03'  # ecdsa_secp384r1_sha384
# b'\x04\x01'  # rsa_pkcs1_sha256
# b'\x04\x02'  # Signature Algorithm: SHA256 DSA (0x0402)
# b'\x04\x03'  # ecdsa_secp256r1_sha256
# b'\x03\x01'  # Signature Algorithm: SHA224 RSA (0x0301)
# b'\x03\x02'  # Signature Algorithm: SHA224 DSA (0x0302)
# b'\x03\x03'  # Signature Algorithm: SHA224 ECDSA (0x0303)
# b'\x02\x01', # rsa_pkcs1_sha1
# b'\x02\x02', # Signature Algorithm: SHA1 DSA (0x0202)
# b'\x02\x03', # Signature Algorithm: ecdsa_sha1 (0x0203)
# b'\x08\x04'  # rsa_pss_rsae_sha256
# b'\x08\x05'  # rsa_pss_rsae_sha384
# b'\x08\x06'  # rsa_pss_rsae_sha512
# b'\x08\x07'  # ed25519
# b'\x08\x08'  # ed448
# b'\x08\x09'  # rsa_pss_pss_sha256
# b'\x08\x0a'  # rsa_pss_pss_sha384
# b'\x08\x0b'  # rsa_pss_pss_sha512
