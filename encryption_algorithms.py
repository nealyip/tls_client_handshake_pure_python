import os
from abc import ABC, abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

import tls


def hmac_sign(content, key, algorithm):
    h = HMAC(key, algorithm, backend=default_backend())
    h.update(content)
    return h.finalize()


def hmac_verify(content, signature, key, algorithm):
    h = HMAC(key, algorithm, backend=default_backend())
    h.update(content)
    h.verify(signature)


class EncryptionAlgorithm(ABC):
    @abstractmethod
    def encrypt(self, tls_version, key, iv, content, *, add=None, sign_key=None, hash_algorithm=None):
        pass

    @abstractmethod
    def decrypt(self, tls_version, key, iv, encrypted, *, add=None, sign_key=None, hash_algorithm=None):
        pass


class AES(EncryptionAlgorithm):

    def encrypt(self, tls_version, key, iv, content, *, add=None, sign_key=None, hash_algorithm=None):
        content_bytes_len = len(content).to_bytes(2, 'big')
        add += content_bytes_len
        signature = hmac_sign(add + content, sign_key, algorithm=hash_algorithm)
        iv = os.urandom(len(iv))  # Use a random iv, len is always 16 for AES block ciphers
        algorithm = algorithms.AES(key)
        algorithm.block_size = len(iv) * 8

        encryptor = Cipher(algorithm, modes.CBC(iv), backend=default_backend()).encryptor()
        content = content + signature
        if tls_version <= tls.TLSV1_2:
            length = 16 - len(content) % 16
            if 0 < length <= 16:
                content += (length - 1).to_bytes(1, 'big') * length
            c = encryptor.update(content) + encryptor.finalize()
            return iv + c
        else:
            raise NotImplementedError('TLSV1.3 todo')

    def decrypt(self, tls_version, key, iv, encrypted, *, add=None, sign_key=None, hash_algorithm=None):
        algorithm = algorithms.AES(key)
        algorithm.block_size = len(iv) * 8
        iv, rest = encrypted[:len(iv)], encrypted[len(iv):]

        decryptor = Cipher(algorithm, modes.CBC(iv), backend=default_backend()).decryptor()

        unpadder = padding.PKCS7(algorithm.block_size).unpadder()
        result = decryptor.update(rest) + decryptor.finalize()
        result = unpadder.update(result) + unpadder.finalize()
        result = result[:-1]

        signature = result[-hash_algorithm.digest_size:]
        content = result[:-hash_algorithm.digest_size]
        content_bytes_len = len(content).to_bytes(2, 'big')
        add += content_bytes_len

        hmac_verify(add + content, signature, sign_key, hash_algorithm)

        return content


class AESGCM(EncryptionAlgorithm):
    nonce_size = 8

    def encrypt(self, tls_version, key, iv, content, *, add=None, sign_key=None, hash_algorithm=None):
        content_bytes_len = len(content).to_bytes(2, 'big')
        nonce = os.urandom(AESGCM.nonce_size)
        algorithm = algorithms.AES(key)

        encryptor = Cipher(algorithm, modes.GCM(iv + nonce), backend=default_backend()).encryptor()
        encryptor.authenticate_additional_data(add + content_bytes_len)

        result = encryptor.update(content) + encryptor.finalize()
        return nonce + result + encryptor.tag

    def decrypt(self, tls_version, key, iv, encrypted, *, add=None, sign_key=None, hash_algorithm=None):
        algorithm = algorithms.AES(key)
        nonce, rest = encrypted[:AESGCM.nonce_size], encrypted[AESGCM.nonce_size:]

        decryptor = Cipher(algorithm, modes.GCM(iv + nonce), backend=default_backend()).decryptor()

        tag_size = 16
        length = len(rest) - tag_size
        decryptor.authenticate_additional_data(add + length.to_bytes(2, 'big'))

        result = decryptor.update(rest[:-16]) + decryptor.finalize_with_tag(rest[-16:])
        return result
