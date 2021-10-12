import os
from abc import ABC, abstractmethod

from asn1crypto.keys import PublicKeyInfo
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat

import ec_curves
import signature_algorithms
import tls


class KeyExchange(ABC):

    def __init__(self, tls_version, client_random, server_random, server_cert, signature_algorithm):
        self.tls_version = tls_version
        self.server_cert = server_cert
        self.signature_algorithm = signature_algorithm
        self.client_random = client_random
        self.server_random = server_random

    def parse_params(self, params_bytes):
        pass

    @abstractmethod
    def exchange(self):
        pass


class ECDH(KeyExchange):

    def __init__(self, tls_version, client_random, server_random, server_cert, signature_algorithm):
        KeyExchange.__init__(self, tls_version, client_random, server_random, server_cert, signature_algorithm)
        self.name_curved: ec_curves.ECCurves = None
        self.public_key = None

    def parse_params(self, params_bytes):
        data_bytes = params_bytes[4:]  # Ignore header and length bytes

        curve_type, data_bytes = data_bytes[:1], data_bytes[1:]

        self.name_curved, data_bytes = ec_curves.ECCurves.get_by_code(data_bytes[:2]), data_bytes[2:]

        pubkey_length, data_bytes = int.from_bytes(data_bytes[:1], 'big'), data_bytes[1:]
        self.public_key, data_bytes = data_bytes[:pubkey_length], data_bytes[pubkey_length:]

        if self.tls_version >= tls.TLSV1_2:
            signature_algorithm, data_bytes = signature_algorithms.SignatureAlgorithm.get_by_code(
                data_bytes[:2], self.server_cert.public_key()), data_bytes[2:]
        else:
            signature_algorithm = signature_algorithms.RsaPkcs1Md5Sha1(self.server_cert.public_key())

        signature_length, data_bytes = int.from_bytes(data_bytes[:2], 'big'), data_bytes[2:]
        signature = data_bytes[:signature_length]

        # Verify signature
        curve_type, named_curve, public_key_length = params_bytes[4:5], params_bytes[5:7], params_bytes[7:8]
        check_content = self.client_random + self.server_random + curve_type + named_curve + public_key_length + self.public_key
        signature_algorithm.verify(signature, check_content)

    def exchange(self):
        key = ec.generate_private_key(
            curve=self.name_curved.curve,
            backend=default_backend(),
        )

        args = (
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo
        )
        der = key.public_key().public_bytes(*args)

        info = PublicKeyInfo.load(der)
        header = der[:len(der) - len(self.public_key)]
        server_public_key = load_der_public_key(header + self.public_key, default_backend())

        shared_key = key.exchange(ec.ECDH(), server_public_key)

        return shared_key, len(info['public_key'].native).to_bytes(1, 'big'), info['public_key'].native


class DH(KeyExchange):

    def __init__(self, tls_version, client_random, server_random, server_cert, signature_algorithm):
        KeyExchange.__init__(self, tls_version, client_random, server_random, server_cert, signature_algorithm)
        self.p = None
        self.g = None
        self.public_key = None

    def parse_params(self, params_bytes):
        data_bytes = params_bytes[4:]  # Ignore header and length bytes

        p_len, data_bytes = data_bytes[:2], data_bytes[2:]
        p_len_int = int.from_bytes(p_len, 'big')
        self.p, data_bytes = data_bytes[:p_len_int], data_bytes[p_len_int:]

        g_len, data_bytes = data_bytes[:2], data_bytes[2:]
        g_len_int = int.from_bytes(g_len, 'big')
        self.g, data_bytes = data_bytes[:g_len_int], data_bytes[g_len_int:]

        pubkey_len, data_bytes = data_bytes[:2], data_bytes[2:]
        pubkey_len_int = int.from_bytes(pubkey_len, 'big')
        self.public_key, data_bytes = data_bytes[:pubkey_len_int], data_bytes[pubkey_len_int:]

        if self.tls_version >= tls.TLSV1_2:
            signature_algorithm, data_bytes = signature_algorithms.SignatureAlgorithm.get_by_code(
                data_bytes[:2], self.server_cert.public_key()), data_bytes[2:]
        else:
            signature_algorithm = signature_algorithms.RsaPkcs1Md5Sha1(self.server_cert.public_key())
        sig_len, data_bytes = int.from_bytes(data_bytes[:2], 'big'), data_bytes[2:]
        signature = data_bytes[:sig_len]

        # Verify signature
        check_content = self.client_random + self.server_random + p_len + self.p + g_len + self.g + pubkey_len + self.public_key
        signature_algorithm.verify(signature, check_content)

    def exchange(self):
        raise NotImplementedError('DH is not implemented yet')


class RSA(KeyExchange):

    def exchange(self):
        """
        When RSA is used for server authentication and key exchange, a 48-
        byte pre_master_secret is generated by the client, encrypted under
        the server's public key, and sent to the server.  The server uses its
        private key to decrypt the pre_master_secret.  Both parties then
        convert the pre_master_secret into the master_secret.

        client_version
        The latest (newest) version supported by the
         client.  This is used to detect version roll-back attacks.
         Upon receiving the premaster secret, the server SHOULD check
         that this value matches the value transmitted by the client in
         the client hello message.

        :param public_key:
        :return:
        """
        secret = self.tls_version + os.urandom(46)
        # encrypted = public_key.encrypt(secret, padding.OAEP(
        #     mgf=padding.MGF1(algorithm=SHA1()),
        #     algorithm=SHA1(),
        #     label=None
        # ))
        encrypted = self.server_cert.public_key().encrypt(secret, padding.PKCS1v15())
        return secret, len(encrypted).to_bytes(2, 'big'), encrypted
