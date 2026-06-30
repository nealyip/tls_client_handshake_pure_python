import collections
import os
import socket
from datetime import datetime

import constants
import tls
from certificates import get_certificate, load
from cipher_suites import CIPHER_SUITES, CipherSuite
from packer import pack, prepend_length, record
from reader import read
from print_colors import bcolors
from extensions import (Extension, ApplicationLayerProtocolNegotiationExtension as ALPN,
                        SupportedVersionsExtension, KeyShareExtension, PskKeyExchangeModesExtension)
from cryptography.hazmat.primitives.hashes import SHA256

# TLS 1.3 cipher suite IDs (prepended to ClientHello when advertising TLS 1.3)
_TLS13_CIPHER_IDS = [b'\x13\x01', b'\x13\x02', b'\x13\x03']  # AES128, AES256, CHACHA20


def print_hex(b):
    return ':'.join('{:02X}'.format(a) for a in b)


def log(fun):
    def run(*args, **kwargs):
        fun_name = ' '.join(map(lambda x: x[0].upper() + x[1:], fun.__name__.split('_')))
        print(fun_name + ' Begin')
        result = fun(*args, **kwargs)
        print(fun_name + ' End')
        return result
    return run


class Client:
    def __init__(self, host, port, tls_version, ciphers, *, extensions=None, match_hostname=True,
                 debug=True, ssl_key_logfile=None):
        self.host = host
        self.port = port
        self.tls_version = tls_version
        self.client_sequence_number = 0
        self.server_sequence_number = 0
        self.security_parameters = dict()
        now = datetime.now()
        self.client_random = int(now.timestamp()).to_bytes(4, 'big') + os.urandom(28)
        self.server_random = None
        self.session_id = b''
        ciphers = ciphers if isinstance(ciphers, collections.abc.Iterable) else tuple(ciphers)
        self.ciphers = tuple(CIPHER_SUITES[cipher] for cipher in ciphers if cipher in CIPHER_SUITES)
        self.extensions = extensions
        self.messages = []
        self.cipher_suite: CipherSuite = None
        self.server_certificate = None
        self.match_hostname = match_hostname
        self.http_version = None

        self.conn = socket.create_connection((host, port))
        self.debug = debug
        self.ssl_key_logfile = ssl_key_logfile
        self.is_server_key_exchange = None

        # TLS 1.3 state (set during client_hello / server_hello)
        self._ecdh_private_key = None
        self.tls13 = None                  # TLS13Handshake instance if 1.3 is negotiated
        self.negotiated_version = None

    def debug_print(self, title, message, *, prefix='\t'):
        if self.debug:
            message = '{color_begin}{message}{color_end}'.format(
                color_begin=bcolors.OKGREEN, message=message, color_end=bcolors.ENDC)
            print(prefix, title, message)

    def record(self, content_type, data, *, tls_version=None):
        return record(content_type, tls_version or self.tls_version, data)

    def pack(self, header_type, data, *, tls_version=None):
        return pack(header_type, tls_version or self.tls_version, data, len_byte_size=3)

    def read(self, return_record=False):
        record, content = read(self.conn)
        if return_record:
            return record, content
        return content

    def _wants_tls13(self) -> bool:
        """Return True if TLS 1.3 appears in the SupportedVersions extension."""
        tls13_bytes = bytes(tls.TLSV1_3())
        for ext in (self.extensions or []):
            if isinstance(ext, SupportedVersionsExtension):
                for v in ext.versions:
                    if bytes(v) == tls13_bytes:
                        return True
        return False

    @log
    def client_hello(self):
        advertise_tls13 = self._wants_tls13()

        # Build cipher suite bytes
        if advertise_tls13:
            # Prepend TLS 1.3 suites before user-supplied TLS 1.2 suites
            ciphers = _TLS13_CIPHER_IDS + [
                int(c['id'], 16).to_bytes(2, 'big') for c in self.ciphers
            ]
        else:
            ciphers = [int(c['id'], 16).to_bytes(2, 'big') for c in self.ciphers]
        ciphers_bytes = prepend_length(b''.join(ciphers), len_byte_size=2)

        # Build extension list
        if advertise_tls13:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            self._ecdh_private_key = X25519PrivateKey.generate()
            pub_bytes = self._ecdh_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

            extra_exts = [
                KeyShareExtension([(b'\x00\x1d', pub_bytes)]),  # x25519
                PskKeyExchangeModesExtension(),
            ]
            all_exts = list(self.extensions or []) + extra_exts
        else:
            all_exts = list(self.extensions or [])

        session_id_bytes = prepend_length(self.session_id, len_byte_size=1)
        compression_method_bytes = prepend_length(b'\x00', len_byte_size=1)
        extensions_bytes = prepend_length(b''.join(map(bytes, all_exts)), len_byte_size=2)

        # For TLS 1.3 compat the legacy_version in ClientHello MUST be 0x0303.
        # self.tls_version is already TLSV1_2 in the standard index.py setup.
        legacy_version = tls.TLSV1_2() if advertise_tls13 else self.tls_version

        client_hello_bytes = self.pack(
            constants.PROTOCOL_CLIENT_HELLO,
            self.client_random
            + session_id_bytes
            + ciphers_bytes
            + compression_method_bytes
            + extensions_bytes,
            tls_version=legacy_version
        )

        message = self.record(constants.CONTENT_TYPE_HANDSHAKE, client_hello_bytes,
                              tls_version=tls.TLSV1())
        self.conn.send(message)
        self.messages.append(client_hello_bytes)
        self.debug_print('Host', self.host)
        self.debug_print('Port', self.port)
        self.debug_print('Client random', print_hex(self.client_random))
        self.debug_print('Cipher suite suggested',
                         '{}'.format(', '.join(c['openssl_name'] for c in self.ciphers)))
        if advertise_tls13:
            self.debug_print('TLS 1.3', 'advertised (key_share: x25519)')

    @log
    def server_hello(self):
        record_bytes, hello_bytes = self.read(return_record=True)
        assert record_bytes[:1] == constants.CONTENT_TYPE_HANDSHAKE, \
            'Server returned {}'.format(print_hex(record_bytes[:1]))
        raw_server_hello = hello_bytes
        self.messages.append(hello_bytes)
        assert len(hello_bytes) > 0, 'No response from server'
        assert hello_bytes[:1] == b'\x02', 'Not server hello'

        legacy_version = hello_bytes[4:6]
        self.server_random = hello_bytes[6:38]
        rest = hello_bytes[38:]

        session_id_length = rest[0]
        rest = rest[1 + session_id_length:]
        server_cipher_suite_bytes = rest[:2]
        rest = rest[3:]  # cipher_suite(2) + compression_method(1)

        extensions_length = int.from_bytes(rest[:2], 'big')
        ext_data = rest[2:2 + extensions_length]
        self.extensions = Extension.parse_extensions(ext_data)

        # ---- Determine negotiated version ----
        negotiated_bytes = legacy_version
        for ext in self.extensions:
            if isinstance(ext, SupportedVersionsExtension) and ext.versions:
                negotiated_bytes = bytes(ext.versions[0])
                break

        try:
            self.negotiated_version = tls.TLS.get_by_code(
                tuple(negotiated_bytes[i:i + 1] for i in range(len(negotiated_bytes)))
            )
        except StopIteration:
            self.negotiated_version = self.tls_version

        # ---- TLS 1.3 path ----
        if bytes(self.negotiated_version) == bytes(tls.TLSV1_3()):
            server_key_share = next(
                (e for e in self.extensions if isinstance(e, KeyShareExtension)), None
            )
            if server_key_share is None:
                raise ValueError('TLS 1.3 ServerHello missing key_share extension')

            cipher_id = '0x{:04X}'.format(int.from_bytes(server_cipher_suite_bytes, 'big'))
            cipher_name = next(
                (k for k, v in CIPHER_SUITES.items() if v['id'] == cipher_id), None
            )
            if cipher_name is None:
                raise ValueError(f'Unknown TLS 1.3 cipher suite: {cipher_id}')

            from tls13.handshake import TLS13Handshake
            self.tls13 = TLS13Handshake(
                conn=self.conn,
                host=self.host,
                cipher_suite_name=cipher_name,
                client_hello_bytes=self.messages[0],
                server_hello_bytes=raw_server_hello,
                ecdh_private_key=self._ecdh_private_key,
                server_key_share=server_key_share,
                client_random=self.client_random,
                debug=self.debug,
                ssl_key_logfile=self.ssl_key_logfile,
            )
            self.debug_print('TLS version negotiated', str(self.negotiated_version))
            self.debug_print('Cipher suite negotiated', cipher_name)
            self.debug_print('Server random', print_hex(self.server_random))
            return

        # ---- TLS 1.2 / 1.1 path (existing logic) ----
        assert legacy_version == self.tls_version, \
            f'Not a desired tls version: got {print_hex(legacy_version)}'

        alpn = [x for x in self.extensions if isinstance(x, ALPN)]
        self.http_version = alpn[0].protocols[0] if alpn else constants.EXTENSION_ALPN_HTTP_1_1
        assert self.http_version == constants.EXTENSION_ALPN_HTTP_1_1, 'Not support http2 yet'

        certificate_bytes = self.read()
        cached_cert_path = r'./debug/{}.crt'.format(self.host)
        if certificate_bytes[0] == 0x0B:
            self.messages.append(certificate_bytes)
            certificate_bytes = certificate_bytes[7:]
            os.path.exists(r'./debug') or os.makedirs(r'./debug')
            self.server_certificate = get_certificate(
                certificate_bytes, open(cached_cert_path, 'wb+'),
                match_hostname=self.match_hostname, host=self.host)
            next_bytes = self.read()
        elif os.path.exists(cached_cert_path):
            self.server_certificate = load(open(cached_cert_path, 'rb'))
            next_bytes = certificate_bytes
        else:
            raise ValueError('No certificate was received.')

        self.cipher_suite = CipherSuite.get_from_id(
            self.tls_version, self.client_random, self.server_random,
            self.server_certificate, server_cipher_suite_bytes)

        self.messages.append(next_bytes)
        self.is_server_key_exchange = next_bytes[:1] == b'\x0c'
        if self.is_server_key_exchange:
            self.cipher_suite.parse_key_exchange_params(next_bytes)
            hello_done_bytes = self.read()
            self.messages.append(hello_done_bytes)
        elif self.session_id:
            raise ValueError('No server key exchange has received. # @todo')

        self.debug_print('Cipher suite negotiated',
                         ' {}({})'.format(self.cipher_suite, print_hex(server_cipher_suite_bytes)))
        self.debug_print('TLS version', self.tls_version)
        self.debug_print('Server random', print_hex(self.server_random))
        self.debug_print('Key exchange', self.cipher_suite.key_exchange.__class__.__name__)
        self.debug_print('Server cert not before (UTC)', self.server_certificate.not_valid_before_utc)
        self.debug_print('Server cert not after (UTC)', self.server_certificate.not_valid_after_utc)
        self.debug_print('Server cert fingerprint (sha256)',
                         print_hex(self.server_certificate.fingerprint(SHA256())))
        if self.is_server_key_exchange:
            public_key = self.cipher_suite.key_exchange.public_key
            self.debug_print(
                'Key Exchange Server Public Key ({!s} bytes)'.format(len(public_key)),
                print_hex(public_key))

    @log
    def client_finish(self):
        pre_master_secret, enc_length, encrypted_pre_master_secret = self.cipher_suite.key_exchange.exchange()

        key_exchange_data = constants.PROTOCOL_CLIENT_KEY_EXCHANGE + prepend_length(
            enc_length + encrypted_pre_master_secret, len_byte_size=3)

        key_exchange_bytes = self.record(constants.CONTENT_TYPE_HANDSHAKE, key_exchange_data)
        self.messages.append(key_exchange_data)

        change_cipher_spec_bytes = self.record(constants.PROTOCOL_CHANGE_CIPHER_SPEC, b'\x01')

        self.cipher_suite.pre_master_secret = pre_master_secret

        pre_message = b''.join(self.messages)

        verify_data = self.cipher_suite.sign_verify_data(pre_message)
        verify_bytes = constants.PROTOCOL_CLIENT_FINISH + prepend_length(verify_data, len_byte_size=3)

        kwargs = {
            'content_bytes': verify_bytes,
            'seq_num': self.client_sequence_number,
            'content_type': constants.CONTENT_TYPE_HANDSHAKE
        }
        encrypted_finished = self.cipher_suite.encrypt(**kwargs)
        encrypted_finished_bytes = self.record(constants.CONTENT_TYPE_HANDSHAKE, encrypted_finished)
        self.messages.append(verify_bytes)

        self.client_sequence_number += 1
        self.conn.send(key_exchange_bytes + change_cipher_spec_bytes + encrypted_finished_bytes)
        if self.is_server_key_exchange:
            self.debug_print(
                'Key Exchange Client Public Key ({!s} bytes)'.format(len(encrypted_pre_master_secret)),
                print_hex(encrypted_pre_master_secret))
        else:
            self.debug_print('Encrypted pre master secret', print_hex(encrypted_pre_master_secret))
        self.debug_print('Pre master secret', print_hex(pre_master_secret))
        self.debug_print('Master secret', print_hex(self.cipher_suite.keys['master_secret']))
        self.debug_print('Verify data', print_hex(verify_data))

        if self.ssl_key_logfile:
            with open(self.ssl_key_logfile, 'a') as f:
                f.write(
                    f'CLIENT_RANDOM {self.client_random.hex()} '
                    f'{self.cipher_suite.keys["master_secret"].hex()}\n'
                )

    @log
    def server_finish(self):
        while True:
            record, content = self.read(return_record=True)
            if record[:1] == constants.CONTENT_TYPE_ALERT:
                if content == constants.ERROR_FATAL + constants.ERROR_CODE_BAD_RECORD_MAC:
                    raise Exception('Bad record mac')
                raise Exception(print_hex(content))
            if content[:1] == constants.PROTOCOL_NEW_SESSION_TICKET:
                self.messages.append(content)
            elif record[:1] == constants.PROTOCOL_SERVER_FINISH:
                pass
            elif record[:1] == constants.CONTENT_TYPE_HANDSHAKE:
                kwargs = {
                    'encrypted_bytes': content,
                    'seq_num': self.server_sequence_number,
                    'content_type': constants.CONTENT_TYPE_HANDSHAKE
                }

                content = self.cipher_suite.decrypt(**kwargs)
                assert content[:1] == constants.PROTOCOL_SERVER_FINISH, \
                    ValueError('Not server finished')

                pre_message = b''.join(self.messages)
                verify_data = content[4:]
                self.cipher_suite.verify_verify_data(pre_message, verify_data)
                self.server_sequence_number += 1
                break
        self.debug_print('Verify data', print_hex(verify_data))

    @log
    def send_application_data(self):
        data = 'GET / HTTP/1.1\r\nHost: {host}\r\n\r\n'.format(host=self.host)
        kwargs = {
            'content_bytes': data.encode(),
            'seq_num': self.client_sequence_number,
            'content_type': constants.CONTENT_TYPE_DATA
        }
        encrypted_data = self.cipher_suite.encrypt(**kwargs)
        encrypted_bytes = self.record(constants.CONTENT_TYPE_DATA, encrypted_data)
        self.conn.send(encrypted_bytes)
        self.client_sequence_number += 1
        self.debug_print('Plain', data.replace('\r', '\\r').replace('\n', '\\n'))
        self.debug_print('Encrypted', print_hex(encrypted_bytes))

    @log
    def receive_application_data(self):
        result = b''
        content_length = None
        while True:
            record, content = self.read(return_record=True)
            if record[:3] == constants.CONTENT_TYPE_ALERT + self.tls_version or len(content) == 0:
                break
            kwargs = {
                'encrypted_bytes': content,
                'seq_num': self.server_sequence_number,
                'content_type': constants.CONTENT_TYPE_DATA
            }

            decoded = self.cipher_suite.decrypt(**kwargs)
            result += decoded

            if content_length is None:
                tmp = result.split(b'\r\n\r\n')[0]
                pos = tmp.find(b'Content-Length')
                if pos > -1:
                    content_length = int(decoded[pos + 15:tmp.find(b'\r\n', pos)])

            if result[-4:] == b'\r\n\r\n':
                break

            if content_length is not None and len(result) >= content_length:
                break

            self.server_sequence_number += 1

        return result

    def run(self):
        self.client_hello()
        self.server_hello()

        if self.tls13 is not None:
            # TLS 1.3 control plane
            self.tls13.process_server_handshake()
            self.tls13.send_client_finished()
            self.tls13.send_application_data()
            result = self.tls13.receive_application_data()
        else:
            # TLS 1.2 / 1.1 control plane (unchanged)
            self.client_finish()
            self.server_finish()
            self.send_application_data()
            result = self.receive_application_data()

        print('Server response', bcolors.OKGREEN, result, bcolors.ENDC)
