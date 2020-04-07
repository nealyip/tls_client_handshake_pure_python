from abc import ABC, abstractmethod

import tls
import constants
from packer import prepend_length


class Extension(ABC):
    header = b''
    inner_len_byte_size = 2

    @classmethod
    def parse_extensions(cls, ext_bytes):
        exts = []
        while ext_bytes:
            ext_type, ext_bytes = ext_bytes[:2], ext_bytes[2:]

            g = globals()
            found = next(filter(lambda x: getattr(g[x], 'header', None) == ext_type, g))
            length, ext_bytes = int.from_bytes(ext_bytes[:2], 'big'), ext_bytes[2:]
            data, ext_bytes = ext_bytes[:length], ext_bytes[length:]
            exts.append(g[found].load_from_bytes(data))

        return tuple(exts)

    @classmethod
    def load_from_bytes(cls, data_bytes):
        return cls()

    @property
    def data_bytes(self):
        return b''

    def get_bytes(self):
        data = prepend_length(self.data_bytes,
                              len_byte_size=self.inner_len_byte_size) if self.inner_len_byte_size > 0 else self.data_bytes
        data = prepend_length(data, len_byte_size=2) if len(self.data_bytes) > 0 else data
        return self.header + data

    def __bytes__(self):
        return self.get_bytes()


class ServerNameExtension(Extension):
    header = b'\x00\x00'

    def __init__(self, host):
        self.host = host.encode(encoding='utf-8') if isinstance(host, str) else host

    @classmethod
    def load_from_bytes(cls, data_bytes):
        return cls(data_bytes)

    @property
    def data_bytes(self):
        return constants.EXTENSION_SERVER_NAME_TYPE_HOSTNAME + prepend_length(self.host, len_byte_size=2)


class ExtendMasterSecretExtension(Extension):
    header = b'\x00\x17'


class SessionTicketExtension(Extension):
    header = b'\x00\x23'

    def __init__(self, session_id=b''):
        self.session_id = session_id

    @property
    def data_bytes(self):
        return self.session_id


class SignatureAlgorithmExtension(Extension):
    """
    This extension is used by DHE/ECDHE key exchange after TLSv1.2 (including)
    """
    header = b'\x00\x0d'

    def __init__(self, algorithms):
        self.algorithms = algorithms

    @property
    def data_bytes(self):
        return b''.join(algorithm.code for algorithm in self.algorithms)


class SignedCertificateTimestampExtension(Extension):
    header = b'\x00\x12'


class ApplicationLayerProtocolNegotiationExtension(Extension):
    header = b'\x00\x10'

    def __init__(self, protocols):
        self.protocols = protocols

    @classmethod
    def load_from_bytes(cls, data_bytes):
        length = int.from_bytes(data_bytes[2:3], 'big')
        protocol = data_bytes[3:3 + length]
        return cls((protocol,))

    @property
    def data_bytes(self):
        data = b''
        for protocol in self.protocols:
            data += prepend_length(protocol, len_byte_size=1)
        return data


class ECPointFormatsExtension(Extension):
    header = b'\x00\x0b'
    inner_len_byte_size = 1

    @property
    def data_bytes(self):
        return constants.EXTENSION_EC_POINT_FORMAT_UNCOMPRESSED


class SupportedGroupsExtension(Extension):
    """
    This extension is used for EDCH(E)
    """
    header = b'\x00\x0a'

    def __init__(self, groups):
        self.groups = groups

    @property
    def data_bytes(self):
        return b''.join(group.code for group in self.groups)


class SupportedVersionsExtension(Extension):
    header = b'\x00\x2b'
    inner_len_byte_size = 1

    def __init__(self, tls_versions):
        self.versions = tls_versions

    @classmethod
    def load_from_bytes(cls, data_bytes):
        return cls((tls.TLS.get_by_code(tuple(data_bytes[i:i + 1] for i in range(0, len(data_bytes)))),))

    @property
    def data_bytes(self):
        return b''.join(bytes(version) for version in self.versions)


class EncryptedThenMacExtension(Extension):
    header = b'\x00\x16'


class HeartbeatExtension(Extension):
    header = b'\x00\x0f'
    inner_len_byte_size = 0

    @property
    def data_bytes(self):
        return constants.EXTENSION_HEARTBEAT_MODE_PEER_ALLOWED_TO_SEND_REQUESTS


class PaddingExtension(Extension):
    header = b'\x00\x15'
    inner_len_byte_size = 0

    @property
    def data_bytes(self):
        return b'\x00'


class StatusRequestExtension(Extension):
    header = b'\x00\x05'
    inner_len_byte_size = 0

    OCSP = b'\x01'

    @property
    def data_bytes(self):
        responder_id = b''
        request_extensions = b''
        content_bytes = prepend_length(responder_id, len_byte_size=2) + prepend_length(request_extensions, len_byte_size=2)
        return StatusRequestExtension.OCSP + content_bytes
