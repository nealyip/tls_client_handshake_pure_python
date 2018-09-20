from abc import ABC

import constants
from packer import prepend_length


class Extension(ABC):
    header = b''
    inner_len_byte_size = 2

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
    inner_len_byte_size = 0


class ApplicationLayerProtocolNegotiationExtension(Extension):
    header = b'\x00\x10'

    @property
    def data_bytes(self):
        data = prepend_length(constants.EXTENSION_ALPN_HTTP_1_1, len_byte_size=1)
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
