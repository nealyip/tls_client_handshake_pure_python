"""
TLS 1.3 key schedule (RFC 8446 Section 7.1).

HKDF-Extract/Expand-Label replaces the TLS 1.2 PRF.

Key hierarchy (no PSK / 0-RTT):
  Early Secret   = HKDF-Extract(0, 0)
  derived        = Derive-Secret(Early, "derived", "")
  Handshake Sec  = HKDF-Extract(derived, ECDHE)
    c_hs_traffic = Derive-Secret(HS, "c hs traffic", CH..SH)
    s_hs_traffic = Derive-Secret(HS, "s hs traffic", CH..SH)
  derived2       = Derive-Secret(HS, "derived", "")
  Master Sec     = HKDF-Extract(derived2, 0)
    c_ap_traffic = Derive-Secret(MS, "c ap traffic", CH..SF)
    s_ap_traffic = Derive-Secret(MS, "s ap traffic", CH..SF)
"""

import hashlib
import hmac as _hmac

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, Hash
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


def hkdf_expand_label(secret, label, context, length, algorithm):
    full_label = b'tls13 ' + label
    hkdf_label = (
        length.to_bytes(2, 'big')
        + len(full_label).to_bytes(1, 'big')
        + full_label
        + len(context).to_bytes(1, 'big')
        + context
    )
    return HKDFExpand(
        algorithm=algorithm, length=length, info=hkdf_label, backend=default_backend()
    ).derive(secret)


def _transcript_hash(algorithm, messages: bytes) -> bytes:
    h = Hash(algorithm, backend=default_backend())
    h.update(messages)
    return h.finalize()


def _derive_secret(secret, label, messages, algorithm):
    th = _transcript_hash(algorithm, messages)
    return hkdf_expand_label(secret, label, th, algorithm.digest_size, algorithm)


class KeySchedule:
    def __init__(self, cipher_suite_name: str):
        if 'SHA384' in cipher_suite_name:
            self.algorithm = SHA384()
            self.hash_len = 48
            self._digestmod = hashlib.sha384
        else:
            self.algorithm = SHA256()
            self.hash_len = 32
            self._digestmod = hashlib.sha256

        self.key_len = 16 if 'AES_128' in cipher_suite_name else 32
        self.keys: dict = {}
        self._handshake_secret = None

    def _extract(self, salt, ikm) -> bytes:
        salt = salt if salt is not None else bytes(self.hash_len)
        ikm = ikm if ikm is not None else bytes(self.hash_len)
        return _hmac.new(salt, ikm, self._digestmod).digest()

    def _expand_label(self, secret, label, context, length) -> bytes:
        return hkdf_expand_label(secret, label, context, length, self.algorithm)

    def _derive_secret(self, secret, label, messages) -> bytes:
        return _derive_secret(secret, label, messages, self.algorithm)

    def _write_keys(self, traffic_secret, prefix):
        self.keys[f'{prefix}_write_key'] = self._expand_label(traffic_secret, b'key', b'', self.key_len)
        self.keys[f'{prefix}_write_iv'] = self._expand_label(traffic_secret, b'iv', b'', 12)

    def derive_handshake_secrets(self, ecdhe_shared_secret: bytes, transcript: bytes):
        """Call right after ServerHello. transcript = ClientHello || ServerHello (handshake bytes)."""
        early = self._extract(None, None)
        derived = self._derive_secret(early, b'derived', b'')
        hs = self._extract(derived, ecdhe_shared_secret)
        self._handshake_secret = hs

        c_hs = self._derive_secret(hs, b'c hs traffic', transcript)
        s_hs = self._derive_secret(hs, b's hs traffic', transcript)
        self.keys['client_hs_traffic_secret'] = c_hs
        self.keys['server_hs_traffic_secret'] = s_hs
        self._write_keys(c_hs, 'client_hs')
        self._write_keys(s_hs, 'server_hs')

    def derive_application_secrets(self, transcript: bytes):
        """Call after server Finished is added to transcript. transcript = CH..ServerFinished."""
        derived = self._derive_secret(self._handshake_secret, b'derived', b'')
        ms = self._extract(derived, None)
        self.keys['master_secret'] = ms

        c_ap = self._derive_secret(ms, b'c ap traffic', transcript)
        s_ap = self._derive_secret(ms, b's ap traffic', transcript)
        self.keys['client_app_traffic_secret'] = c_ap
        self.keys['server_app_traffic_secret'] = s_ap
        self._write_keys(c_ap, 'client_app')
        self._write_keys(s_ap, 'server_app')

    def compute_finished(self, traffic_secret: bytes, transcript_bytes: bytes) -> bytes:
        """HMAC(finished_key, Hash(transcript))."""
        finished_key = self._expand_label(traffic_secret, b'finished', b'', self.hash_len)
        th = _transcript_hash(self.algorithm, transcript_bytes)
        return _hmac.new(finished_key, th, self._digestmod).digest()

    def transcript_hash(self, messages: bytes) -> bytes:
        return _transcript_hash(self.algorithm, messages)
