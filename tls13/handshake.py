"""
TLS 1.3 handshake control plane (RFC 8446).

Called by client.py after ServerHello is parsed and the negotiated version
is confirmed to be TLS 1.3.  Responsibilities:

  1. Compute ECDHE shared secret from the server's key_share.
  2. Derive handshake traffic keys via HKDF key schedule.
  3. Decrypt and process: EncryptedExtensions, Certificate,
     CertificateVerify, server Finished.
  4. Send encrypted client Finished; derive application traffic keys.
  5. Send/receive application data (HTTP/1.1 GET).
"""

import os

import constants
from certificates import get_certificate
from print_colors import bcolors
from tls13.key_schedule import KeySchedule
from tls13.record import encrypt_record, decrypt_record


def _hex(b: bytes) -> str:
    return ':'.join(f'{x:02X}' for x in b)


def _wrap_record(ciphertext: bytes) -> bytes:
    """Wrap ciphertext in a TLS 1.3 ApplicationData record (0x17 0x03 0x03 len)."""
    return constants.CONTENT_TYPE_DATA + b'\x03\x03' + len(ciphertext).to_bytes(2, 'big') + ciphertext


# Named-group IDs used in key_share
_GROUP_X25519 = b'\x00\x1d'
_GROUP_SECP256R1 = b'\x00\x17'
_GROUP_SECP384R1 = b'\x00\x18'

# TLS 1.3 handshake message types
_MSG_ENCRYPTED_EXTENSIONS = b'\x08'
_MSG_CERTIFICATE = b'\x0b'
_MSG_CERTIFICATE_VERIFY = b'\x0f'
_MSG_FINISHED = b'\x14'


class TLS13Handshake:
    """
    Drives a TLS 1.3 handshake after ServerHello has been received.

    Parameters
    ----------
    conn            : open socket
    host            : server hostname (for cert validation and HTTP Host header)
    cipher_suite_name : e.g. 'TLS_AES_128_GCM_SHA256'
    client_hello_bytes : raw ClientHello handshake message (type+len+body)
    server_hello_bytes : raw ServerHello handshake message (type+len+body)
    ecdh_private_key   : X25519PrivateKey (or EC private key)
    server_key_share   : KeyShareExtension instance parsed from ServerHello
    client_random      : 32-byte client random (for SSLKEYLOGFILE)
    """

    def __init__(self, conn, host, cipher_suite_name,
                 client_hello_bytes, server_hello_bytes,
                 ecdh_private_key, server_key_share,
                 client_random, debug=True, ssl_key_logfile=None):
        self.conn = conn
        self.host = host
        self.cipher_suite_name = cipher_suite_name
        self.client_random = client_random
        self.debug = debug
        self.ssl_key_logfile = ssl_key_logfile

        self.key_schedule = KeySchedule(cipher_suite_name)
        self.server_certificate = None

        # Sequence counters
        self._srv_hs_seq = 0
        self._cli_hs_seq = 0
        self._srv_app_seq = 0
        self._cli_app_seq = 0

        # Compute shared secret and derive handshake keys
        server_pub = self._load_server_pub_key(server_key_share)
        shared_secret = ecdh_private_key.exchange(server_pub)
        transcript = client_hello_bytes + server_hello_bytes
        self.key_schedule.derive_handshake_secrets(shared_secret, transcript)
        self._transcript = transcript

        self._dbg('ECDHE shared secret', _hex(shared_secret))
        self._dbg('Server HS write key', _hex(self.key_schedule.keys['server_hs_write_key']))
        self._dbg('Client HS write key', _hex(self.key_schedule.keys['client_hs_write_key']))

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def process_server_handshake(self):
        """Read and process all encrypted server handshake messages."""
        buffer = b''
        while True:
            record_header, content = self._read_record()

            if record_header[:1] == constants.CONTENT_TYPE_ALERT:
                raise Exception(f'TLS Alert: {_hex(content)}')

            # Legacy ChangeCipherSpec – ignore (RFC 8446 §D.4)
            if record_header[:1] == b'\x14':
                continue

            if record_header[:1] != constants.CONTENT_TYPE_DATA:
                continue

            inner_type, plaintext = self._decrypt_srv_hs(record_header, content)

            if inner_type == b'\x14':   # inner CCS (ignore)
                continue
            if inner_type != constants.CONTENT_TYPE_HANDSHAKE:
                continue

            buffer += plaintext

            # Parse complete handshake messages out of the buffer
            done = False
            while len(buffer) >= 4:
                msg_type = buffer[:1]
                msg_len = int.from_bytes(buffer[1:4], 'big')
                if len(buffer) < 4 + msg_len:
                    break
                msg_bytes = buffer[:4 + msg_len]
                buffer = buffer[4 + msg_len:]
                self._dispatch(msg_type, msg_bytes)
                if msg_type == _MSG_FINISHED:
                    done = True
                    break
            if done:
                break

    def send_client_finished(self):
        """Compute and send encrypted client Finished, write SSLKEYLOGFILE."""
        client_hs_secret = self.key_schedule.keys['client_hs_traffic_secret']
        # Transcript at this point: CH..ServerFinished
        verify_data = self.key_schedule.compute_finished(client_hs_secret, self._transcript)

        finished_msg = _MSG_FINISHED + len(verify_data).to_bytes(3, 'big') + verify_data
        self.conn.send(self._encrypt_cli_hs(constants.CONTENT_TYPE_HANDSHAKE, finished_msg))

        # Update transcript (used if session tickets arrive later)
        self._transcript += finished_msg

        if self.ssl_key_logfile:
            cr = self.client_random.hex()
            c = self.key_schedule.keys['client_app_traffic_secret'].hex()
            s = self.key_schedule.keys['server_app_traffic_secret'].hex()
            with open(self.ssl_key_logfile, 'a') as f:
                f.write(f'CLIENT_TRAFFIC_SECRET_0 {cr} {c}\n')
                f.write(f'SERVER_TRAFFIC_SECRET_0 {cr} {s}\n')

        self._dbg('Client Finished', 'sent')

    def send_application_data(self):
        data = f'GET / HTTP/1.1\r\nHost: {self.host}\r\n\r\n'.encode()
        self.conn.send(self._encrypt_cli_app(constants.CONTENT_TYPE_DATA, data))
        self._dbg('HTTP GET', data.decode().replace('\r', '\\r').replace('\n', '\\n'))

    def receive_application_data(self) -> bytes:
        result = b''
        content_length = None
        header_end = -1

        while True:
            record_header, content = self._read_record()

            if record_header[:1] == constants.CONTENT_TYPE_ALERT:
                break
            if record_header[:1] == b'\x14':
                continue
            if record_header[:1] != constants.CONTENT_TYPE_DATA:
                continue

            inner_type, plaintext = self._decrypt_srv_app(record_header, content)

            if inner_type == constants.CONTENT_TYPE_ALERT:
                break
            if inner_type == constants.CONTENT_TYPE_HANDSHAKE:
                # Could be NewSessionTicket – ignore for now
                continue
            if inner_type != constants.CONTENT_TYPE_DATA:
                continue

            result += plaintext

            if header_end == -1:
                header_end = result.find(b'\r\n\r\n')
                if header_end != -1:
                    pos = result.find(b'Content-Length:')
                    if pos != -1:
                        end = result.find(b'\r\n', pos)
                        content_length = int(result[pos + 15:end].strip())

            if result[-4:] == b'\r\n\r\n':
                break
            if content_length is not None and header_end != -1:
                if len(result) >= header_end + 4 + content_length:
                    break

        return result

    # ------------------------------------------------------------------
    # Internal handshake message dispatching
    # ------------------------------------------------------------------

    def _dispatch(self, msg_type: bytes, msg_bytes: bytes):
        if msg_type == _MSG_ENCRYPTED_EXTENSIONS:
            self._transcript += msg_bytes
            self._dbg('EncryptedExtensions', 'received')

        elif msg_type == _MSG_CERTIFICATE:
            self._transcript += msg_bytes
            self._process_certificate(msg_bytes)

        elif msg_type == _MSG_CERTIFICATE_VERIFY:
            # Verify BEFORE adding to transcript
            self._process_certificate_verify(msg_bytes)
            self._transcript += msg_bytes

        elif msg_type == _MSG_FINISHED:
            # Verify BEFORE adding to transcript, then derive app keys
            self._verify_server_finished(msg_bytes)
            self._transcript += msg_bytes
            self.key_schedule.derive_application_secrets(self._transcript)
            self._dbg('App write key (client)', _hex(self.key_schedule.keys['client_app_write_key']))
            self._dbg('App write key (server)', _hex(self.key_schedule.keys['server_app_write_key']))

    def _process_certificate(self, msg_bytes: bytes):
        # type(1) + length(3) + context_len(1) + context + cert_list_len(3) + cert_list
        data = msg_bytes[4:]
        ctx_len = data[0]
        data = data[1 + ctx_len:]

        cert_list_len = int.from_bytes(data[:3], 'big')
        cert_list = data[3:3 + cert_list_len]

        # TLS 1.3 cert entry: cert_data_len(3) + cert_der + ext_len(2) + extensions
        # get_certificate() expects plain: cert_data_len(3) + cert_der (repeating)
        plain = b''
        remaining = cert_list
        while remaining:
            cert_len = int.from_bytes(remaining[:3], 'big')
            remaining = remaining[3:]
            cert_der = remaining[:cert_len]
            remaining = remaining[cert_len:]
            ext_len = int.from_bytes(remaining[:2], 'big')
            remaining = remaining[2 + ext_len:]
            plain += len(cert_der).to_bytes(3, 'big') + cert_der

        os.path.exists('./debug') or os.makedirs('./debug')
        cached = f'./debug/{self.host}.crt'
        with open(cached, 'wb+') as f:
            self.server_certificate = get_certificate(plain, f, match_hostname=True, host=self.host)

        from cryptography.hazmat.primitives.hashes import SHA256
        self._dbg('Server cert fingerprint (sha256)',
                  _hex(self.server_certificate.fingerprint(SHA256())))
        self._dbg('Server cert not after (UTC)',
                  self.server_certificate.not_valid_after_utc)

    def _process_certificate_verify(self, msg_bytes: bytes):
        # type(1) + length(3) + sig_alg(2) + sig_len(2) + signature
        data = msg_bytes[4:]
        sig_alg_bytes = data[:2]
        sig_len = int.from_bytes(data[2:4], 'big')
        signature = data[4:4 + sig_len]

        # signed_data = 0x20*64 || "TLS 1.3, server CertificateVerify" || 0x00 || Hash(transcript)
        transcript_hash = self.key_schedule.transcript_hash(self._transcript)
        context = b' ' * 64 + b'TLS 1.3, server CertificateVerify' + b'\x00'
        signed_content = context + transcript_hash

        import signature_algorithms as sa
        algo = sa.SignatureAlgorithm.get_by_code(sig_alg_bytes, self.server_certificate.public_key())
        algo.verify(signature, signed_content)
        self._dbg('CertificateVerify', 'OK')

    def _verify_server_finished(self, msg_bytes: bytes):
        verify_data = msg_bytes[4:]
        server_hs_secret = self.key_schedule.keys['server_hs_traffic_secret']
        expected = self.key_schedule.compute_finished(server_hs_secret, self._transcript)
        assert verify_data == expected, 'Server Finished HMAC mismatch'
        self._dbg('Server Finished', 'OK')

    # ------------------------------------------------------------------
    # Record layer helpers
    # ------------------------------------------------------------------

    def _read_record(self):
        from reader import read
        return read(self.conn)

    def _decrypt_srv_hs(self, record_header, encrypted):
        k = self.key_schedule.keys['server_hs_write_key']
        iv = self.key_schedule.keys['server_hs_write_iv']
        inner_type, plain = decrypt_record(k, iv, self._srv_hs_seq, record_header, encrypted,
                                           self.cipher_suite_name)
        self._srv_hs_seq += 1
        return inner_type, plain

    def _decrypt_srv_app(self, record_header, encrypted):
        k = self.key_schedule.keys['server_app_write_key']
        iv = self.key_schedule.keys['server_app_write_iv']
        inner_type, plain = decrypt_record(k, iv, self._srv_app_seq, record_header, encrypted,
                                           self.cipher_suite_name)
        self._srv_app_seq += 1
        return inner_type, plain

    def _encrypt_cli_hs(self, inner_content_type, data) -> bytes:
        k = self.key_schedule.keys['client_hs_write_key']
        iv = self.key_schedule.keys['client_hs_write_iv']
        ct = encrypt_record(k, iv, self._cli_hs_seq, inner_content_type, data, self.cipher_suite_name)
        self._cli_hs_seq += 1
        return _wrap_record(ct)

    def _encrypt_cli_app(self, inner_content_type, data) -> bytes:
        k = self.key_schedule.keys['client_app_write_key']
        iv = self.key_schedule.keys['client_app_write_iv']
        ct = encrypt_record(k, iv, self._cli_app_seq, inner_content_type, data, self.cipher_suite_name)
        self._cli_app_seq += 1
        return _wrap_record(ct)

    # ------------------------------------------------------------------
    # Key loading
    # ------------------------------------------------------------------

    def _load_server_pub_key(self, server_key_share):
        group = server_key_share.server_group
        pub_bytes = server_key_share.server_public_key_bytes

        if group == _GROUP_X25519:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
            return X25519PublicKey.from_public_bytes(pub_bytes)

        if group == _GROUP_SECP256R1:
            from cryptography.hazmat.primitives.asymmetric import ec
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)

        if group == _GROUP_SECP384R1:
            from cryptography.hazmat.primitives.asymmetric import ec
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), pub_bytes)

        raise ValueError(f'Unsupported key_share group: {group.hex()}')

    # ------------------------------------------------------------------
    # Debug
    # ------------------------------------------------------------------

    def _dbg(self, title, message, prefix='\t'):
        if self.debug:
            msg = f'{bcolors.OKGREEN}{message}{bcolors.ENDC}'
            print(prefix, title, msg)
