import os
import io
import random
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend


def get_certificate(certificate_bytes, filelike, *, match_hostname, host) -> x509.Certificate:
    server_cert = None
    while certificate_bytes:
        length, certificate_bytes = int.from_bytes(certificate_bytes[:3], 'big'), certificate_bytes[3:]
        der, certificate_bytes = certificate_bytes[:length], certificate_bytes[length:]

        pem = ssl.DER_cert_to_PEM_cert(der)
        server_cert = server_cert or pem
        filelike.write(pem.encode())  # Debug dump cert chain

    if match_hostname:
        tmpfile = r'./{}.tmpfile.crt'.format(random.randint(100000000, 1000000000))
        with open(tmpfile, 'wb') as f:
            filelike.seek(0)
            f.write(filelike.read())

        try:
            attempt_match_hostname(tmpfile, host)
        finally:
            os.remove(tmpfile)

    return load(server_cert)


def load(cert) -> x509.Certificate:
    if isinstance(cert, io.BufferedIOBase):
        cert = cert.read()
        if len(cert) == 0:
            raise ValueError('The cached certificate is empty. Please manually delete the cert file under the debug '
                             'folder.')

    if isinstance(cert, str):
        cert = cert.encode()
    decoded = x509.load_pem_x509_certificate(cert, default_backend())
    return decoded


def ssl_decode_cert(path):
    # builtin method (undocumented)
    return ssl._ssl._test_decode_cert(path)


def attempt_match_hostname(certpath, host):
    ssl.match_hostname(ssl_decode_cert(certpath), host)
