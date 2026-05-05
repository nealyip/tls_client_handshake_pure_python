import argparse
import os
import sys

import constants
import ec_curves
import extensions
import signature_algorithms
import tls
from client import Client

# TLSv1.0 is not supported
_TLS_VERSION_MAP = {
    '1.1': tls.TLSV1_1,
    '1.2': tls.TLSV1_2,
    '1.3': tls.TLSV1_3,
}


def args():
    parser = argparse.ArgumentParser(
        description='TLS client handshake demo (pure Python)'
    )
    parser.add_argument(dest='host',
                        help='Hostname to connect to, or "-" to read from stdin')
    parser.add_argument('-c', '--cipher', dest='cipher', default=False, nargs='?',
                        help='Force a specific cipher suite (e.g. AES256-SHA)')
    parser.add_argument('-t', '--tls', dest='tls_version', default='1.3',
                        choices=_TLS_VERSION_MAP.keys(), metavar='VERSION',
                        help='Maximum TLS version to negotiate: 1.1 | 1.2 | 1.3 (default: 1.3)')
    return parser.parse_args()


def run(host, cipher, tls_version_str='1.3'):
    port = 443
    max_version = _TLS_VERSION_MAP[tls_version_str]()

    # Base version used in ClientHello legacy_version field (always ≤ 1.2 for wire compat)
    base_version = tls.TLSV1_2() if tls_version_str == '1.3' else max_version

    # Build the supported_versions list based on requested max
    if tls_version_str == '1.3':
        supported_versions = (tls.TLSV1_3(), tls.TLSV1_2())
    elif tls_version_str == '1.2':
        supported_versions = (tls.TLSV1_2(),)
    else:  # 1.1
        supported_versions = (tls.TLSV1_1(),)

    # Signature algorithms: include RSA-PSS only when TLS 1.3 is possible
    sig_algs = []
    if tls_version_str == '1.3':
        sig_algs += [
            signature_algorithms.RsaPssRsaeSha256,
            signature_algorithms.RsaPssRsaeSha384,
            signature_algorithms.RsaPssRsaeSha512,
        ]
    sig_algs += [
        signature_algorithms.RsaPkcs1Sha256,
        signature_algorithms.RsaPkcs1Sha1,
        signature_algorithms.EcdsaSecp256r1Sha256,
        signature_algorithms.EcdsaSecp384r1Sha384,
    ]

    exts = (
        extensions.ServerNameExtension(host),
        extensions.SignatureAlgorithmExtension(sig_algs),
        extensions.ECPointFormatsExtension(),
        extensions.ApplicationLayerProtocolNegotiationExtension((
            constants.EXTENSION_ALPN_HTTP_1_1,
            # constants.EXTENSION_ALPN_HTTP_2,
        )),
        extensions.SupportedGroupsExtension((
            ec_curves.X25519(), ec_curves.SECP256R1(), ec_curves.SECP384R1()
        )),
        # client.py auto-injects key_share + psk_key_exchange_modes when TLS 1.3 is listed
        extensions.SupportedVersionsExtension(supported_versions),
        # extensions.SessionTicketExtension()
        # extensions.SignedCertificateTimestampExtension(),
        # extensions.StatusRequestExtension()
    )

    if cipher:
        cipher_suites = [cipher]
    else:
        cipher_suites = (
            # TLS 1.2 fallback suites (TLS 1.3 suites prepended automatically by client.py)
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-RSA-AES256-SHA',
            'AES256-GCM-SHA384',
            'AES256-SHA256',
            'AES256-SHA',
            'AES128-SHA',
        )
        # cipher_suites = ('ECDHE-RSA-AES128-SHA',)
        # cipher_suites = ('DHE-RSA-AES128-SHA', )
        # cipher_suites = ('AES256-SHA', )
        # cipher_suites = ('AES256-GCM-SHA384', )
        # cipher_suites = ('ECDHE-RSA-AES256-SHA384', )
        # cipher_suites = ('ECDHE-RSA-AES256-GCM-SHA384', )
        # cipher_suites = ('ECDHE-ECDSA-AES256-GCM-SHA384',)

    ssl_key_logfile = os.getenv('SSLKEYLOGFILE')

    client = Client(host, port, base_version, cipher_suites, extensions=exts,
                    match_hostname=True, ssl_key_logfile=ssl_key_logfile)
    client.run()


if __name__ == '__main__':
    parsed_args = args()
    host = parsed_args.host
    if host == '-':
        for host in sys.stdin:
            host = host.strip()
            if host == '':
                continue
            run(host, parsed_args.cipher, parsed_args.tls_version)
    else:
        run(host, parsed_args.cipher, parsed_args.tls_version)
