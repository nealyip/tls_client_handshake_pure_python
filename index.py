import argparse
import os
import sys

import constants
import ec_curves
import extensions
import signature_algorithms
import tls
from client import Client


def args():
    parser = argparse.ArgumentParser()
    parser.add_argument(dest="host")
    parser.add_argument('-c', '--cipher', dest="cipher", default=False, nargs='?')
    return parser.parse_args()

def run(host, cipher):
    port = 443
    # TLSv1.0 is not supported
    tls_version = tls.TLSV1_2()

    exts = (
        extensions.ServerNameExtension(host),
        extensions.SignatureAlgorithmExtension((
            signature_algorithms.RsaPkcs1Sha256,
            signature_algorithms.RsaPkcs1Sha1,
            signature_algorithms.EcdsaSecp256r1Sha256,
            signature_algorithms.EcdsaSecp384r1Sha384
        )),
        extensions.ECPointFormatsExtension(),
        extensions.ApplicationLayerProtocolNegotiationExtension((
            constants.EXTENSION_ALPN_HTTP_1_1,
            # constants.EXTENSION_ALPN_HTTP_2,
        )),
        extensions.SupportedGroupsExtension((ec_curves.SECP256R1(),)),
        extensions.SupportedVersionsExtension((tls_version,)),
        # extensions.SessionTicketExtension()
        # extensions.SignedCertificateTimestampExtension(),
        # extensions.StatusRequestExtension()
    )

    if cipher:
        cipher_suites = [cipher]
    else:
        cipher_suites = (
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

    client = Client(host, port, tls_version, cipher_suites, extensions=exts, match_hostname=True,
                    ssl_key_logfile=ssl_key_logfile)
    client.run()

if __name__ == '__main__':
    parsed_args = args()
    host = parsed_args.host
    if host == '-':
        for host in sys.stdin:
            host = host.strip()
            if host == '':
                continue
            run(host, parsed_args.cipher)
    else:
        run(host, parsed_args.cipher)
