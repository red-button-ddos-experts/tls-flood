import argparse
import os
from time import time

from tls_client import constants
from tls_client import ec_curves
from tls_client import extensions
from tls_client import signature_algorithms
from tls_client import tls
from tls_client.client import Client

MAX_CPS_ALLOWED = 30


def args():
    parser = argparse.ArgumentParser()
    parser.add_argument(dest="host")
    parser.add_argument(dest="cps", type=int)
    parser.add_argument('-c', '--cipher', dest="cipher", default=False, nargs='?')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')
    return parser.parse_args()


def main():
    parsed_args = args()
    host = parsed_args.host
    max_cps = parsed_args.cps
    verbose = parsed_args.verbose
    print('verbose:', verbose)

    if max_cps > MAX_CPS_ALLOWED:
        max_cps = MAX_CPS_ALLOWED
        print("Warning: max cps allowed is 30")

    port = 443
    # TLSv1.0 is not supported
    tls_version = tls.TLSV1_2()

    n_extensions = (
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

    if parsed_args.cipher:
        cipher_suites = [parsed_args.cipher]
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

    # for testing stable fire rate
    start = time()
    amount = 0
    print("CPS used is:", max_cps)

    while True:
        # monitor seconds
        if time() - start >= 1:
            start = time()
            print("CPS:", amount)
            amount = 0

        # monitor amount
        if amount < max_cps:
            client = Client(host, port, tls_version, cipher_suites, extensions=n_extensions, match_hostname=True,
                            ssl_key_logfile=ssl_key_logfile)
            client.run(verbose)
            amount += 1
