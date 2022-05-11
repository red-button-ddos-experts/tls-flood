from collections.abc import Iterable
import os
import socket
from datetime import datetime

from tls_client import constants
from tls_client import tls
from tls_client.cipher_suites import CIPHER_SUITES
from tls_client.packer import pack, prepend_length, record
from tls_client.reader import read


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
    def __init__(self, host, port, tls_version, ciphers, *, extensions=None, match_hostname=True, debug=True,
                 ssl_key_logfile=None):
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
        ciphers = ciphers if isinstance(ciphers, Iterable) else tuple(ciphers)
        self.ciphers = tuple(CIPHER_SUITES[cipher] for cipher in ciphers if cipher in CIPHER_SUITES)
        self.extensions = extensions
        self.messages = []
        self.cipher_suite = None
        self.server_certificate = None
        self.match_hostname = match_hostname
        self.http_version = None

        try:
            self.conn = socket.create_connection((host, port))
        except ConnectionRefusedError:
            print("ERROR: Couldn't establish a connection with", host, "on port", port)
            exit(-1)
        self.debug = debug
        self.ssl_key_logfile = ssl_key_logfile
        self.is_server_key_exchange = None

    def debug_print(self, title, message, *, prefix='\t'):
        if self.debug:
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

    def client_hello(self, verbose):
        ciphers = b''.join(int(cipher['id'], 16).to_bytes(2, 'big') for cipher in self.ciphers)

        session_id_bytes = prepend_length(self.session_id, len_byte_size=1)

        cipher_suites_bytes = prepend_length(ciphers, len_byte_size=2)

        compression_method_bytes = prepend_length(b'\x00', len_byte_size=1)

        extensions_bytes = prepend_length(b''.join(map(bytes, self.extensions)), len_byte_size=2)

        client_hello_bytes = self.pack(constants.PROTOCOL_CLIENT_HELLO,
                                       self.client_random +
                                       session_id_bytes +
                                       cipher_suites_bytes +
                                       compression_method_bytes +
                                       extensions_bytes
                                       )

        message = self.record(constants.CONTENT_TYPE_HANDSHAKE, client_hello_bytes, tls_version=tls.TLSV1())
        self.conn.send(message)

        print("--- CLIENT REQUEST ---")
        self.debug_print('Host', self.host)
        self.debug_print('Port', self.port)
        self.debug_print('Client random', print_hex(self.client_random))
        self.debug_print('Cipher suite suggested',
                         '{}'.format(', '.join(cipher['openssl_name'] for cipher in self.ciphers)))

        if verbose:
            self.verbose_print()

    def verbose_print(self):
        record_bytes, hello_bytes = self.read(return_record=True)
        assert record_bytes[:1] == constants.CONTENT_TYPE_HANDSHAKE, 'Server return {}'.format(
            print_hex(record_bytes[:1]))

        assert len(hello_bytes) > 0, 'No response from server'
        assert hello_bytes[:1] == b'\x02', 'Not server hello'
        tls_version = hello_bytes[4:6]
        assert tls_version == self.tls_version, 'Not a desired tls version'

        print("--- SERVER RESPONSE ---")
        print("Got ServerHello from server.")
        print("Current TLS version " + str(self.tls_version) + " tls version")
        print("Dump:")
        print(record_bytes)
        print(hello_bytes)
        print("-" * 30)

    def run(self, verbose: bool):
        self.client_hello(verbose)
