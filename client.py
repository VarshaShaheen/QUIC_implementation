# client.py
import os
from quic import (generate_ecdhe_key_pair, serialize_public_key)


def generate_client_hello_payload(client_public_key_serialized):
    handshake_type_client_hello = b'\x01'
    tls_version = b'\x03\x03'  # TLS 1.3 version number for compatibility
    client_random = os.urandom(32)
    session_id = b'\x00'
    cipher_suites = b'\x13\x01'  # TLS_AES_128_GCM_SHA256
    cipher_suites_length = b'\x00\x02'
    compression_methods = b'\x00'
    compression_methods_length = b'\x01'

    client_hello = (
            handshake_type_client_hello +
            b'\x00\x00\x00' +  # Placeholder for length
            tls_version +
            client_random +
            session_id +
            cipher_suites_length + cipher_suites +
            compression_methods_length + compression_methods +
            b'\x00\x00'  # Extensions length - assume no extensions for simplicity
            + client_public_key_serialized  # Append serialized public key
    )

    client_hello_length = len(client_hello) - 4
    client_hello = (
            client_hello[:1] +
            client_hello_length.to_bytes(3, byteorder='big') +
            client_hello[4:]
    )

    crypto_frame = (
            b'\x06' +  # Frame type for CRYPTO
            b'\x00' +  # Start of the crypto stream
            len(client_hello).to_bytes(2, byteorder='big') +
            client_hello
    )

    return crypto_frame
