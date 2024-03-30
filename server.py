# server.py
import os
from quic import (generate_ecdhe_key_pair, serialize_public_key)


def generate_server_hello_payload(server_public_key_serialized):
    handshake_type_server_hello = b'\x02'
    tls_version = b'\x03\x03'
    server_random = os.urandom(32)
    session_id = b'\x00'
    cipher_suite = b'\x13\x01'
    compression_method = b'\x00'

    server_hello = (
            handshake_type_server_hello +
            b'\x00\x00\x00' +
            tls_version +
            server_random +
            session_id +
            cipher_suite +
            compression_method +
            b'\x00\x00'  # Extensions length - assume no extensions for simplicity
            + server_public_key_serialized  # Append serialized public key
    )

    server_hello_length = len(server_hello) - 4
    server_hello = (
            server_hello[:1] +
            server_hello_length.to_bytes(3, byteorder='big') +
            server_hello[4:]
    )

    crypto_frame = (
            b'\x06' +  # Frame type for CRYPTO
            b'\x00' +  # Start of the crypto stream
            len(server_hello).to_bytes(2, byteorder='big') +
            server_hello
    )

    return crypto_frame
