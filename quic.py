from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os


def generate_ecdhe_key_pair():
    """
    Generates an ECDHE key pair for the key exchange process.
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def derive_pre_master_secret(private_key, peer_public_key):
    """
    Derives the pre-master secret from the private key and the peer's public key.
    """
    # Compute the shared secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # Deriving the pre-master secret from the shared secret
    pre_master_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'pre-master secret',
        backend=default_backend()
    ).derive(shared_secret)

    return pre_master_secret


def derive_handshake_secrets(shared_secret):
    """
    Derive handshake traffic secrets from the shared secret.
    """
    # Placeholder for the handshake hash, to be replaced with actual data in a real implementation
    salt = os.urandom(32)  # Using random data as a placeholder for the handshake hash

    # Derive the pseudorandom key (prk) from the shared secret and salt
    prk = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'handshake data',  # Placeholder for actual handshake context data
        backend=default_backend()
    ).derive(shared_secret)

    # Derive client_handshake_secret
    client_handshake_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # Not needed for the expand phase
        info=b'tls13 client handshake traffic',
        backend=default_backend()
    ).derive(prk)

    # Derive server_handshake_secret
    server_handshake_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # Not needed for the expand phase
        info=b'tls13 server handshake traffic',
        backend=default_backend()
    ).derive(prk)

    return client_handshake_secret, server_handshake_secret


def create_finished_message(secret, handshake_hash):
    """
    Create the 'Finished' message with HMAC.
    """
    h = hmac.HMAC(secret, hashes.SHA256(), backend=default_backend())
    h.update(handshake_hash)
    return h.finalize()


def create_quic_finished_packet(secret):
    """
    Creates a QUIC packet containing the Finished message.
    """
    handshake_hash = b'\x00' * 32  # Placeholder for actual handshake hash
    finished_message = create_finished_message(secret, handshake_hash)

    packet_type = b'\x02'  # Arbitrary type for Finished message
    payload_length = len(finished_message).to_bytes(2, 'big')
    quic_packet = packet_type + payload_length + finished_message

    return quic_packet


def generate_hello(packet_number: bytes, dcid: bytes, scid: bytes, payload: bytes) -> bytes:
    """
    Generate a QUIC Hello packet (Client or Server)
    """
    version = b'\xff\x00\x00\x1d'  # QUIC draft version
    token_len = b'\x00'
    packet_type_flags = b'\xc0'
    length = len(packet_number) + len(payload)

    quic_packet = bytearray(packet_type_flags)
    quic_packet += version
    quic_packet += len(dcid).to_bytes(1, byteorder='big') + dcid
    quic_packet += len(scid).to_bytes(1, byteorder='big') + scid
    quic_packet += token_len
    quic_packet += length.to_bytes(2, byteorder='big')
    quic_packet += packet_number
    quic_packet += payload

    return bytes(quic_packet)


def decode_quic_packet(quic_packet: bytes):
    """
    Decode a QUIC packet and extract the packet number and payload.
    """
    packet_number = quic_packet[6:14]
    payload = quic_packet[14:]
    return packet_number, payload


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
