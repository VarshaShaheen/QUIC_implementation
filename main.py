import socket
import threading
import os
from quic import (generate_ecdhe_key_pair, serialize_public_key, deserialize_public_key,
                  derive_pre_master_secret, derive_handshake_secrets, create_finished_message,
                  create_quic_finished_packet, generate_hello, decode_quic_packet)
from client import generate_client_hello_payload  # This needs to be adjusted if it's not already
from server import generate_server_hello_payload  # Adjusted to accept server_public_key_serialized

HOST = '127.0.0.1'
CLIENT_PORT = 65432
SERVER_PORT = 65431


def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((HOST, SERVER_PORT))

    # Generate server's ECDHE key pair and serialize the public key
    server_private_key, server_public_key = generate_ecdhe_key_pair()
    server_public_key_serialized = serialize_public_key(server_public_key)

    # Wait for ClientHello, which in this implementation, is expected to include the client's public key
    data, client_addr = server_socket.recvfrom(1024)
    print("Server received ClientHello.")

    # Extract client's public key from received data
    # For simplicity, assume the client's public key directly follows the ClientHello message
    client_public_key_serialized = data[-len(server_public_key_serialized):]  # Adjust according to your protocol
    client_public_key = deserialize_public_key(client_public_key_serialized)

    # Generate and send ServerHello, including the server's public key
    server_hello_payload = generate_server_hello_payload(server_public_key_serialized)
    server_socket.sendto(server_hello_payload, client_addr)
    print("Server sent ServerHello.")

    # Derive the shared secret for further communication
    pre_master_secret = derive_pre_master_secret(server_private_key, client_public_key)
    _, server_secret = derive_handshake_secrets(pre_master_secret)

    # Send Finished message to conclude the handshake
    finished_message = create_quic_finished_packet(server_secret)
    server_socket.sendto(finished_message, client_addr)
    print("Server sent Finished message.")

    server_socket.close()


def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Generate client's ECDHE key pair
    client_private_key, client_public_key = generate_ecdhe_key_pair()

    # Serialize the public key
    client_public_key_serialized = serialize_public_key(client_public_key)

    # Generate ClientHello payload with the serialized public key
    client_hello_payload = generate_client_hello_payload(client_public_key_serialized)
    client_socket.sendto(client_hello_payload, (HOST, SERVER_PORT))
    print("Client sent ClientHello.")

    # Wait for ServerHello, which includes the server's public key
    server_hello, _ = client_socket.recvfrom(1024)
    print("Client received ServerHello.")
    server_public_key_serialized = server_hello[-len(client_public_key_serialized):]  # Adjust accordingly
    server_public_key = deserialize_public_key(server_public_key_serialized)

    # Derive the shared secret for further communication
    pre_master_secret = derive_pre_master_secret(client_private_key, server_public_key)
    client_secret, _ = derive_handshake_secrets(pre_master_secret)

    # Wait for Finished message from the server
    finished_message, _ = client_socket.recvfrom(1024)
    print("Client received Finished message.")

    client_socket.close()


if __name__ == "__main__":
    server_thread = threading.Thread(target=server)
    client_thread = threading.Thread(target=client)

    server_thread.start()
    client_thread.start()

    server_thread.join()
    client_thread.join()
