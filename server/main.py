import socket
import threading

from server import *

def handle_request(server:Server, request_header:RequestHeader, payload:bytes):
    if request_header.code == REQUEST_REGISTER:
        return server.register_client(request_header, payload)
    elif request_header.code == REQUEST_KEY_SHARE:
        return server.share_key(request_header, payload)
    elif request_header.code == REQUEST_LOGIN:
        return server.login(request_header, payload)
    elif request_header.code == REQUEST_SEND_FILE:
        return server.receive_file(request_header, payload)
    elif request_header.code == REQUEST_VALID_CRC:
        return server.confirm_valid_crc(request_header, payload)
    elif request_header.code == REQUEST_INVALID_CRC:
        return server.confirm_invalid_crc(request_header, payload)
    elif request_header.code == REQUEST_LAST_INVALID_CRC:
        return server.confirm_last_invalid_crc()
    else:
        return False

def handle_client(sock, address):
    print(f"[NEW CONNECTION] : {address} connected.")
    server = Server(sock)
    while True:
        try:
            request_header_buf = sock.recv(REQUEST_HDR_SIZE)
            request_header = RequestHeader()
            request_header.parse_from_bytes(request_header_buf)

            payload = bytes()
            if request_header.payload_size != 0:
                while len(payload) < request_header.payload_size:
                    if (request_header.payload_size - len(payload)) > 0:
                        packet = sock.recv(request_header.payload_size - len(payload))
                        if not packet:
                            break
                        payload += packet
                    else:
                        break

            if not handle_request(server, request_header, payload):
                break

        except Exception as e:
            print(f"*** EXCEPTION: {e}")
            break
    server.db_connection.close()
    sock.close()


def main():
    if not os.path.exists(OUT_FILE_PATH):
        os.makedirs(OUT_FILE_PATH)

    port = SERVER_PORT
    try:
        port_file = open(INFO_FILE_NAME, "r")
        port = int(port_file.read())
        port_file.close()
    except FileNotFoundError as e:
        pass

    address = (SERVER_IP, port)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(address)
    server_sock.listen()
    print(f"[STARTING] : Server running on {SERVER_IP}:{port}")
    try:
        while True:
            sock, address = server_sock.accept()
            thread = threading.Thread(target=handle_client, args=(sock, address))
            thread.start()

    except Exception as e:
        print(f"[EXCEPTION] : {e}")


if __name__ == "__main__":
    main()
