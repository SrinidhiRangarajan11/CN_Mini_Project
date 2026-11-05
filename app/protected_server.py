import socket
import threading

def handle_service_client(client_socket, client_address):
    """Handles connections from authorized clients to the protected service."""
    client_ip = client_address[0]
    print(f"[PROTECTED SERVICE] Authorized connection accepted from {client_ip}")
    try:
        welcome_message = "WELCOME TO THE PROTECTED SERVICE: Access Granted by SDN Controller!\n"
        client_socket.sendall(welcome_message.encode('utf-8'))
    except Exception as e:
        print(f"[PROTECTED SERVICE ERROR] {e}")
    finally:
        client_socket.close()

def run_protected_server(host='0.0.0.0', port=8080):
    """Starts the protected target TCP server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] Protected Target Server running on {host}:{port}...")
    
    try:
        while True:
            client_socket, client_address = server.accept()
            client_thread = threading.Thread(
                target=handle_service_client, 
                args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Protected Server...")
    finally:
        server.close()

if __name__ == "__main__":
    run_protected_server()
