import socket
import threading
import logging
import requests

logging.basicConfig(
    filename='results/auth.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

USER_CREDENTIALS = {
    "alice": "password123",
    "bob": "secure456",
    "charlie": "tcp789"
}

ACTIVE_SESSIONS = {}

# Configured according to Member 2's controller/config.py settings (REST_PORT = 8081)
CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 8081
CONTROLLER_URL = f"http://{CONTROLLER_IP}:{CONTROLLER_PORT}/auth/policy"

def notify_controller(client_ip, action):
    payload = {"ip": client_ip, "action": action}
    try:
        response = requests.post(CONTROLLER_URL, json=payload, timeout=3)
        if response.status_code == 200:
            print(f"[SDN SYNC] Successfully notified controller: Action '{action}' for IP {client_ip}")
        else:
            print(f"[SDN SYNC WARNING] Controller responded with status {response.status_code}: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[SDN SYNC ERROR] Could not reach SDN controller at {CONTROLLER_URL}: {e}")

def handle_client(client_socket, client_address):
    client_ip = client_address[0]
    print(f"[+] Auth connection accepted from {client_ip}:{client_address[1]}")
    current_user = None
    
    try:
        while True:
            data = client_socket.recv(1024).decode('utf-8').strip()
            if not data:
                break
                
            parts = data.split(' ')
            command = parts[0].upper()
            
            if command == "LOGIN" and len(parts) == 3:
                username, password = parts[1], parts[2]
                
                if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
                    token = f"TOKEN_{username}_XYZ999"
                    ACTIVE_SESSIONS[token] = username
                    current_user = username
                    
                    response = f"AUTH_OK TOKEN:{token}\n"
                    client_socket.sendall(response.encode('utf-8'))
                    
                    logging.info(f"SUCCESSFUL_LOGIN user={username} ip={client_ip}")
                    print(f"[AUTH] User '{username}' authenticated successfully.")
                    notify_controller(client_ip, "GRANT")
                else:
                    response = "AUTH_FAIL Invalid credentials\n"
                    client_socket.sendall(response.encode('utf-8'))
                    logging.warning(f"FAILED_LOGIN attempt_user={username} ip={client_ip}")
                    
            elif command == "LOGOUT":
                if current_user:
                    logging.info(f"LOGOUT user={current_user} ip={client_ip}")
                notify_controller(client_ip, "REVOKE")
                client_socket.sendall(b"LOGOUT_SUCCESS\n")
                break
            else:
                client_socket.sendall(b"ERROR Unknown command or bad syntax\n")
                
    except Exception as e:
        print(f"[ERROR] Exception with client {client_ip}: {e}")
    finally:
        client_socket.close()

def start_auth_server(host='0.0.0.0', port=9000):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] TCP Auth Server listening on {host}:{port}...")
    try:
        while True:
            client_socket, client_address = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Auth Server...")
    finally:
        server.close()

if __name__ == "__main__":
    start_auth_server()
