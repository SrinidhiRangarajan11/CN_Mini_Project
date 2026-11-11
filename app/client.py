import socket
import sys

def run_client():
    auth_server_ip = '10.0.0.2'
    auth_server_port = 9000
    
    print("[CLIENT] Connecting to TCP Authentication Server...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((auth_server_ip, auth_server_port))
    except Exception as e:
        print(f"[ERROR] Could not connect to auth server: {e}")
        return

    username = input("Enter username (e.g. alice, bob): ").strip()
    password = input("Enter password (e.g. password123): ").strip()
    
    login_payload = f"LOGIN {username} {password}\n"
    sock.sendall(login_payload.encode('utf-8'))
    
    response = sock.recv(1024).decode('utf-8')
    print(f"[SERVER RESPONSE] {response.strip()}")
    
    if "AUTH_OK" in response:
        print("[+] Authentication Successful!")
        
        test_service = input("Would you like to test connecting to the Protected Service? (y/n): ").strip()
        if test_service.lower() == 'y':
            try:
                service_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                service_sock.connect(('10.0.0.3', 8080))
                msg = service_sock.recv(1024).decode('utf-8')
                print(f"[PROTECTED SERVICE DATA] {msg.strip()}")
                service_sock.close()
            except Exception as e:
                print(f"[-] Access Blocked / Failed to reach protected service: {e}")
        
        logout = input("Would you like to logout now? (y/n): ").strip()
        if logout.lower() == 'y':
            sock.sendall(b"LOGOUT\n")
            logout_resp = sock.recv(1024).decode('utf-8')
            print(f"[SERVER RESPONSE] {logout_resp.strip()}")
            
    else:
        print("[-] Authentication Failed. Access denied.")
        
    sock.close()

if __name__ == '__main__':
    run_client()
