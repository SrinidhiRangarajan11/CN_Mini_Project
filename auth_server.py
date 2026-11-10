import os
import socket
import threading
import logging
import secrets
import time
import requests

# Project paths and logging
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(RESULTS_DIR, "auth.log"),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Credential store (demonstration purposes)
USER_CREDENTIALS = {
    "alice": "password123",
    "bob": "secure456",
    "charlie": "tcp789"
}

# Active sessions
ACTIVE_SESSIONS = {}
ACTIVE_CLIENTS = {}
SESSION_LOCK = threading.Lock()

# SDN Controller REST API
CONTROLLER_URL = "http://10.0.0.254:8081/auth/policy"


def notify_controller(client_ip, action):
    """Notify the SDN controller about an access-policy change."""

    payload = {
        "ip": client_ip,
        "action": action
    }

    try:
        response = requests.post(
            CONTROLLER_URL,
            json=payload,
            timeout=3
        )

        response.raise_for_status()

        print(
            f"[SDN SYNC] Controller confirmed {action} "
            f"for {client_ip}"
        )

        return True

    except requests.exceptions.RequestException as e:
        logging.error(
            "CONTROLLER_ERROR action=%s ip=%s error=%s",
            action, client_ip, e
        )

        print(f"[SDN SYNC ERROR] {e}")
        return False


def remove_session(client_ip, token):
    """Remove a session from the in-memory session tracker."""

    with SESSION_LOCK:
        ACTIVE_SESSIONS.pop(token, None)

        if ACTIVE_CLIENTS.get(client_ip) == token:
            ACTIVE_CLIENTS.pop(client_ip, None)


def send_response(client_socket, message):
    try:
        client_socket.sendall((message + "\n").encode("utf-8"))
    except OSError:
        pass


def handle_client(client_socket, client_address):
    """Handle one client connection."""

    client_ip = client_address[0]

    print(
        f"[+] Auth connection accepted from "
        f"{client_ip}:{client_address[1]}"
    )

    current_user = None
    current_token = None
    access_granted = False
    reader = None

    try:
        # Read newline-delimited TCP commands.
        reader = client_socket.makefile("r", encoding="utf-8")

        while True:
            data = reader.readline()

            if not data:
                break

            parts = data.strip().split()

            if not parts:
                continue

            command = parts[0].upper()

            if command == "LOGIN":

                if len(parts) != 3:
                    send_response(
                        client_socket,
                        "ERROR Invalid LOGIN syntax"
                    )
                    continue

                if current_token is not None:
                    send_response(
                        client_socket,
                        "AUTH_FAIL Already authenticated"
                    )
                    continue

                username, password = parts[1], parts[2]

                if (
                    username not in USER_CREDENTIALS
                    or USER_CREDENTIALS[username] != password
                ):
                    logging.warning(
                        "FAILED_LOGIN attempt_user=%s ip=%s",
                        username, client_ip
                    )

                    send_response(
                        client_socket,
                        "AUTH_FAIL Invalid credentials"
                    )

                    print(
                        f"[AUTH] Failed login for '{username}' "
                        f"from {client_ip}"
                    )
                    continue

                # Generate an unpredictable session token.
                token = secrets.token_urlsafe(32)

                # This topology uses IP-based access policies.
                # Prevent multiple simultaneous sessions from
                # competing for the same client's access rules.
                with SESSION_LOCK:
                    already_active = client_ip in ACTIVE_CLIENTS

                    if not already_active:
                        ACTIVE_CLIENTS[client_ip] = token

                if already_active:
                    send_response(
                        client_socket,
                        "AUTH_FAIL A session is already active"
                    )
                    continue

                current_user = username
                current_token = token

                # Do not report successful authentication until
                # the controller confirms the GRANT operation.
                if not notify_controller(client_ip, "GRANT"):

                    # Best-effort rollback in case the controller
                    # processed the request but its response was lost.
                    notify_controller(client_ip, "REVOKE")

                    remove_session(client_ip, token)

                    current_user = None
                    current_token = None

                    send_response(
                        client_socket,
                        "AUTH_FAIL Controller unavailable"
                    )
                    continue

                access_granted = True

                with SESSION_LOCK:
                    ACTIVE_SESSIONS[token] = {
                        "username": username,
                        "client_ip": client_ip,
                        "created_at": time.time()
                    }

                logging.info(
                    "SUCCESSFUL_LOGIN user=%s ip=%s",
                    username, client_ip
                )

                print(
                    f"[AUTH] User '{username}' authenticated."
                )

                send_response(
                    client_socket,
                    f"AUTH_OK TOKEN:{token}"
                )

            elif command == "LOGOUT":

                if len(parts) != 1:
                    send_response(
                        client_socket,
                        "ERROR Invalid LOGOUT syntax"
                    )
                    continue

                if current_token is None:
                    send_response(
                        client_socket,
                        "LOGOUT_SUCCESS No active session"
                    )
                    break

                if notify_controller(client_ip, "REVOKE"):

                    access_granted = False

                    logging.info(
                        "LOGOUT user=%s ip=%s",
                        current_user, client_ip
                    )

                    remove_session(client_ip, current_token)

                    current_user = None
                    current_token = None

                    send_response(
                        client_socket,
                        "LOGOUT_SUCCESS"
                    )

                    print(
                        f"[AUTH] Client {client_ip} logged out."
                    )

                else:
                    # Keep the session marked as active so the
                    # finally block can make another revoke attempt.
                    send_response(
                        client_socket,
                        "LOGOUT_FAILED Controller revocation unconfirmed"
                    )

                break

            else:
                send_response(
                    client_socket,
                    "ERROR Unknown command"
                )

    except Exception as e:
        logging.exception(
            "CLIENT_HANDLER_ERROR ip=%s",
            client_ip
        )
        print(f"[ERROR] Client {client_ip}: {e}")

    finally:

        # Revoke access when the TCP connection closes unexpectedly,
        # including when the client chooses not to log out.
        if current_token is not None:

            if access_granted:

                print(
                    f"[AUTH] Revoking access for disconnected "
                    f"client {client_ip}"
                )

                if not notify_controller(client_ip, "REVOKE"):
                    logging.critical(
                        "REVOCATION_FAILED ip=%s; "
                        "access rules may remain installed",
                        client_ip
                    )
                else:
                    logging.info(
                        "DISCONNECT_REVOKE ip=%s user=%s",
                        client_ip, current_user
                    )

            remove_session(client_ip, current_token)

        if reader is not None:
            reader.close()

        client_socket.close()

        print(f"[-] Connection closed for {client_ip}")


def start_auth_server(host="0.0.0.0", port=9000):
    """Start the multithreaded TCP authentication server."""

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind((host, port))
    server.listen(10)

    print(
        f"[*] TCP Auth Server listening on {host}:{port}..."
    )

    try:
        while True:

            client_socket, client_address = server.accept()

            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True
            )

            client_thread.start()

    except KeyboardInterrupt:
        print("\n[*] Shutting down Authentication Server...")

    finally:
        server.close()


if __name__ == "__main__":
    start_auth_server()
