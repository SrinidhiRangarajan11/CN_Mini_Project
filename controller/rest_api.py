import json
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from controller import config


def start_auth_api(sdn_app, host, port):

    class AuthPolicyHandler(BaseHTTPRequestHandler):

        def send_json(self, status, data):
            response = json.dumps(data).encode('utf-8')

            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(response)

        def do_POST(self):

            # Only the authentication server can request policy changes.
            source_ip = self.client_address[0]

            if source_ip != config.AUTH_SERVER_IP:
                self.send_json(403, {
                    'error': 'Forbidden: Unauthorized source IP'
                })
                return

            if self.path != '/auth/policy':
                self.send_json(404, {
                    'error': 'Endpoint not found'
                })
                return

            try:
                length = int(self.headers.get('Content-Length', 0))

                if length <= 0 or length > 4096:
                    self.send_json(400, {
                        'error': 'Invalid request size'
                    })
                    return

                body = json.loads(self.rfile.read(length))

                if not isinstance(body, dict):
                    raise ValueError('Invalid JSON body')

                client_ip = str(
                    ipaddress.ip_address(body.get('ip', ''))
                )

                action = body.get('action')

                if not isinstance(action, str):
                    raise ValueError('Invalid action')

                action = action.upper()

            except (ValueError, TypeError, AttributeError):
                self.send_json(400, {
                    'error': 'Invalid request'
                })
                return

            try:
                if action == 'GRANT':
                    sdn_app.grant_client(client_ip)
                    message = 'Access granted'

                elif action in ('REVOKE', 'TIMEOUT'):
                    sdn_app.revoke_client(client_ip)
                    message = 'Access revoked'

                elif action == 'BRUTE_FORCE_ALERT':
                    sdn_app.revoke_client(client_ip)
                    sdn_app.record_security_event(
                        client_ip,
                        'Brute-force alert received'
                    )
                    message = 'Security alert processed'

                else:
                    self.send_json(400, {
                        'error': 'Unknown action'
                    })
                    return

                self.send_json(200, {
                    'status': 'success',
                    'message': message
                })

            except Exception:
                sdn_app.logger.exception(
                    'Failed to process authentication policy request'
                )
                self.send_json(500, {
                    'error': 'Controller failed to process request'
                })

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(
        (host, port),
        AuthPolicyHandler
    )

    server.daemon_threads = True

    thread = Thread(
        target=server.serve_forever,
        daemon=True
    )
    thread.start()

    sdn_app.logger.info(
        "Authentication REST API listening on %s:%s",
        host,
        port
    )

    return server
