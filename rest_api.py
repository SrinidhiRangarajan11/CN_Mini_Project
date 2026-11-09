import json
import ipaddress

from ryu.app.wsgi import ControllerBase, route
from webob import Response


class AuthPolicyAPI(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(AuthPolicyAPI, self).__init__(req, link, data, **config)
        self.sdn_app = data['sdn_app']

    @route('auth_policy', '/auth/policy', methods=['POST'])
    def auth_policy(self, req, **kwargs):

        try:
            body = req.json
            client_ip = str(ipaddress.ip_address(body.get('ip', '')))
            action = body.get('action', '').upper()

        except (ValueError, TypeError, AttributeError):
            return Response(
                status=400,
                body=json.dumps({'error': 'Invalid request'}).encode(),
                content_type='application/json'
            )

        if action == 'GRANT':
            self.sdn_app.grant_client(client_ip)
            message = 'Access granted'

        elif action in ('REVOKE', 'TIMEOUT'):
            self.sdn_app.revoke_client(client_ip)
            message = 'Access revoked'

        elif action == 'BRUTE_FORCE_ALERT':
            self.sdn_app.revoke_client(client_ip)
            self.sdn_app.record_security_event(
                client_ip,
                'Brute-force alert received'
            )
            message = 'Security alert processed'

        else:
            return Response(
                status=400,
                body=json.dumps({'error': 'Unknown action'}).encode(),
                content_type='application/json'
            )

        return Response(
            status=200,
            body=json.dumps({'status': 'success', 'message': message}).encode(),
            content_type='application/json'
        )
