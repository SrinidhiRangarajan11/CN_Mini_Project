from mininet.topo import Topo


class AccessControlTopo(Topo):

    def build(self):

        # Main Open vSwitch
        s1 = self.addSwitch('s1')

        # Three client hosts
        clients = [
            ('h1', '10.0.0.1/24'),
            ('h2', '10.0.0.12/24'),
            ('h3', '10.0.0.13/24')
        ]

        for name, ip in clients:
            host = self.addHost(name, ip=ip)
            self.addLink(host, s1)

        # Authentication server
        h_auth = self.addHost(
            'h_auth',
            ip='10.0.0.2/24'
        )
        self.addLink(h_auth, s1)

        # Protected service
        h_service = self.addHost(
            'h_service',
            ip='10.0.0.3/24'
        )
        self.addLink(h_service, s1)


topos = {
    'access': lambda: AccessControlTopo()
}
