import ipaddress


def add_flow(datapath, priority, match, actions=None, cookie=0):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    instructions = []

    if actions is not None:
        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

    flow_mod = parser.OFPFlowMod(
        datapath=datapath,
        cookie=cookie,
        priority=priority,
        match=match,
        instructions=instructions
    )

    datapath.send_msg(flow_mod)


def grant_access(datapath, client_ip, service_ip, service_port):
    parser = datapath.ofproto_parser
    ofproto = datapath.ofproto

    cookie = 0xA000000000000000 | int(
        ipaddress.ip_address(client_ip)
    )

    # Client to protected service
    forward_match = parser.OFPMatch(
        eth_type=0x0800,
        ip_proto=6,
        ipv4_src=client_ip,
        ipv4_dst=service_ip,
        tcp_dst=service_port
    )

    # Protected service to client
    reverse_match = parser.OFPMatch(
        eth_type=0x0800,
        ip_proto=6,
        ipv4_src=service_ip,
        ipv4_dst=client_ip,
        tcp_src=service_port
    )

    actions = [
        parser.OFPActionOutput(ofproto.OFPP_NORMAL)
    ]

    # Priority 400 overrides the default block at 300.
    add_flow(datapath, 400, forward_match, actions, cookie)
    add_flow(datapath, 400, reverse_match, actions, cookie)

    return cookie


def revoke_access(datapath, client_ip):
    parser = datapath.ofproto_parser
    ofproto = datapath.ofproto

    cookie = 0xA000000000000000 | int(
        ipaddress.ip_address(client_ip)
    )

    flow_mod = parser.OFPFlowMod(
        datapath=datapath,
        command=ofproto.OFPFC_DELETE,
        cookie=cookie,
        cookie_mask=0xFFFFFFFFFFFFFFFF,
        table_id=ofproto.OFPTT_ALL,
        out_port=ofproto.OFPP_ANY,
        out_group=ofproto.OFPG_ANY,
        match=parser.OFPMatch()
    )

    datapath.send_msg(flow_mod)
