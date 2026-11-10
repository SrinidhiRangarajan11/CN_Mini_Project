
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types

from controller import config
from controller.flow_manager import grant_access, revoke_access
from controller.access_logger import log_access, log_security_event
from controller.rest_api import start_auth_api


class SDNAuthController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNAuthController, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.mac_to_port = {}

        self.auth_api_server = start_auth_api(
            self, config.REST_HOST, config.REST_PORT
        )

        self.logger.info("SDN Authentication Controller started")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Block unauthenticated TCP access to protected service
        match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,
            ipv4_dst=config.PROTECTED_SERVICE_IP,
            tcp_dst=config.PROTECTED_SERVICE_PORT
        )

        drop_flow = parser.OFPFlowMod(
            datapath=datapath,
            priority=config.BLOCK_PRIORITY,
            match=match,
            instructions=[]
        )
        datapath.send_msg(drop_flow)

        # Send unknown packets to controller
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        table_miss = parser.OFPFlowMod(
            datapath=datapath,
            priority=config.TABLE_MISS_PRIORITY,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(table_miss)

        log_access("ALL", "SWITCH_CONNECTED", "Switch connected")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        src = eth.src
        dst = eth.dst

        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(
            dst, ofproto.OFPP_FLOOD
        )

        actions = [parser.OFPActionOutput(out_port)]

        # Install a forwarding rule for known destinations
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src,
                eth_dst=dst
            )

            instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions
                )
            ]

            flow = parser.OFPFlowMod(
                datapath=datapath,
                priority=config.MAC_FORWARD_PRIORITY,
                match=match,
                instructions=instructions
            )
            datapath.send_msg(flow)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    def grant_client(self, client_ip):
        for datapath in self.datapaths.values():
            grant_access(
                datapath,
                client_ip,
                config.PROTECTED_SERVICE_IP,
                config.PROTECTED_SERVICE_PORT
            )

        log_access(
            client_ip,
            "GRANT",
            "Protected service access granted"
        )

    def revoke_client(self, client_ip):
        for datapath in self.datapaths.values():
            revoke_access(datapath, client_ip)

        log_access(
            client_ip,
            "REVOKE",
            "Protected service access revoked"
        )

    def record_security_event(self, client_ip, message):
        log_security_event(client_ip, message)
