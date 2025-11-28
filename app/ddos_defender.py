# """
# Ryu Controller với khả năng phát hiện và ngăn chặn DDoS
# Sử dụng flow statistics để detect traffic anomaly
# """

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp
from ryu.lib import hub
from collections import defaultdict
import time

class DDoSDefender(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDefender, self).__init__(*args, **kwargs)
        
        # MAC learning table
        self.mac_to_port = {}
        
        # DDoS Detection variables
        self.flow_stats = {}
        self.packet_count = defaultdict(int)
        self.last_check = time.time()
        
        # Thresholds
        self.PACKET_THRESHOLD = 100  # packets per second
        self.CHECK_INTERVAL = 5  # seconds
        
        # Blacklist
        self.blacklist = set()
        
        # Start monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Khởi tạo switch với table-miss flow entry"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.info("Switch %s connected", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        """Thêm flow entry vào switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle,
                                    hard_timeout=hard)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle, hard_timeout=hard)
        datapath.send_msg(mod)

    def block_ip(self, datapath, src_ip):
        """Block một IP address"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Drop packets from this IP
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = []  # Empty actions = drop
        self.add_flow(datapath, 100, match, actions, idle=300)
        
        self.blacklist.add(src_ip)
        self.logger.warning("🚨 BLOCKED IP: %s (DDoS detected)", src_ip)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Xử lý packet-in messages"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Packet counting cho DDoS detection
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            self.packet_count[src_ip] += 1

        # Check if source IP is blacklisted
        if ip_pkt and ip_pkt.src in self.blacklist:
            return  # Drop silently

        # Determine output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow to avoid packet-in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=10)
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle=10)

        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _monitor(self):
        """Monitor thread để detect DDoS"""
        while True:
            hub.sleep(self.CHECK_INTERVAL)
            self._check_for_ddos()

    def _check_for_ddos(self):
        """Kiểm tra DDoS attack dựa trên packet rate"""
        current_time = time.time()
        time_diff = current_time - self.last_check
        
        for src_ip, count in list(self.packet_count.items()):
            rate = count / time_diff
            
            if rate > self.PACKET_THRESHOLD:
                self.logger.warning("⚠️  High traffic from %s: %.2f pkt/s", 
                                  src_ip, rate)
                
                # Block if not already blocked
                if src_ip not in self.blacklist:
                    # Get all datapaths and block on all switches
                    for dp in self.mac_to_port.keys():
                        # You need to store datapath objects to use here
                        pass
            else:
                if count > 0:
                    self.logger.info("✓ Normal traffic from %s: %.2f pkt/s", 
                                   src_ip, rate)
        
        # Reset counters
        self.packet_count.clear()
        self.last_check = current_time
        
        if self.blacklist:
            self.logger.info("🛡️  Currently blocked IPs: %s", 
                           ', '.join(self.blacklist))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Nhận flow statistics từ switches"""
        flows = []
        for stat in ev.msg.body:
            flows.append({
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'duration_sec': stat.duration_sec,
            })
        self.flow_stats[ev.msg.datapath.id] = flows