from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, arp
import hashlib

class LoadBalancerController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancerController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        # Cấu hình Load Balancer - ĐIỀU CHỈNH THEO TOPOLOGY
        self.vip = "10.0.0.100"  # Virtual IP
        self.vip_mac = "00:00:00:00:00:ff"  # Virtual MAC
        
        # Backend servers - CẬP NHẬT IP VÀ MAC THEO TOPOLOGY
        self.backends = [
            {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02"},  # h2
            {"ip": "10.0.0.3", "mac": "00:00:00:00:00:03"},  # h3
            {"ip": "10.0.0.4", "mac": "00:00:00:00:00:04"}   # h4
        ]
        
        # Client host - h1
        self.client_ip = "10.0.0.1"
        
        # Lưu trữ connection mapping
        # Key: (client_ip, client_port, dst_port)
        # Value: backend dict
        self.connection_map = {}
        
        # Statistics
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "backend_stats": {b["ip"]: 0 for b in self.backends}
        }
        
        self.logger.info("="*60)
        self.logger.info("Load Balancer Controller khởi động")
        self.logger.info("VIP: %s (%s)", self.vip, self.vip_mac)
        self.logger.info("Client: %s", self.client_ip)
        self.logger.info("Backends:")
        for i, backend in enumerate(self.backends, 1):
            self.logger.info("  %d. %s (%s)", i, backend["ip"], backend["mac"])
        self.logger.info("="*60)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.logger.info("Switch %s kết nối", datapath.id)
        
        # Table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        # Flow để xử lý ARP request cho VIP
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_ARP,
            arp_tpa=self.vip
        )
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 100, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle_timeout=0, hard_timeout=0):
        """Thêm flow entry"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )
        
        datapath.send_msg(mod)

    def select_backend(self, client_ip, client_port, dst_port):
        """Chọn backend server sử dụng hash-based load balancing"""
        # Tạo key từ client info
        key = f"{client_ip}:{client_port}:{dst_port}"
        
        # Hash để chọn backend
        hash_value = int(hashlib.md5(key.encode()).hexdigest(), 16)
        backend_index = hash_value % len(self.backends)
        
        backend = self.backends[backend_index]
        
        self.logger.info("Backend selected: %s for %s", backend["ip"], key)
        return backend

    def handle_arp(self, datapath, in_port, pkt):
        """Xử lý ARP request cho VIP"""
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt.opcode != arp.ARP_REQUEST:
            return
        
        if arp_pkt.dst_ip != self.vip:
            return
        
        self.logger.info("ARP request cho VIP từ %s", arp_pkt.src_ip)
        
        # Tạo ARP reply
        parser = datapath.ofproto_parser
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Tạo ARP reply packet
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=eth.src,
            src=self.vip_mac
        ))
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=self.vip_mac,
            src_ip=self.vip,
            dst_mac=arp_pkt.src_mac,
            dst_ip=arp_pkt.src_ip
        ))
        arp_reply.serialize()
        
        # Gửi ARP reply
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=arp_reply.data
        )
        datapath.send_msg(out)
        
        self.logger.info("ARP reply sent: VIP MAC = %s", self.vip_mac)

    def install_lb_flows(self, datapath, in_port, src_ip, dst_ip, src_port, 
                        dst_port, backend, eth_src):
        """Cài đặt flows cho load balancing"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # Flow 1: Client -> VIP => Rewrite to Backend
        # Match: từ client đến VIP
        match_c2b = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=self.vip,
            ip_proto=6,  # TCP
            tcp_src=src_port,
            tcp_dst=dst_port
        )
        
        # Actions: Rewrite destination IP và MAC sang backend
        actions_c2b = [
            parser.OFPActionSetField(ipv4_dst=backend["ip"]),
            parser.OFPActionSetField(eth_dst=backend["mac"]),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        
        self.add_flow(datapath, 200, match_c2b, actions_c2b, 
                     idle_timeout=30, hard_timeout=60)
        
        # Flow 2: Backend -> Client => Rewrite from VIP
        # Match: từ backend về client
        match_b2c = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=backend["ip"],
            ipv4_dst=src_ip,
            ip_proto=6,
            tcp_src=dst_port,
            tcp_dst=src_port
        )
        
        # Actions: Rewrite source IP và MAC thành VIP
        actions_b2c = [
            parser.OFPActionSetField(ipv4_src=self.vip),
            parser.OFPActionSetField(eth_src=self.vip_mac),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        
        self.add_flow(datapath, 200, match_b2c, actions_b2c,
                     idle_timeout=30, hard_timeout=60)
        
        self.logger.info("LB flows installed:")
        self.logger.info("  %s:%d -> %s:%d => %s:%d", 
                        src_ip, src_port, self.vip, dst_port,
                        backend["ip"], dst_port)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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
        
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Xử lý ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, in_port, pkt)
            return

        # Xử lý IP packet
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            # Non-IP traffic, xử lý như switch thông thường
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
            
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        # Xử lý TCP packet đến VIP (Load Balancing)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt and dst_ip == self.vip:
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
            
            connection_key = (src_ip, src_port, dst_port)
            
            # Kiểm tra connection đã tồn tại chưa
            if connection_key not in self.connection_map:
                # New connection
                backend = self.select_backend(src_ip, src_port, dst_port)
                self.connection_map[connection_key] = backend
                
                # Update statistics
                self.stats["total_connections"] += 1
                self.stats["active_connections"] += 1
                self.stats["backend_stats"][backend["ip"]] += 1
                
                self.logger.info("="*60)
                self.logger.info("NEW CONNECTION #%d", self.stats["total_connections"])
                self.logger.info("Client: %s:%d -> VIP: %s:%d", 
                               src_ip, src_port, self.vip, dst_port)
                self.logger.info("Backend: %s", backend["ip"])
                self.logger.info("Backend stats: %s", self.stats["backend_stats"])
                self.logger.info("="*60)
            else:
                backend = self.connection_map[connection_key]
            
            # Cài đặt flows cho connection này
            self.install_lb_flows(datapath, in_port, src_ip, dst_ip,
                                 src_port, dst_port, backend, eth.src)
            
            # Forward packet đầu tiên
            actions = [
                parser.OFPActionSetField(ipv4_dst=backend["ip"]),
                parser.OFPActionSetField(eth_dst=backend["mac"]),
                parser.OFPActionOutput(ofproto.OFPP_NORMAL)
            ]
            
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)
            
        else:
            # Non-LB traffic, xử lý như switch thông thường
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
            
            actions = [parser.OFPActionOutput(out_port)]
            
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 1, match, actions)
            
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """Xử lý khi flow bị remove (timeout)"""
        msg = ev.msg
        match = msg.match
        
        # Giảm active connections khi flow timeout
        if 'ipv4_src' in match and 'tcp_src' in match:
            src_ip = match['ipv4_src']
            src_port = match['tcp_src']
            dst_port = match['tcp_dst']
            
            connection_key = (src_ip, src_port, dst_port)
            if connection_key in self.connection_map:
                del self.connection_map[connection_key]
                self.stats["active_connections"] -= 1
                
                self.logger.info("Connection closed: %s:%d (Active: %d)",
                               src_ip, src_port, self.stats["active_connections"])