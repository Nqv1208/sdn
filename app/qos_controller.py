from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp

class QoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(QoSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # Cấu hình QoS - ĐIỀU CHỈNH THEO TOPOLOGY CỦA BẠN
        self.qos_config = {
            # Luồng ưu tiên: h1 (10.0.0.1) -> h4 (10.0.0.4)
            "priority_flows": [
                {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.4", "meter_id": 1},
            ],
            # Luồng thường: h2 (10.0.0.2) -> h5 (10.0.0.5)
            "normal_flows": [
                {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.5", "meter_id": 2},
            ],
            # Cấu hình meter (bits per second)
            "meters": {
                1: {"rate": 100000, "burst": 10000},  # Priority: 100 Mbps
                2: {"rate": 10000, "burst": 1000}     # Normal: 10 Mbps
            }
        }

        self.logger.info("QoS Controller khởi động")
        self.logger.info("Priority flows: %s", self.qos_config["priority_flows"])
        self.logger.info("Normal flows: %s", self.qos_config["normal_flows"])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Switch %s kết nối", datapath.id)

        # Cài đặt meters
        self._install_meters(datapath)

        # Table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def _install_meters(self, datapath):
        """Cài đặt OpenFlow meters cho QoS"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        for meter_id, config in self.qos_config["meters"].items():
            # Tạo meter band (drop nếu vượt rate)
            bands = [parser.OFPMeterBandDrop(
                rate=config["rate"],      # kbps
                burst_size=config["burst"]
            )]
            
            # Tạo meter modification message
            req = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_ADD,
                flags=ofproto.OFPMF_KBPS,  # Rate in kbps
                meter_id=meter_id,
                bands=bands
            )
            
            datapath.send_msg(req)
            self.logger.info("Meter %d installed: rate=%d kbps, burst=%d", 
                           meter_id, config["rate"], config["burst"])

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, 
                 meter_id=None, idle_timeout=0, hard_timeout=0):
        """Thêm flow với tùy chọn meter"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Tạo instructions
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        # Thêm meter instruction nếu có
        if meter_id:
            inst.insert(0, parser.OFPInstructionMeter(meter_id))
        
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

    def _check_qos_flow(self, src_ip, dst_ip):
        """Kiểm tra xem flow có cần QoS không"""
        # Kiểm tra priority flows
        for flow in self.qos_config["priority_flows"]:
            if src_ip == flow["src_ip"] and dst_ip == flow["dst_ip"]:
                return flow["meter_id"], "priority"
        
        # Kiểm tra normal flows
        for flow in self.qos_config["normal_flows"]:
            if src_ip == flow["src_ip"] and dst_ip == flow["dst_ip"]:
                return flow["meter_id"], "normal"
        
        return None, None

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

        # Xử lý IPv4 packet để áp dụng QoS
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        meter_id = None
        qos_type = None
        
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            meter_id, qos_type = self._check_qos_flow(src_ip, dst_ip)
            
            if meter_id:
                self.logger.info("QoS flow detected: %s -> %s (type=%s, meter=%d)",
                               src_ip, dst_ip, qos_type, meter_id)

        # Xác định output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Cài đặt flow
        if out_port != ofproto.OFPP_FLOOD:
            if ip_pkt and meter_id:
                # Flow với QoS (có meter)
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip
                )
                # Priority cao hơn cho QoS flows
                priority = 100 if qos_type == "priority" else 50
                self.add_flow(datapath, priority, match, actions, 
                            meter_id=meter_id, idle_timeout=30, hard_timeout=60)
                
                self.logger.info("Flow installed with QoS: priority=%d, meter=%d", 
                               priority, meter_id)
            else:
                # Flow thông thường (không có meter)
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 1, match, actions)

        # Gửi packet đi
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

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_reply_handler(self, ev):
        """Nhận meter statistics"""
        meters = []
        for stat in ev.msg.body:
            meters.append('meter_id=0x%08x flow_count=%d '
                        'packet_in_count=%d byte_in_count=%d '
                        'duration_sec=%d duration_nsec=%d' %
                        (stat.meter_id, stat.flow_count,
                         stat.packet_in_count, stat.byte_in_count,
                         stat.duration_sec, stat.duration_nsec))
        self.logger.info('MeterStats: %s', meters)
