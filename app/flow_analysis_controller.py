# Lab 3: Advanced DDoS Detection Controller
# Features:
# - Multi-metric flow analysis
# - Statistical anomaly detection
# - Entropy-based detection
# - Simple ML classification
# - Real-time mitigation

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.lib import hub
from collections import defaultdict, deque
from datetime import datetime
import time
import math
import numpy as np

from app import state_store, command_store

class FlowAnalysisDDoSDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowAnalysisDDoSDetector, self).__init__(*args, **kwargs)
        
        # Network state
        self.datapaths = {}
        self.mac_to_port = {}
        
        # === FLOW STATISTICS ===
        self.flow_stats = defaultdict(dict)
        self.port_stats = defaultdict(dict)
        
        # === PER-HOST METRICS ===
        self.host_metrics = defaultdict(lambda: {
            'packet_count': deque(maxlen=30),      # Last 30 samples
            'byte_count': deque(maxlen=30),
            'flow_count': deque(maxlen=30),
            'protocol_dist': defaultdict(int),      # TCP/UDP/ICMP count
            'port_dist': defaultdict(int),          # Destination ports
            'packet_size': deque(maxlen=100),       # Packet sizes
            'inter_arrival': deque(maxlen=100),     # Inter-arrival times
            'tcp_flags': defaultdict(int),          # SYN, ACK, FIN, etc.
            'last_seen': time.time(),
            'flow_rate': 0,
            'packet_rate': 0,
            'byte_rate': 0,
        })
        
        # === DETECTION THRESHOLDS ===
        self.thresholds = {
            'packet_rate': 100,        # packets/sec
            'byte_rate': 1000000,      # bytes/sec (1MB/s)
            'flow_rate': 50,           # new flows/sec
            'syn_ratio': 0.7,          # SYN packets / Total TCP
            'entropy_threshold': 2.0,   # Shannon entropy
            'small_packet_ratio': 0.8, # Small packets (<100 bytes)
        }
        
        # === ATTACK DETECTION STATE ===
        self.blacklist = set()
        self.greylist = {}  # IP -> warning_count
        self.whitelist = set()  # Trusted IPs
        
        # === ANOMALY SCORES ===
        self.anomaly_scores = defaultdict(float)
        
        # === ATTACK STATISTICS ===
        self.attack_stats = {
            'total_attacks_detected': 0,
            'syn_floods': 0,
            'udp_floods': 0,
            'http_floods': 0,
            'icmp_floods': 0,
            'blocked_ips': set(),
            'total_packets_blocked': 0,
        }
        
        # === ML FEATURES (Simple) ===
        self.feature_history = defaultdict(lambda: deque(maxlen=100))
        
        # === MONITORING THREADS ===
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.stats_request_thread = hub.spawn(self._stats_request_loop)
        self.analysis_thread = hub.spawn(self._analysis_loop)
        self.command_thread = hub.spawn(self._command_loop)
        
        # Timing
        self.last_analysis = time.time()
        self.start_time = time.time()

    # ==================== SWITCH INITIALIZATION ====================
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Initialize switch with table-miss flow"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.datapaths[dpid] = datapath
        self.logger.info('🟢 Switch %016x connected', dpid)

        # Install table-miss
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, 
                 buffer_id=None, idle=0, hard=0):
        """Add flow entry to switch"""
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

    # ==================== PACKET PROCESSING ====================
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Process incoming packets and extract features"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == 0x88cc:  # LLDP
            return

        dst = eth.dst
        src = eth.src

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # === DEEP PACKET INSPECTION ===
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            # Check blacklist
            if src_ip in self.blacklist:
                self.attack_stats['total_packets_blocked'] += 1
                return  # Drop silently
            
            # Extract features
            self._extract_packet_features(pkt, src_ip, dst_ip, len(msg.data))
            
            # Check for anomalies (quick check)
            if self._quick_anomaly_check(src_ip):
                self.logger.warning('⚠️  Quick anomaly detected from %s', src_ip)

        # === NORMAL SWITCHING (L2 learning, handle ARP/IP) ===
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow for known destination (covers ARP + IP)
        if out_port != ofproto.OFPP_FLOOD:
            l2_match = parser.OFPMatch(in_port=in_port,
                                       eth_src=src,
                                       eth_dst=dst)
            # Prefer specific IP match when available
            if ip_pkt:
                l3_match = parser.OFPMatch(in_port=in_port,
                                           eth_type=0x0800,
                                           ipv4_src=ip_pkt.src,
                                           ipv4_dst=ip_pkt.dst)
                match = l3_match
            else:
                match = l2_match

            if msg.buffer_id != ofproto.OFPP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions,
                              msg.buffer_id, idle=10)
                return
            else:
                self.add_flow(datapath, 10, match, actions, idle=10)

        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    # ==================== FEATURE EXTRACTION ====================
    
    def _extract_packet_features(self, pkt, src_ip, dst_ip, pkt_size):
        """Extract features from packet for analysis"""
        metrics = self.host_metrics[src_ip]
        current_time = time.time()
        
        # Packet size
        metrics['packet_size'].append(pkt_size)
        
        # Inter-arrival time
        if metrics['last_seen']:
            inter_arrival = current_time - metrics['last_seen']
            metrics['inter_arrival'].append(inter_arrival)
        metrics['last_seen'] = current_time
        
        # Protocol distribution
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        
        if tcp_pkt:
            metrics['protocol_dist']['tcp'] += 1
            metrics['port_dist'][tcp_pkt.dst_port] += 1
            
            # TCP flags analysis
            if tcp_pkt.bits & 0x02:  # SYN
                metrics['tcp_flags']['syn'] += 1
            if tcp_pkt.bits & 0x10:  # ACK
                metrics['tcp_flags']['ack'] += 1
            if tcp_pkt.bits & 0x01:  # FIN
                metrics['tcp_flags']['fin'] += 1
            if tcp_pkt.bits & 0x04:  # RST
                metrics['tcp_flags']['rst'] += 1
                
        elif udp_pkt:
            metrics['protocol_dist']['udp'] += 1
            metrics['port_dist'][udp_pkt.dst_port] += 1
            
        elif icmp_pkt:
            metrics['protocol_dist']['icmp'] += 1

    def _quick_anomaly_check(self, src_ip):
        """Quick check for obvious anomalies"""
        metrics = self.host_metrics[src_ip]
        
        # Check if too many packets in short time
        recent_packets = len([t for t in metrics['packet_size'] 
                            if time.time() - metrics['last_seen'] < 1.0])
        
        if recent_packets > self.thresholds['packet_rate'] / 10:
            return True
        
        return False

    # ==================== STATISTICS COLLECTION ====================
    
    def _stats_request_loop(self):
        """Request flow statistics from switches"""
        while True:
            for dp in self.datapaths.values():
                self._request_flow_stats(dp)
                self._request_port_stats(dp)
            hub.sleep(3)

    def _request_flow_stats(self, datapath):
        """Request flow statistics"""
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _request_port_stats(self, datapath):
        """Request port statistics"""
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Process flow statistics"""
        dpid = ev.msg.datapath.id
        flows = []
        
        for stat in ev.msg.body:
            match_fields = {}
            try:
                for key, value in stat.match.items():
                    match_fields[str(key)] = value
            except AttributeError:
                match_fields = {'raw': str(stat.match)}

            flows.append({
                'priority': stat.priority,
                'match': match_fields,
                'duration_sec': stat.duration_sec,
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
            })
        
        self.flow_stats[dpid] = flows

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Process port statistics"""
        dpid = ev.msg.datapath.id
        ports = {}
        
        for stat in ev.msg.body:
            ports[stat.port_no] = {
                'rx_packets': stat.rx_packets,
                'tx_packets': stat.tx_packets,
                'rx_bytes': stat.rx_bytes,
                'tx_bytes': stat.tx_bytes,
                'rx_dropped': stat.rx_dropped,
                'tx_dropped': stat.tx_dropped,
                'rx_errors': stat.rx_errors,
                'tx_errors': stat.tx_errors,
            }
        
        self.port_stats[dpid] = ports

    # ==================== ANALYSIS & DETECTION ====================
    
    def _analysis_loop(self):
        """Main analysis loop for DDoS detection"""
        while True:
            hub.sleep(5)
            self._analyze_all_hosts()
            self._export_state()

    def _analyze_all_hosts(self):
        """Analyze all hosts for anomalies"""
        current_time = time.time()
        time_window = current_time - self.last_analysis
        
        if time_window < 1:
            return
        
        for src_ip, metrics in list(self.host_metrics.items()):
            # Calculate rates
            packet_count = len(metrics['packet_size'])
            metrics['packet_rate'] = packet_count / time_window
            
            if metrics['packet_size']:
                total_bytes = sum(metrics['packet_size'])
                metrics['byte_rate'] = total_bytes / time_window
            
            # Analyze for DDoS
            anomaly_score = self._calculate_anomaly_score(src_ip, metrics)
            self.anomaly_scores[src_ip] = anomaly_score
            
            # Decision
            if anomaly_score > 0.8:  # High confidence attack
                self._handle_attack(src_ip, metrics, anomaly_score)
            elif anomaly_score > 0.5:  # Suspicious
                self._add_to_greylist(src_ip, anomaly_score)
        
        self.last_analysis = current_time

    def _calculate_anomaly_score(self, src_ip, metrics):
        """Calculate anomaly score based on multiple features"""
        score = 0.0
        weights = []
        
        # === FEATURE 1: Packet Rate ===
        if metrics['packet_rate'] > self.thresholds['packet_rate']:
            feature_score = min(metrics['packet_rate'] / 
                              (self.thresholds['packet_rate'] * 2), 1.0)
            score += feature_score * 0.25
            weights.append('high_packet_rate')
        
        # === FEATURE 2: SYN Flood Detection ===
        tcp_total = metrics['protocol_dist'].get('tcp', 0)
        if tcp_total > 10:
            syn_count = metrics['tcp_flags'].get('syn', 0)
            ack_count = metrics['tcp_flags'].get('ack', 0)
            
            if syn_count > ack_count * 3:  # SYN >> ACK
                syn_ratio = syn_count / (syn_count + ack_count + 1)
                if syn_ratio > self.thresholds['syn_ratio']:
                    score += 0.3
                    weights.append('syn_flood')
        
        # === FEATURE 3: UDP Flood ===
        total_packets = sum(metrics['protocol_dist'].values())
        if total_packets > 50:
            udp_ratio = metrics['protocol_dist'].get('udp', 0) / total_packets
            if udp_ratio > 0.8:
                score += 0.25
                weights.append('udp_flood')
        
        # === FEATURE 4: Port Scan / Single Port Attack ===
        if metrics['port_dist']:
            port_entropy = self._calculate_entropy(
                list(metrics['port_dist'].values())
            )
            if port_entropy < self.thresholds['entropy_threshold']:
                score += 0.15
                weights.append('low_port_entropy')
        
        # === FEATURE 5: Small Packet Attack ===
        if len(metrics['packet_size']) > 10:
            small_packets = sum(1 for s in metrics['packet_size'] if s < 100)
            small_ratio = small_packets / len(metrics['packet_size'])
            if small_ratio > self.thresholds['small_packet_ratio']:
                score += 0.15
                weights.append('small_packet_flood')
        
        # === FEATURE 6: High Inter-arrival Variance ===
        if len(metrics['inter_arrival']) > 10:
            variance = np.var(list(metrics['inter_arrival']))
            if variance < 0.001:  # Very uniform timing (bot-like)
                score += 0.1
                weights.append('uniform_timing')
        
        # Store detection reasons
        if score > 0.5:
            self.logger.info('Anomaly score %.2f for %s: %s', 
                           score, src_ip, ', '.join(weights))
        
        return min(score, 1.0)

    def _calculate_entropy(self, values):
        """Calculate Shannon entropy"""
        if not values:
            return 0
        
        total = sum(values)
        if total == 0:
            return 0
        
        entropy = 0
        for count in values:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return entropy

    # ==================== MITIGATION ====================
    
    def _handle_attack(self, src_ip, metrics, anomaly_score):
        """Handle detected attack"""
        if src_ip in self.whitelist:
            return
        
        if src_ip in self.blacklist:
            return
        
        # Determine attack type
        attack_type = self._classify_attack(metrics)
        
        self.logger.critical('🚨 ATTACK DETECTED from %s!', src_ip)
        self.logger.critical('   Type: %s', attack_type)
        self.logger.critical('   Anomaly Score: %.2f', anomaly_score)
        self.logger.critical('   Packet Rate: %.2f pps', metrics['packet_rate'])
        
        # Update statistics
        self.attack_stats['total_attacks_detected'] += 1
        if 'SYN' in attack_type:
            self.attack_stats['syn_floods'] += 1
        elif 'UDP' in attack_type:
            self.attack_stats['udp_floods'] += 1
        elif 'HTTP' in attack_type:
            self.attack_stats['http_floods'] += 1
        
        # Block the attacker
        self._block_ip_all_switches(src_ip)

    def _classify_attack(self, metrics):
        """Classify attack type based on metrics"""
        tcp_total = metrics['protocol_dist'].get('tcp', 0)
        udp_total = metrics['protocol_dist'].get('udp', 0)
        total = sum(metrics['protocol_dist'].values())
        
        if total == 0:
            return 'Unknown'
        
        # SYN Flood
        syn_count = metrics['tcp_flags'].get('syn', 0)
        if syn_count > tcp_total * 0.7:
            return 'SYN Flood'
        
        # UDP Flood
        if udp_total / total > 0.8:
            return 'UDP Flood'
        
        # HTTP Flood (TCP on common web ports)
        http_ports = [80, 443, 8080, 8443]
        http_traffic = sum(metrics['port_dist'].get(p, 0) for p in http_ports)
        if http_traffic > total * 0.5:
            return 'HTTP Flood'
        
        return 'Mixed Attack'

    def _add_to_greylist(self, src_ip, score):
        """Add suspicious IP to greylist"""
        if src_ip not in self.greylist:
            self.greylist[src_ip] = {'count': 0, 'score': score}
            self.logger.warning('⚠️  Added %s to greylist (score: %.2f)', 
                              src_ip, score)
        
        self.greylist[src_ip]['count'] += 1
        self.greylist[src_ip]['score'] = max(self.greylist[src_ip]['score'], score)
        
        # Promote to blacklist after multiple warnings
        if self.greylist[src_ip]['count'] >= 3:
            self.logger.warning('Promoting %s from greylist to blacklist', src_ip)
            self._block_ip_all_switches(src_ip)

    def _block_ip_all_switches(self, src_ip):
        """Block IP on all switches"""
        for dpid, datapath in self.datapaths.items():
            self._install_block_flow(datapath, src_ip)
        
        self.blacklist.add(src_ip)
        self.attack_stats['blocked_ips'].add(src_ip)
        
        self.logger.critical('🛡️  BLOCKED %s on all switches', src_ip)

    def _install_block_flow(self, datapath, src_ip):
        """Install blocking flow on switch"""
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = []  # Drop
        
        self.add_flow(datapath, 1000, match, actions, hard=300)

    # ==================== MONITORING & REPORTING ====================
    
    def _monitor_loop(self):
        """Display monitoring dashboard"""
        while True:
            hub.sleep(10)
            self._print_dashboard()

    def _print_dashboard(self):
        """Print real-time dashboard"""
        uptime = time.time() - self.start_time
        
        print('\n' + '='*80)
        print(f'🛡️  DDoS DETECTION DASHBOARD - Uptime: {uptime:.0f}s')
        print('='*80)
        
        print(f'\n📊 NETWORK STATUS:')
        print(f'  Active Switches: {len(self.datapaths)}')
        print(f'  Monitored Hosts: {len(self.host_metrics)}')
        print(f'  Total Flows: {sum(len(f) for f in self.flow_stats.values())}')
        
        print(f'\n🚨 ATTACK STATISTICS:')
        print(f'  Total Attacks Detected: {self.attack_stats["total_attacks_detected"]}')
        print(f'  SYN Floods: {self.attack_stats["syn_floods"]}')
        print(f'  UDP Floods: {self.attack_stats["udp_floods"]}')
        print(f'  HTTP Floods: {self.attack_stats["http_floods"]}')
        print(f'  Blocked IPs: {len(self.attack_stats["blocked_ips"])}')
        print(f'  Packets Blocked: {self.attack_stats["total_packets_blocked"]}')
        
        print(f'\n⚠️  THREAT LISTS:')
        print(f'  Blacklist: {len(self.blacklist)} IPs')
        if self.blacklist:
            print(f'    {", ".join(list(self.blacklist)[:5])}')
        print(f'  Greylist: {len(self.greylist)} IPs')
        if self.greylist:
            for ip, info in list(self.greylist.items())[:3]:
                print(f'    {ip}: warnings={info["count"]}, score={info["score"]:.2f}')
        
        print(f'\n📈 TOP TRAFFIC SOURCES:')
        sorted_hosts = sorted(
            self.host_metrics.items(),
            key=lambda x: x[1]['packet_rate'],
            reverse=True
        )[:5]
        
        for src_ip, metrics in sorted_hosts:
            status = '🔴' if src_ip in self.blacklist else '🟢'
            anomaly = self.anomaly_scores.get(src_ip, 0)
            print(f'  {status} {src_ip}: {metrics["packet_rate"]:.1f} pps, '
                  f'anomaly={anomaly:.2f}')
        
        print('='*80 + '\n')

    # ==================== STATE EXPORT ====================

    def _export_state(self):
        """Persist current controller state for external API."""
        stats = dict(self.attack_stats)
        stats['blocked_ips'] = list(stats.get('blocked_ips', []))

        snapshot = {
            'uptime_seconds': time.time() - self.start_time,
            'network': self._serialize_network(),
            'flows': self._serialize_flow_stats(),
            'ports': self._serialize_port_stats(),
            'hosts': self._serialize_host_metrics(),
            'threats': self._serialize_threats(),
            'anomaly_scores': self._serialize_anomaly_scores(),
            'thresholds': self.thresholds,
            'stats': stats,
        }
        state_store.persist_controller_state(snapshot)

    def _serialize_network(self):
        switches = []
        for dpid, datapath in self.datapaths.items():
            switches.append({
                'dpid': format(dpid, '016x'),
                'numeric_dpid': dpid,
                'flow_count': len(self.flow_stats.get(dpid, [])),
                'port_count': len(self.port_stats.get(dpid, {})),
            })

        return {
            'switch_count': len(switches),
            'host_count': len(self.host_metrics),
            'switches': switches,
        }

    def _serialize_flow_stats(self):
        serialized = {}
        for dpid, flows in self.flow_stats.items():
            serialized[str(dpid)] = flows
        return serialized

    def _serialize_port_stats(self):
        serialized = {}
        for dpid, ports in self.port_stats.items():
            serialized[str(dpid)] = ports
        return serialized

    def _serialize_host_metrics(self):
        serialized = {}
        for host_ip, metrics in self.host_metrics.items():
            serialized[host_ip] = {
                'packet_rate': metrics.get('packet_rate', 0),
                'byte_rate': metrics.get('byte_rate', 0),
                'flow_rate': metrics.get('flow_rate', 0),
                'protocol_dist': dict(metrics.get('protocol_dist', {})),
                'port_dist_top': self._top_n(metrics.get('port_dist', {})),
                'tcp_flags': dict(metrics.get('tcp_flags', {})),
                'packet_samples': list(metrics.get('packet_size', []))[-10:],
                'inter_arrival_samples': list(metrics.get('inter_arrival', []))[-10:],
                'last_seen': metrics.get('last_seen', 0),
            }
        return serialized

    def _serialize_threats(self):
        return {
            'blacklist': list(self.blacklist),
            'greylist': [
                {'ip': ip, 'count': data['count'], 'score': data['score']}
                for ip, data in self.greylist.items()
            ],
            'whitelist': list(self.whitelist),
            'blocked_ips': list(self.attack_stats.get('blocked_ips', [])),
        }

    def _serialize_anomaly_scores(self):
        return {ip: score for ip, score in self.anomaly_scores.items()}

    def _top_n(self, data_dict, n=5):
        items = sorted(data_dict.items(), key=lambda kv: kv[1], reverse=True)
        return [{'port_or_key': key, 'count': value} for key, value in items[:n]]

    # ==================== COMMAND PROCESSOR ====================

    def _command_loop(self):
        """Poll queued commands from Flask API."""
        while True:
            hub.sleep(2)
            commands = command_store.pop_all_commands()
            for command in commands:
                self._process_command(command)

    def _process_command(self, command):
        cmd_type = command.get('type')
        payload = command.get('payload', {})
        ip_address = payload.get('ip')

        if cmd_type == 'block_ip' and ip_address:
            self._block_ip_all_switches(ip_address)
        elif cmd_type == 'unblock_ip' and ip_address:
            self._unblock_ip_all_switches(ip_address)
        elif cmd_type == 'whitelist_ip' and ip_address:
            self.whitelist.add(ip_address)
            self.logger.info('Added %s to whitelist via API', ip_address)
        elif cmd_type == 'remove_whitelist_ip' and ip_address:
            self.whitelist.discard(ip_address)
            self.logger.info('Removed %s from whitelist via API', ip_address)
        elif cmd_type == 'set_thresholds':
            for key, value in payload.items():
                if key in self.thresholds:
                    self.thresholds[key] = value
            self.logger.info('Thresholds updated via API: %s', payload)
        else:
            self.logger.warning('Unknown command from API: %s', command)

    def _unblock_ip_all_switches(self, src_ip):
        """Remove blocking flows for IP."""
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match,
            )
            datapath.send_msg(mod)

        self.blacklist.discard(src_ip)
        self.attack_stats['blocked_ips'].discard(src_ip)
        self.logger.info('🟢 Unblocked %s on all switches', src_ip)