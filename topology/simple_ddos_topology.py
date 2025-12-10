# Lab 3: SDN Security - DDoS Detection using Flow Analysis
# Simple topology: 3 switches, 6 hosts

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def create_topology():
    """Create simple topology for DDoS detection lab"""
    
    net = Mininet(controller=RemoteController,
                  switch=OVSSwitch,
                  link=TCLink,
                  autoSetMacs=True)
    
    info('*** Adding SDN Controller\n')
    c0 = net.addController('c0', controller=RemoteController,
                          ip='127.0.0.1', port=6633)
    
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13', dpid='0000000000000001')
    s2 = net.addSwitch('s2', protocols='OpenFlow13', dpid='0000000000000002')
    s3 = net.addSwitch('s3', protocols='OpenFlow13', dpid='0000000000000003')
    
    info('*** Adding hosts\n')
    # Switch 1: 2 hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    
    # Switch 2: 2 hosts (h3 will be web server, h4 attacker)
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
    
    # Switch 3: 2 hosts (h5, h6 attackers)
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
    h6 = net.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')
    
    info('*** Creating links\n')
    # Connect switches to controller
    net.addLink(s1, s2, bw=100)
    net.addLink(s2, s3, bw=100)
    net.addLink(s1, s3, bw=100)
    
    # Connect hosts to switches
    net.addLink(h1, s1, bw=10)
    net.addLink(h2, s1, bw=10)
    net.addLink(h3, s2, bw=10)
    net.addLink(h4, s2, bw=10)
    net.addLink(h5, s3, bw=10)
    net.addLink(h6, s3, bw=10)
    
    info('*** Starting network\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    
    info('*** Configuring network interfaces\n')
    # Ensure all hosts have proper network configuration
    for host in [h1, h2, h3, h4, h5, h6]:
        host.cmd('ip link set %s-eth0 up' % host.name)
        # Add default route if needed
        host.cmd('ip route add default via 10.0.0.1 2>/dev/null || true')
    
    info('*** Setting up services\n')
    # h3 as web server
    h3.cmd('python3 -m http.server 80 &')
    
    print('\n' + '='*70)
    print('*** LAB E: DDoS DETECTION USING FLOW ANALYSIS ***')
    print('='*70)
    print('\n📊 TOPOLOGY:')
    print('  • 3 Open vSwitches (s1, s2, s3)')
    print('  • 6 Hosts (h1-h6)')
    print('\n🎯 ROLES:')
    print('  • h1, h2: Legitimate clients')
    print('  • h3 (10.0.0.3): Web server (HTTP on port 80)')
    print('  • h4, h5, h6: Potential attackers')
    print('\n🧪 ATTACK SCENARIOS:')
    print('  1. SYN Flood: xterm h4 -> sudo hping3 -S --flood -p 80 10.0.0.3')
    print('  2. UDP Flood: xterm h5 -> sudo hping3 --udp --flood -p 80 10.0.0.3')
    print('  3. HTTP Flood: xterm h6 -> python3 http_flood.py')
    print('  4. Distributed: Run attacks from h4, h5, h6 simultaneously')
    print('\n📈 MONITORING:')
    print('  • Controller dashboard updates every 5 seconds')
    print('  • View flows: sh ovs-ofctl dump-flows s2 -O OpenFlow13')
    print('  • Check stats: sh ovs-ofctl dump-ports s2 -O OpenFlow13')
    print('\n✅ TEST LEGITIMATE TRAFFIC:')
    print('  • h1 ping h3')
    print('  • h1 curl http://10.0.0.3')
    print('  • h2 wget http://10.0.0.3')
    print('='*70 + '\n')
    
    CLI(net)
    
    info('*** Stopping network\n')
    h3.cmd('kill %python3')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()