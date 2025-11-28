# """
# SDN DDoS Mitigation Lab
# Topology: 3 switches, 1 web server, 5 clients (2 legitimate, 3 attackers)
# """

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def create_topology():
    # """Tạo topology mạng SDN"""
    
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)
    
    info('*** Adding controller\n')
    # Kết nối tới Ryu controller (chạy trên port 6633)
    c0 = net.addController('c0', controller=RemoteController, 
                          ip='127.0.0.1', port=6633)
    
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    
    info('*** Adding hosts\n')
    # Web Server
    server = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    
    # Legitimate Clients
    client1 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    client2 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    
    # Attackers
    attacker1 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
    attacker2 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
    attacker3 = net.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')
    
    info('*** Creating links\n')
    # Links với bandwidth constraints
    net.addLink(server, s1, bw=100)
    net.addLink(client1, s2, bw=10)
    net.addLink(client2, s2, bw=10)
    net.addLink(attacker1, s3, bw=10)
    net.addLink(attacker2, s3, bw=10)
    net.addLink(attacker3, s3, bw=10)
    
    # Inter-switch links
    net.addLink(s1, s2, bw=100)
    net.addLink(s1, s3, bw=100)
    
    info('*** Starting network\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    
    info('*** Setting up web server\n')
    server.cmd('python3 -m http.server 80 &')
    
    info('*** Network is ready!\n')
    info('*** Web Server: h1 (10.0.0.1)\n')
    info('*** Legitimate Clients: h2, h3\n')
    info('*** Attackers: h4, h5, h6\n')
    info('*** Run "xterm h4 h5 h6" để mở terminal cho attackers\n')
    
    CLI(net)
    
    info('*** Stopping network\n')
    server.cmd('kill %python3')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()