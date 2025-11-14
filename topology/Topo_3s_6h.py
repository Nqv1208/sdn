from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.cli import CLI

class MyTopo_3s_6h(Topo):
    def build(self):
        # Tao host
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')

        # Tao switch
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Tao link
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(s1, s2)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(s2, s3)
        self.addLink(h5, s3)
        self.addLink(h6, s3)

if __name__ == '__main__':
    topo = MyTopo_3s_6h()
    net = Mininet(topo=topo, controller=RemoteController, link=TCLink)
    net.start()
    print("*** Network is up ***")
    CLI(net)
    net.stop()
