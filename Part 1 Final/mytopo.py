"""Custom topology example

Three hosts on seperate subnets connected to a router

   host --- router --- host
    host ---^

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        Host1 = self.addHost( 'h1' , ip="10.0.1.100/24", defaultRoute = "via 10.0.1.1" )
        Host2 = self.addHost( 'h2' , ip="10.0.2.100/24", defaultRoute = "via 10.0.2.1" )
        Host3 = self.addHost( 'h3' , ip="10.0.3.100/24", defaultRoute = "via 10.0.3.1" )
        Router = self.addSwitch( 's4', dpid="0000000000000111" )

        # Add links
        self.addLink( Host1, Router )
        self.addLink( Host2, Router )
        self.addLink( Host3, Router )


topos = { 'mytopo': ( lambda: MyTopo() ) }
