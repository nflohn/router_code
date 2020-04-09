There are two files here:
	mytopo_part2.py - creates a mininet topology of three hosts connected to one switch on one subnet and two more hosts on another subnet connected to a 
	different switch.  The two switches are connected.  
	
	part2_router_noflow.py - A basic POX openflow/mininet IP router controller that forwards packets based on a static/hardcoded IP routing table.  If an IP 
	address is called that is not in the static routing table, an ICMP destination unreachable message is returned.  The router's interfaces are also pingable.  
	The router runs ARP if any MAC addresses are not know and responds to ARP requests.  It also updates the destination and source MAC addresses for packets 
	it forwards.

In order to run this code:
	1. Start the mininet virtual machine
	2. confirm that all network adapters are configured properly (command: ifconfig -a) and they all have assigned IP addresses.  If any do not run the command:
	"sudo dhclient ethX" where X is the adapter not configured right
	1. Import mytopo_part2.py to the default folder (mininet-vm) on your mininet virtual machine and import part2_router_noflow.py to the /pox/pox/misc folder.
	2. In a new SSH session with X11 forwarding enabled, start mininet using the command: sudo mn --custom mytopo_part2.py --topo mytopo --mac --switch ovsk --controller remote
	3. In another new SSH session with X11 forwarding enabled, navigate to the pox folder (command: cd pox) and run the controller using: ./pox.py log --no-default misc.part2_router_noflow misc.full_payload
	4. Wait a few seconds for the controller to connect