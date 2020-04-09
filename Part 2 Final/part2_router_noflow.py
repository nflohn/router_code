"""
A basic router

For each switch:
1) A static ARP table is defined mapping IP addresses to MAC addresses and ports
2) When you see an ARP query, try to answer it using information in the table
   from step 1.  
3) If the destination is unknown then flood the ARP packet
4) When you see an IP packet, if you know the destination port (because it's
   in the table from step 1), install a flow for it.  If the IP packet destination is
   unknown then return an ICMP Destination Unreachable packet
"""

from pox.core import core
import pox
import pox.lib.packet as pkt
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer


import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time

# Timeout for flows
FLOW_IDLE_TIMEOUT = 10

# Timeout for ARP entries
ARP_TIMEOUT = 60 * 2

# Maximum number of packet to buffer on a switch for an unknown IP
MAX_BUFFERED_PER_IP = 5

# Maximum time to hang on to a buffer for an unknown IP in seconds
MAX_BUFFER_TIME = 5


class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    if self.port == of.OFPP_NONE: return False
    return time.time() > self.timeout


def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


class l3_switch (EventMixin):
  def __init__ (self, fakeways = [], arp_for_unknowns = False):
    # These are "fake gateways" -- we'll answer ARPs for them with MAC
    # of the switch they're connected to.
    self.fakeways = set(fakeways)

    # If this is true and we see a packet for an unknown
    # host, we'll ARP for it.
    self.arp_for_unknowns = arp_for_unknowns

    # (dpid,IP) -> expire_time
    # We use this to keep from spamming ARPs
    self.outstanding_arps = {}

    # (dpid,IP) -> [(expire_time,buffer_id,in_port), ...]
    # These are buffers we've gotten at this datapath for this IP which
    # we can't deliver because we don't know where they go.
    self.lost_buffers = {}

    # For each switch, we map IP addresses to Entries
    self.arpTable = {}

    # This timer handles expiring stuff
    self._expire_timer = Timer(5, self._handle_expiration, recurring=True)

    self.listenTo(core)

  def _handle_expiration (self):
    # Called by a timer so that we can remove old items.
    empty = []
    for k,v in self.lost_buffers.iteritems():
      dpid,ip = k

      for item in list(v):
        expires_at,buffer_id,in_port = item
        if expires_at < time.time():
          # This packet is old.  Tell this switch to drop it.
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)

    # Remove empty buffer bins
    for k in empty:
      del self.lost_buffers[k]

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    """
    We may have "lost" buffers -- packets we got but didn't know
    where to send at the time.  We may know now.  Try and see.
    """
    if (dpid,ipaddr) in self.lost_buffers:
      # Yup!
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.debug("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpid_to_str(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)

  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
    log.debug("Up...")

  def _handle_PacketIn (self, event):
    dpid = event.connection.dpid
    #hardcoded ARP tables
    self.arpTable[1]={}
    self.arpTable[1][IPAddr('10.0.1.2')] = Entry(1, EthAddr('00:00:00:00:00:01'))
    self.arpTable[1][IPAddr('10.0.1.3')] = Entry(2, EthAddr('00:00:00:00:00:02'))
    self.arpTable[1][IPAddr('10.0.2.2')] = Entry(3, EthAddr('00:00:00:00:00:06'))
    self.arpTable[1][IPAddr('10.0.2.3')] = Entry(3, EthAddr('00:00:00:00:00:07'))
    self.arpTable[1][IPAddr('10.0.2.4')] = Entry(3, EthAddr('00:00:00:00:00:08'))
    self.arpTable[1][IPAddr('10.0.2.1')] = Entry(3, EthAddr('00:00:00:00:00:09'))
    self.arpTable[2]={}
    self.arpTable[2][IPAddr('10.0.2.2')] = Entry(1, EthAddr('00:00:00:00:00:03'))
    self.arpTable[2][IPAddr('10.0.2.3')] = Entry(2, EthAddr('00:00:00:00:00:04'))
    self.arpTable[2][IPAddr('10.0.2.4')] = Entry(3, EthAddr('00:00:00:00:00:05'))
    self.arpTable[2][IPAddr('10.0.1.2')] = Entry(4, EthAddr('00:00:00:00:00:10'))
    self.arpTable[2][IPAddr('10.0.1.3')] = Entry(4, EthAddr('00:00:00:00:00:11'))
    self.arpTable[2][IPAddr('10.0.1.1')] = Entry(4, EthAddr('00:00:00:00:00:12'))
    #return address library
    returnAddr = {IPAddr('10.0.1.2') : IPAddr('10.0.1.1'),IPAddr('10.0.1.3') : IPAddr('10.0.1.1'), IPAddr('10.0.2.2') : IPAddr('10.0.2.1'), IPAddr('10.0.2.3') : IPAddr('10.0.2.1'),IPAddr('10.0.2.4') : IPAddr('10.0.2.1')}
    inport = event.port
    packet = event.parsed
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = {}
      for fake in self.fakeways:
        self.arpTable[dpid][IPAddr(fake)] = Entry(of.OFPP_NONE,
         dpid_to_mac(dpid))

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    if isinstance(packet.next, ipv4):
      log.debug("%i %i IP %s => %s", dpid,inport,
                packet.next.srcip,packet.next.dstip)

      # Send any waiting packets...
      self._send_lost_buffers(dpid, packet.next.srcip, packet.src, inport)
	  
      # Learn or update port/MAC info
      if packet.next.srcip in self.arpTable[dpid]:
        if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
          log.info("%i %i RE-learned %s", dpid,inport,packet.next.srcip)
      else:
        log.debug("%i %i learned %s", dpid,inport,str(packet.next.srcip))
      self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)

      # Try to forward
      dstaddr = packet.next.dstip
      srcaddr = packet.next.srcip
      if (((srcaddr == IPAddr('10.0.1.2') or srcaddr == IPAddr('10.0.1.3')) and (packet.src == EthAddr('00:00:00:00:00:01') or packet.src == EthAddr('00:00:00:00:00:02'))) or ((srcaddr == IPAddr('10.0.2.2') or srcaddr == IPAddr('10.0.2.3') or srcaddr == IPAddr('10.0.2.4')) and (packet.src != EthAddr('00:00:00:00:00:03') and packet.src != EthAddr('00:00:00:00:00:04') and packet.src != EthAddr('00:00:00:00:00:05')))):
		if dstaddr in self.arpTable[1]:
			# send to a known IP address and install flow

			prt = self.arpTable[1][dstaddr].port
			mac = self.arpTable[1][dstaddr].mac
			if prt == inport:
				log.warning("%i %i not sending packet for %s back out of the " +
                      "input port" % (dpid, inport, str(dstaddr)))
			else:
				log.debug("%i %i forwarding packet for %s => %s out port %i"
                    % (dpid, inport, packet.next.srcip, dstaddr, prt))
				e = pkt.ethernet()
                                e.src = self.arpTable[1][IPAddr('10.0.2.1')].mac
                                e.dst = mac
                                e.type = e.IP_TYPE
				e.payload = packet.payload

                                msg = of.ofp_packet_out()
                                msg.actions.append(of.ofp_action_output(port = prt))
                                msg.data = e.pack()
                                msg.in_port = event.port
                                event.connection.send(msg)
     
		elif dstaddr == IPAddr('10.0.1.1'):
			# Make the ICMP ping reply
			icmp = pkt.icmp()
			icmp.type = pkt.TYPE_ECHO_REPLY
			icmp.payload = packet.find("icmp").payload

			# Make the IP packet
			ipp = pkt.ipv4()
			ipp.protocol = ipp.ICMP_PROTOCOL
			ipp.srcip = packet.find("ipv4").dstip
			ipp.dstip = packet.find("ipv4").srcip
			# make the ethernet frame
			e = pkt.ethernet()
			e.src = packet.dst
			e.dst = packet.src
			e.type = e.IP_TYPE
			# put the ICMP packet in the IP packet and the IP packet in the ehternet frame
			ipp.payload = icmp
			e.payload = ipp
			# Send it back to the input port
			msg = of.ofp_packet_out()
			msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
			msg.data = e.pack()
			msg.in_port = event.port
			event.connection.send(msg)
			log.debug("%s pinged %s", ipp.dstip, ipp.srcip)
	
		

		else:
			# We don't know this destination.
			# need to send ICMP unreachable

			#make the ICMP Destination unreachable
			icmp2 = pkt.icmp()
			icmp2.type = pkt.TYPE_DEST_UNREACH
			origIP = event.parsed.find('ipv4')
			PL = origIP.pack()
			PL = PL[:origIP.hl * 4 + 8]
			import struct
			PL = struct.pack("!HH" , 0,0) + PL
			icmp2.payload = PL

			#make the IP packet
			ipp2= pkt.ipv4()
			ipp2.protocol = ipp2.ICMP_PROTOCOL
			ipp2.srcip = packet.next.dstip
			ipp2.dstip = packet.next.srcip

			#make the ehternet frame
			e2 = pkt.ethernet()
			e2.src = dpid_to_mac(dpid)
			e2.dst = packet.src
			e2.type = e2.IP_TYPE

			#put the ICMP packe in the IP packet and the IP packet in the ethernet frame
			ipp2.payload = icmp2
			e2.payload = ipp2

			# send it back to the port it came from
			msg = of.ofp_packet_out()
			msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
			msg.data = e2.pack()
			msg.in_port = event.port
			event.connection.send(msg)

			log.debug("%s called %s which is unreachable. ICMP destination unreachable packet sent", ipp2.dstip, ipp2.srcip)

		
      elif (((srcaddr == IPAddr('10.0.1.2') or srcaddr == IPAddr('10.0.1.3')) and (packet.src != EthAddr('00:00:00:00:00:01') and packet.src != EthAddr('00:00:00:00:00:02'))) or ((srcaddr == IPAddr('10.0.2.2') or srcaddr == IPAddr('10.0.2.3') or srcaddr == IPAddr('10.0.2.4')) and (packet.src == EthAddr('00:00:00:00:00:03') or packet.src == EthAddr('00:00:00:00:00:04') or packet.src == EthAddr('00:00:00:00:00:05')))):
		if dstaddr in self.arpTable[2]:
			# send to a known IP address and install flow
			prt = self.arpTable[2][dstaddr].port
			mac = self.arpTable[2][dstaddr].mac
			if prt == inport:
				log.warning("%i %i not sending packet for %s back out of the " +
                      "input port" % (dpid, inport, str(dstaddr)))
			else:
				log.debug("%i %i forwarding packet for %s => %s out port %i"
                    % (dpid, inport, packet.next.srcip, dstaddr, prt))
                                e = pkt.ethernet()
                                e.src = self.arpTable[2][IPAddr('10.0.1.1')].mac
                                e.dst = mac
                                e.type = e.IP_TYPE
				e.payload = packet.payload

                                msg = of.ofp_packet_out()
                                msg.actions.append(of.ofp_action_output(port = prt))
                                msg.data = e.pack()
                                msg.in_port = event.port
                                event.connection.send(msg)
     
			
	
		elif dstaddr == IPAddr('10.0.2.1'):
			# Make the ICMP ping reply
			icmp = pkt.icmp()
			icmp.type = pkt.TYPE_ECHO_REPLY
			icmp.payload = packet.find("icmp").payload

			# Make the IP packet
			ipp = pkt.ipv4()
			ipp.protocol = ipp.ICMP_PROTOCOL
			ipp.srcip = packet.find("ipv4").dstip
			ipp.dstip = packet.find("ipv4").srcip
			# make the ethernet frame
			e = pkt.ethernet()
			e.src = packet.dst
			e.dst = packet.src
			e.type = e.IP_TYPE
			# put the ICMP packet in the IP packet and the IP packet in the ehternet frame
			ipp.payload = icmp
			e.payload = ipp
			#	 Send it back to the input port
			msg = of.ofp_packet_out()
			msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
			msg.data = e.pack()
			msg.in_port = event.port
			event.connection.send(msg)
			log.debug("%s pinged %s", ipp.dstip, ipp.srcip)


		else:
			# We don't know this destination.
			# need to send ICMP unreachable
			#make the ICMP Destination unreachable
			icmp2 = pkt.icmp()
			icmp2.type = pkt.TYPE_DEST_UNREACH
			origIP = event.parsed.find('ipv4')
			PL = origIP.pack()
			PL = PL[:origIP.hl * 4 + 8]
			import struct
			PL = struct.pack("!HH" , 0,0) + PL
			icmp2.payload = PL
			#make the IP packet
			ipp2= pkt.ipv4()
			ipp2.protocol = ipp2.ICMP_PROTOCOL
			ipp2.srcip = packet.next.dstip
			ipp2.dstip = packet.next.srcip
			#make the ehternet frame
			e2 = pkt.ethernet()
			e2.src = dpid_to_mac(dpid)
			e2.dst = packet.src
			e2.type = e2.IP_TYPE

			#put the ICMP packe in the IP packet and the IP packet in the ethernet frame
			ipp2.payload = icmp2
			e2.payload = ipp2

			# send it back to the port it came from
			msg = of.ofp_packet_out()
			msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
			msg.data = e2.pack()
			msg.in_port = event.port
			event.connection.send(msg)

			log.debug("%s called %s which is unreachable. ICMP destination unreachable packet sent", ipp2.dstip, ipp2.srcip)
	
    elif packet.find("icmp"):
        # Reply to passive ICMP pings

        # Make the ICMP ping reply
        icmp = pkt.icmp()
        icmp.type = pkt.TYPE_ECHO_REPLY
        icmp.payload = packet.find("icmp").payload

        # Make the IP packet
        ipp = pkt.ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = packet.find("ipv4").dstip
        ipp.dstip = packet.find("ipv4").srcip
        # make the ethernet frame
        e = pkt.ethernet()
        e.src = packet.dst
        e.dst = packet.src
        e.type = e.IP_TYPE
        # put the ICMP packet in the IP packet and the IP packet in the ehternet frame
        ipp.payload = icmp
        e.payload = ipp
        # Send it back to the input port
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.data = e.pack()
        msg.in_port = event.port
        event.connection.send(msg)
        log.debug("%s pinged %s", ipp.dstip, ipp.srcip)
	
	
    elif isinstance(packet.next, arp):
	  #deal with ARP packets
      a = packet.next
      match = of.ofp_match.from_packet(packet)
      log.debug("%i %i ARP %s %s => %s", dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))

      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:

            # Learn or update port/MAC info
            if a.protosrc in self.arpTable[dpid]:
              if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
                log.info("%i %i RE-learned %s", dpid,inport,str(a.protosrc))
            else:
              log.debug("%i %i learned %s", dpid,inport,str(a.protosrc))
            self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

            

            if a.opcode == arp.REQUEST:
              # Maybe we can answer
			  #if the IP requested is for the switch
              if match.nw_dst == IPAddr('10.0.1.1'):
                r = arp()
                r.opcode = arp.REPLY
                r.hwdst = a.hwsrc
                r.protosrc = IPAddr('10.0.1.1')
                r.protodst = a.protosrc
                r.hwsrc = dpid_to_mac(dpid)
                r.hwtype = a.hwtype
                r.prototype = a.prototype
                r.hwlen = a.hwlen
                r.protolen = a.protolen
                
                e = ethernet(type=packet.ARP_TYPE, src=dpid_to_mac(dpid), dst=a.hwsrc)
                e.set_payload(r)
                msg=of.ofp_packet_out()
                msg.data = e.pack()
                msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
                msg.in_port=inport
                event.connection.send(msg)
                log.debug("answered ARP for router interface at 10.0.1.1")
                return

              elif match.nw_dst == IPAddr('10.0.2.1'):
                r = arp()
                r.opcode = arp.REPLY
                r.hwdst = a.hwsrc
                r.protosrc = IPAddr('10.0.2.1')
                r.protodst = a.protosrc
                r.hwsrc = dpid_to_mac(dpid)
                r.hwtype = a.hwtype
                r.prototype = a.prototype
                r.hwlen = a.hwlen
                r.protolen = a.protolen
                
                e = ethernet(type=packet.ARP_TYPE, src=dpid_to_mac(dpid), dst=a.hwsrc)
                e.set_payload(r)
                msg=of.ofp_packet_out()
                msg.data = e.pack()
                msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
                msg.in_port=inport
                event.connection.send(msg)
                log.debug("answered ARP for router interface at 10.0.2.1")
                return

              

              elif a.protodst in self.arpTable[1]:
                # if the ip address is for another known host

                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = a.hwsrc
                  r.protodst = a.protosrc
                  r.protosrc = a.protodst
                  r.hwsrc = self.arpTable[dpid][a.protodst].mac
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid),
                               dst=a.hwsrc)
                  e.set_payload(r)
                  log.debug("%i %i answering ARP for %s" % (dpid, inport,
                   str(r.protosrc)))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port =
                                                          of.OFPP_IN_PORT))
                  msg.in_port = inport
                  event.connection.send(msg)
                  return

              

      # Didn't know how to answer or otherwise handle this ARP, so just flood it
      log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst)))

      msg = of.ofp_packet_out(in_port = inport, data = event.ofp,
          action = of.ofp_action_output(port = of.OFPP_FLOOD))
      event.connection.send(msg)


def launch (fakeways="", arp_for_unknowns=None):
  fakeways = fakeways.replace(","," ").split()
  fakeways = [IPAddr(x) for x in fakeways]
  if arp_for_unknowns is None:
    arp_for_unknowns = len(fakeways) > 0
  else:
    arp_for_unknowns = str_to_bool(arp_for_unknowns)
  core.registerNew(l3_switch, fakeways, arp_for_unknowns)

