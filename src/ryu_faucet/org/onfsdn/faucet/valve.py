# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASISo
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ipaddr
import logging

from collections import namedtuple

from util import mac_addr_is_unicast

from ryu.lib import ofctl_v1_3 as ofctl
from ryu.lib import mac
from ryu.lib.packet import arp, ethernet, icmp, ipv4, packet
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser


def valve_factory(dp):
    """Return a Valve object based dp's hardware configuration field.

    Arguments:
    dp -- a DP object with the configuration for this valve.
    """
    if dp.hardware in dp.SUPPORTED_HARDWARE:
        return OVSStatelessValve(dp)
    else:
        return None


class Valve(object):
    """Generates the messages to configure a datapath as a l2 learning switch.

    This is a non functional generic base class. The implementation of datapath
    entry/exit, port entry/exit and packet in messages are hardware dependant
    and therefore are unimplemented.
    """

    def __init__(self, *args, **kwargs):
        raise NotImplementedError

    def reload_config(self, new_dp):
        """Reload the config from new_dp

        KW Arguments:
        new_dp -- A new DP object containing the updated config."""
        raise NotImplementedError

    def datapath_connect(self, dp_id, ports):
        """Generate the default openflow msgs for a datapath upon connection.

        Depending on the implementation, a network state database may be
        updated.

        Arguments:
        dp_id -- the Datapath unique ID (64bit int)
        ports -- a list containing the port numbers of each port on the
            datapath.

        Returns:
        A list of flow mod messages that will be sent in order to the datapath
        in order to configure it."""

        raise NotImplementedError

    def datapath_disconnect(self, dp_id):
        """Update n/w state db upon disconnection of datapath with id dp_id."""
        raise NotImplementedError

    def port_add(self, dp_id, port_num):
        """Generate openflow msgs to update the datapath upon addition of port.

        Arguments:
        dp_id -- the unique id of the datapath
        port_num -- the port number of the new port

        Returns
        A list of flow mod messages to be sent to the datapath."""
        raise NotImplementedError

    def port_delete(self, dp_id, port_num):
        """Generate openflow msgs to update the datapath upon deletion of port.

        Returns
        A list of flow mod messages to be sent to the datapath."""
        raise NotImplementedError

    def rcv_packet(self, dp_id, in_port, vlan_vid, match, pkt):
        """Generate openflow msgs to update datapath upon receipt of packet.

        This involves asssociating the ethernet source address of the packet
        with the given in_port (ethernet switching) ideally so that no packets
        from this address are sent to the controller, and packets to this
        address are output to in_port. This may not be fully possible depending
        on the limitations of the datapath.

        Depending on implementation this may involve updating a nw state db.

        Arguments:
        dp_id -- the unique id of the datapath that received the packet (64bit
            int)
        in_port -- the port number of the port that received the packet
        vlan_vid -- the vlan_vid tagged to the packet.
        pkt -- the packet send to us (Ryu ethernet object).

        Returns
        A list of flow mod messages to be sent to the datpath."""

        raise NotImplementedError


class OVSStatelessValve(Valve):
    """Valve implementation for Open vSwitch.

    Stateless because the controller does not keep track of the mac addresses,
    it just installs the necessary rules directly to the switch with
    timeouts."""

    FAUCET_MAC = '0e:00:00:00:00:01'

    def __init__(self, dp, logname='faucet', *args, **kwargs):
        self.dp = dp
        self.logger = logging.getLogger(logname)

    def ignore_port(self, port_num):
        """Ignore non-physical ports."""
        # port numbers > 0xF0000000 indicate a logical port
        return port_num > 0xF0000000

    def ignore_dpid(self, dp_id):
        """Ignore all DPIDs except the DPID configured."""
        if dp_id != self.dp.dp_id:
            self.logger.error("Unknown dpid:%s", dp_id)
            return True
        return False

    def all_valve_tables(self):
        return (
            self.dp.vlan_table,
            self.dp.acl_table,
            self.dp.eth_src_table,
            self.dp.eth_dst_table,
            self.dp.flood_table)

    def apply_actions(self, actions):
        return parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)

    def goto_table(self, table_id):
        return parser.OFPInstructionGotoTable(table_id)

    def set_eth_src(self, eth_src):
        return parser.OFPActionSetField(eth_src=eth_src)

    def set_eth_dst(self, eth_dst):
        return parser.OFPActionSetField(eth_dst=eth_dst)

    def valve_in_match(self, in_port=None, vlan=None,
                       eth_type=None, eth_src=None,
                       eth_dst=None, eth_dst_mask=None,
                       nw_proto=None, nw_src=None, nw_dst=None):
        match_dict = {}
        if in_port is not None:
            match_dict['in_port'] = in_port
        if vlan is not None:
            if vlan.vid == ofp.OFPVID_NONE:
                match_dict['vlan_vid'] = ofp.OFPVID_NONE
            else:
                match_dict['vlan_vid'] = vlan.vid|ofp.OFPVID_PRESENT
        if eth_src is not None:
            match_dict['eth_src'] = eth_src
        if eth_dst is not None:
            if eth_dst_mask is not None:
                match_dict['eth_dst'] = (eth_dst, eth_dst_mask)
            else:
                match_dict['eth_dst'] = eth_dst
        if nw_proto is not None:
            match_dict['ip_proto'] = nw_proto
        if nw_src is not None:
            match_dict['ipv4_src'] = (str(nw_src.ip), str(nw_src.netmask))
        if nw_dst is not None:
            nw_dst_masked = (str(nw_dst.ip), str(nw_dst.netmask))
            if eth_type == ether.ETH_TYPE_ARP:
                match_dict['arp_tpa'] = nw_dst_masked
            else:
                match_dict['ipv4_dst'] = nw_dst_masked
        if eth_type is not None:
            match_dict['eth_type'] = eth_type
        match = parser.OFPMatch(**match_dict)
        return match

    def valve_packetout(self, out_port, data):
        return parser.OFPPacketOut(
            datapath=None,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(out_port, 0)],
            data=data)

    def valve_flowmod(self, table_id, match=None, priority=None,
                      inst=[], command=ofp.OFPFC_ADD, out_port=0,
                      out_group=0, hard_timeout=0, idle_timeout=0):
        """Helper function to construct a flow mod message with cookie."""
        if match is None:
            match = self.valve_in_match()
        if priority is None:
            priority = self.dp.lowest_priority
        return parser.OFPFlowMod(
            datapath=None,
            cookie=self.dp.cookie,
            command=command,
            table_id=table_id,
            priority=priority,
            out_port=out_port,
            out_group=out_group,
            match=match,
            instructions=inst,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout)

    def valve_flowdel(self, table_id, match=None, priority=None,
                      out_port=ofp.OFPP_ANY):
        """Delete matching flows from a table."""
        return self.valve_flowmod(
            table_id,
            match=match,
            priority=priority,
            command=ofp.OFPFC_DELETE,
            out_port=out_port,
            out_group=ofp.OFPG_ANY)

    def valve_flowdrop(self, table_id, match=None, priority=None):
        """Add drop matching flow to a table."""
        return self.valve_flowmod(
            table_id,
            match=match,
            priority=priority,
            inst=[])

    def valve_flowcontroller(self, table_id, match=None, priority=None, inst=[]):
        return self.valve_flowmod(
            table_id,
            match=match,
            priority=priority,
            inst=[self.apply_actions([parser.OFPActionOutput(
                ofp.OFPP_CONTROLLER, max_len=256)])] + inst)

    def delete_all_valve_flows(self):
        """Delete all flows from Valve's tables."""
        ofmsgs = []
        for table_id in self.all_valve_tables():
            ofmsgs.append(self.valve_flowdel(table_id))
        return ofmsgs

    def add_default_drop_flows(self):
        """Add default drop rules."""
        ofmsgs = []

        # default drop on all tables
        for table in self.all_valve_tables():
            ofmsgs.append(self.valve_flowdrop(
                table,
                priority=self.dp.lowest_priority))

        # antispoof for FAUCET's MAC address
        ofmsgs.append(self.valve_flowdrop(
            self.dp.vlan_table,
            self.valve_in_match(eth_src=self.FAUCET_MAC),
            priority=self.dp.high_priority))

        # drop STDP BPDU
        for bpdu_mac in ("01:80:C2:00:00:00", "01:00:0C:CC:CC:CD"):
            ofmsgs.append(self.valve_flowdrop(
                self.dp.vlan_table,
                self.valve_in_match(eth_dst=bpdu_mac),
                priority=self.dp.highest_priority))

        # drop LLDP
        ofmsgs.append(self.valve_flowdrop(
            self.dp.vlan_table,
            self.valve_in_match(eth_type=ether.ETH_TYPE_LLDP),
            priority=self.dp.highest_priority))

        # drop broadcast sources
        ofmsgs.append(self.valve_flowdrop(
            self.dp.vlan_table,
            self.valve_in_match(eth_src=mac.BROADCAST_STR),
            priority=self.dp.highest_priority))

        return ofmsgs

    def add_vlan_flood_flow(self):
        """Add a flow to flood packets for unknown destinations."""
        return [self.valve_flowmod(
            self.dp.eth_dst_table,
            priority=self.dp.low_priority,
            inst=[self.goto_table(self.dp.flood_table)])]

    def add_controller_learn_flow(self):
        """Add a flow to allow the controller to learn and add flows for destinations."""
        return [self.valve_flowcontroller(
            self.dp.eth_src_table,
            priority=self.dp.low_priority,
            inst=[self.goto_table(self.dp.eth_dst_table)])]

    def add_default_flows(self):
        """Configure datapath with necessary default tables and rules."""
        ofmsgs = []
        ofmsgs.extend(self.delete_all_valve_flows())
        ofmsgs.extend(self.add_default_drop_flows())
        ofmsgs.extend(self.add_vlan_flood_flow())
        ofmsgs.extend(self.add_controller_learn_flow())
        return ofmsgs

    def add_ports_and_vlans(self, discovered_port_nums):
        """Add all ports and VLANs from configuration and discovered from switch."""
        ofmsgs = []
        all_port_nums = set()

        # add vlan ports
        for vlan in self.dp.vlans.itervalues():
            self.logger.info("Configuring VLAN %s", vlan)
            vlan_ports = vlan.tagged + vlan.untagged
            for port in vlan_ports:
                all_port_nums.add(port.number)
            # install eth_dst_table flood ofmsgs
            ofmsgs.extend(self.build_flood_rules(vlan))

        # add mirror ports.
        for port_num in self.dp.mirror_from_port.itervalues():
            all_port_nums.add(port_num)

        # add any ports discovered but not configured
        for port_num in discovered_port_nums:
            if self.ignore_port(port_num):
                continue
            if port_num not in all_port_nums:
                all_port_nums.add(port_num)

        # now configure all ports
        for port_num in all_port_nums:
            ofmsgs.extend(self.port_add(self.dp.dp_id, port_num))

        return ofmsgs

    def build_flood_ports_for_vlan(self, vlan_ports, eth_dst):
        ports = []
        for port in vlan_ports:
            if not port.running():
                continue
            if eth_dst is None or mac_addr_is_unicast(eth_dst):
                if not port.unicast_flood:
                    continue
            ports.append(port)
        return ports

    def build_flood_rule_actions(self, vlan, eth_dst):
        flood_acts = []
        tagged_ports = self.build_flood_ports_for_vlan(vlan.tagged, eth_dst)
        for port in tagged_ports:
            flood_acts.append(parser.OFPActionOutput(port.number))
        untagged_ports = self.build_flood_ports_for_vlan(vlan.untagged, eth_dst)
        if untagged_ports:
            flood_acts.append(parser.OFPActionPopVlan())
            for port in untagged_ports:
                flood_acts.append(parser.OFPActionOutput(port.number))
        return flood_acts

    def build_flood_rules(self, vlan, modify=False):
        """Add a flow to flood packets to unknown destinations on a VLAN."""
        command = ofp.OFPFC_ADD
        if modify:
            command = ofp.OFPFC_MODIFY_STRICT
        flood_priority = self.dp.low_priority
        flood_eth_dst_matches = []
        if vlan.unicast_flood:
            flood_eth_dst_matches.extend([(None, None)])
        flood_eth_dst_matches.extend([
            ('01:80:C2:00:00:00', '01:80:C2:00:00:00'), # 802.x
            ('01:00:5E:00:00:00', 'ff:ff:ff:00:00:00'), # IPv4 multicast
            ('33:33:00:00:00:00', 'ff:ff:00:00:00:00'), # IPv6 multicast
            (mac.BROADCAST_STR, None), # flood on ethernet broadcasts
        ])
        ofmsgs = []
        for eth_dst, eth_dst_mask in flood_eth_dst_matches:
            flood_acts = self.build_flood_rule_actions(vlan, eth_dst)
            ofmsgs.append(self.valve_flowmod(
                self.dp.flood_table,
                match=self.valve_in_match(
                    vlan=vlan, eth_dst=eth_dst, eth_dst_mask=eth_dst_mask),
                command=command,
                inst=[self.apply_actions(flood_acts)],
                priority=flood_priority))
            flood_priority += 1
        for port in vlan.tagged + vlan.untagged:
            if port.number in self.dp.mirror_from_port:
                mirror_port = self.dp.mirror_from_port[port.number]
                mirror_acts = [parser.OFPActionOutput(mirror_port)] + flood_acts
                for eth_dst, eth_dst_mask in flood_eth_dst_matches:
                    flood_acts = self.build_flood_rule_actions(vlan, eth_dst)
                    ofmsgs.append(self.valve_flowmod(
                        self.dp.flood_table,
                        match=self.valve_in_match(
                            in_port=port.number, vlan=vlan,
                            eth_dst=eth_dst, eth_dst_mask=eth_dst_mask),
                        command=command,
                        inst=[self.apply_actions(mirror_acts)],
                        priority=flood_priority))
                    flood_priority += 1
        return ofmsgs

    def datapath_connect(self, dp_id, discovered_port_nums):
        if self.ignore_dpid(dp_id):
            return []
        if discovered_port_nums is None:
            discovered_port_nums = []

        self.logger.info("Configuring datapath")
        ofmsgs = []
        ofmsgs.extend(self.add_default_flows())
        ofmsgs.extend(self.add_ports_and_vlans(discovered_port_nums))
        self.dp.running = True
        return ofmsgs

    def datapath_disconnect(self, dp_id):
        if not self.ignore_dpid(dp_id):
            self.logger.critical("Datapath disconnected")
        return []

    def datapath_down(self, dp_id):
        if self.ignore_dpid(dp_id):
            return []
        self.dp.running = False
        self.logger.warning("Datapath down {0}".format(dp_id))

    def port_add_acl(self, port_num):
        ofmsgs = []
        forwarding_table = self.dp.eth_src_table
        if port_num in self.dp.acl_in:
            acl_num = self.dp.acl_in[port_num]
            forwarding_table = self.dp.acl_table
            acl_rule_priority = self.dp.highest_priority
            acl_allow_inst = self.goto_table(self.dp.eth_src_table)
            for rule_conf in self.dp.acls[acl_num]:
                # default drop
                acl_inst = []
                match_dict = {}
                for attrib, attrib_value in rule_conf.iteritems():
                    if attrib == "allow":
                        if attrib_value == 1:
                            acl_inst.append(acl_allow_inst)
                        continue
                    if attrib == "in_port":
                        continue
                    match_dict[attrib] = attrib_value
                # override in_port always
                match_dict["in_port"] = port_num
                # to_match() needs to access parser via dp
                # this uses the old API, which is oh so convenient
                # (transparently handling masks for example).
                null_dp = namedtuple("null_dp", "ofproto_parser")
                null_dp.ofproto_parser = parser
                acl_match = ofctl.to_match(null_dp, match_dict)
                ofmsgs.append(self.valve_flowmod(
                    self.dp.acl_table,
                    acl_match,
                    priority=acl_rule_priority,
                    inst=acl_inst))
                acl_rule_priority -= 1
        return ofmsgs, forwarding_table

    def add_controller_ip(self, ip):
        ofmsgs = []
        # TODO: add IPv6
        host_ip = ipaddr.IPv4Network(
            '/'.join([str(ip.ip), str(ip.max_prefixlen)]))
        ofmsgs.append(self.valve_flowcontroller(
            self.dp.eth_src_table,
            self.valve_in_match(
                eth_type=ether.ETH_TYPE_IP,
                eth_dst=self.FAUCET_MAC,
                nw_proto=0x1,
                nw_src=ip,
                nw_dst=host_ip),
            priority=self.dp.highest_priority))
        ofmsgs.append(self.valve_flowcontroller(
            self.dp.eth_src_table,
            self.valve_in_match(
                eth_type=ether.ETH_TYPE_ARP, nw_dst=host_ip),
            priority=self.dp.highest_priority))
        return ofmsgs

    def port_add_vlan_untagged(self, port, vlan, forwarding_table, mirror_act):
        ofmsgs = []
        vid = vlan.vid
        if vlan.ip is not None:
            ofmsgs.extend(self.add_controller_ip(vlan.ip))
        push_vlan_act = mirror_act + [
            parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
            parser.OFPActionSetField(vlan_vid=vid|ofp.OFPVID_PRESENT)]
        push_vlan_inst = [
            self.apply_actions(push_vlan_act),
            self.goto_table(forwarding_table)
        ]
        null_vlan = namedtuple("null_vlan", "vid")
        null_vlan.vid = ofp.OFPVID_NONE
        ofmsgs.append(self.valve_flowmod(
            self.dp.vlan_table,
            self.valve_in_match(in_port=port.number, vlan=null_vlan),
            priority=self.dp.low_priority,
            inst=push_vlan_inst))
        ofmsgs.extend(self.build_flood_rules(vlan))
        return ofmsgs

    def port_add_vlan_tagged(self, port, vlan, forwarding_table, mirror_act):
        ofmsgs = []
        vlan_inst = [
            self.apply_actions(mirror_act),
            self.goto_table(forwarding_table)
        ]
        ofmsgs.append(self.valve_flowmod(
            self.dp.vlan_table,
            self.valve_in_match(in_port=port.number, vlan=vlan),
            priority=self.dp.low_priority,
            inst=vlan_inst))
        ofmsgs.extend(self.build_flood_rules(vlan))
        return ofmsgs

    def port_add_vlans(self, port, forwarding_table, mirror_act):
        ofmsgs = []
        vlans = self.dp.vlans.values()
        tagged_vlans_with_port = [
            vlan for vlan in vlans if port in vlan.tagged]
        untagged_vlans_with_port = [
            vlan for vlan in vlans if port in vlan.untagged]
        for vlan in tagged_vlans_with_port:
            ofmsgs.extend(self.port_add_vlan_tagged(
                port, vlan, forwarding_table, mirror_act))
        for vlan in untagged_vlans_with_port:
            ofmsgs.extend(self.port_add_vlan_untagged(
                port, vlan, forwarding_table, mirror_act))
        return ofmsgs

    def port_add(self, dp_id, port_num):
        if self.ignore_dpid(dp_id) or self.ignore_port(port_num):
            return []

        if port_num not in self.dp.ports:
            self.logger.info(
                "Autoconfiguring port:%u based on default config", port_num)
            self.dp.add_port(port_num)

        port = self.dp.ports[port_num]
        self.logger.info("Port added {0}".format(port))
        port.phys_up = True

        if not port.running():
            return []

        in_port_match = self.valve_in_match(in_port=port_num)
        ofmsgs = []
        self.logger.info("Sending config for port {0}".format(port))

        for table in self.all_valve_tables():
            ofmsgs.append(self.valve_flowdel(table, in_port_match))

        if port_num in self.dp.mirror_from_port.values():
            # this is a mirror port - drop all input packets
            ofmsgs.append(self.valve_flowdrop(
                self.dp.vlan_table,
                in_port_match))
            return ofmsgs

        mirror_act = []
        # this port is mirrored to another port
        if port_num in self.dp.mirror_from_port:
            mirror_port_num = self.dp.mirror_from_port[port_num]
            mirror_act = [parser.OFPActionOutput(mirror_port_num)]

        acl_ofmsgs, forwarding_table = self.port_add_acl(port_num)
        ofmsgs.extend(acl_ofmsgs)
        ofmsgs.extend(self.port_add_vlans(port, forwarding_table, mirror_act))
        return ofmsgs

    def port_delete(self, dp_id, port_num):
        if self.ignore_dpid(dp_id) or self.ignore_port(port_num):
            return []

        if port_num not in self.dp.ports:
            return []

        port = self.dp.ports[port_num]
        port.phys_up = False

        self.logger.warning("Port down: {0}".format(port))

        ofmsgs = []

        # delete all rules matching this port in all tables.
        for table in self.all_valve_tables():
            ofmsgs.append(self.valve_flowdel(table,
                self.valve_in_match(in_port=port_num)))

        # delete eth_dst rules
        ofmsgs.append(self.valve_flowdel(
            self.dp.eth_dst_table,
            out_port=port_num))

        ofmsgs.append(parser.OFPBarrierRequest(None))

        for vlan in self.dp.vlans.values():
            if port_num in vlan.tagged or port_num in vlan.untagged:
                ofmsgs.extend(self.build_flood_rules(vlan), modify=True)

        return ofmsgs

    def delete_host_from_vlan(self, eth_src, vlan):
        ofmsgs = []
        # delete any existing ofmsgs for this vlan/mac combination on the
        # src mac table
        ofmsgs.append(self.valve_flowdel(
            self.dp.eth_src_table,
            self.valve_in_match(vlan=vlan, eth_src=eth_src)))

        # delete any existing ofmsgs for this vlan/mac combination on the dst
        # mac table
        ofmsgs.append(self.valve_flowdel(
            self.dp.eth_dst_table,
            self.valve_in_match(vlan=vlan, eth_dst=eth_src)))

        ofmsgs.append(parser.OFPBarrierRequest(None))
        return ofmsgs

    def control_plane_arp_handler(self, in_port, vlan_vid, eth_src, arp_pkt):
        eth_pkt = ethernet.ethernet(
            eth_src, self.FAUCET_MAC, ether.ETH_TYPE_ARP)
        arp_pkt = arp.arp(opcode=2, src_mac=self.FAUCET_MAC, src_ip=arp_pkt.dst_ip,
            dst_mac=eth_src, dst_ip=arp_pkt.src_ip)
        pkt = packet.Packet()
        pkt.add_protocol(eth_pkt)
        pkt.add_protocol(arp_pkt)
        pkt.serialize()
        return [self.valve_packetout(in_port, pkt.data)]

    def control_plane_icmp_handler(self, in_port, vlan_vid, eth_src, ipv4_pkt, icmp_pkt):
        eth_pkt = ethernet.ethernet(
            eth_src, self.FAUCET_MAC, ether.ETH_TYPE_IP)
        ipv4_pkt = ipv4.ipv4(
            dst=ipv4_pkt.src, src=ipv4_pkt.dst, proto=ipv4_pkt.proto)
        icmp_pkt = icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE,
            data=icmp_pkt.data)
        pkt = packet.Packet()
        pkt.add_protocol(eth_pkt)
        pkt.add_protocol(ipv4_pkt)
        pkt.add_protocol(icmp_pkt)
        pkt.serialize()
        return [self.valve_packetout(in_port, pkt.data)]

    def control_plane_handler(self, in_port, vlan_vid, eth_src,
                              ipv4_pkt, arp_pkt, icmp_pkt):
        if arp_pkt is not None:
            return self.control_plane_arp_handler(
                in_port, vlan_vid, eth_src, arp_pkt)
        if icmp_pkt is not None:
            return self.control_plane_icmp_handler(
                in_port, vlan_vid, eth_src, ipv4_pkt, icmp_pkt)
        return []

    def faucet_ips(self):
        return [str(vlan.ip.ip) for vlan in self.dp.vlans.values()
            if vlan.ip is not None]

    def to_faucet_ip(self, src_ip, dst_ip):
        faucet_ips = self.faucet_ips()
        if src_ip in faucet_ips:
            return False
        if dst_ip in faucet_ips:
            return True
        return False

    def learn_host_on_vlan_port(self, port, vlan, eth_src):
        ofmsgs = []
        in_port = port.number

        # hosts learned on this port never relearned
        if port.permanent_learn:
            learn_timeout = 0

            # antispoof this host
            ofmsgs.append(self.valve_flowdrop(
                self.dp.eth_src_table,
                self.valve_in_match(vlan=vlan, eth_src=eth_src),
                priority=(self.dp.highest_priority-1)))
        else:
            learn_timeout = self.dp.timeout
            ofmsgs.extend(self.delete_host_from_vlan(eth_src, vlan))

        mirror_acts = []
        if in_port in self.dp.mirror_from_port:
            mirror_port_num = self.dp.mirror_from_port[in_port]
            mirror_acts = [parser.OFPActionOutput(mirror_port_num)]

        # Update datapath to no longer send packets from this mac to controller
        # note the use of hard_timeout here and idle_timeout for the dst table
        # this is to ensure that the source rules will always be deleted before
        # any rules on the dst table. Otherwise if the dst table rule expires
        # but the src table rule is still being hit intermittantly the switch
        # will flood packets to that dst and not realise it needs to relearn
        # the rule
        ofmsgs.append(self.valve_flowmod(
            self.dp.eth_src_table,
            self.valve_in_match(in_port=in_port, vlan=vlan, eth_src=eth_src),
            priority=self.dp.highest_priority,
            inst=[self.goto_table(self.dp.eth_dst_table)],
            hard_timeout=learn_timeout))

        # update datapath to output packets to this mac via the associated port
        if vlan.port_is_tagged(in_port):
            dst_act = [parser.OFPActionOutput(in_port)]
        else:
            dst_act = [
                parser.OFPActionPopVlan(),
                parser.OFPActionOutput(in_port)]
        if mirror_acts:
            dst_act.extend(mirror_acts)
        inst = [self.apply_actions(dst_act)]
        ofmsgs.append(self.valve_flowmod(
            self.dp.eth_dst_table,
            self.valve_in_match(vlan=vlan, eth_dst=eth_src),
            priority=self.dp.high_priority,
            inst=inst,
            idle_timeout=learn_timeout))
        return ofmsgs

    def rcv_packet(self, dp_id, in_port, vlan_vid, match, pkt):
        if self.ignore_dpid(dp_id) or self.ignore_port(in_port):
            return []

        if not self.dp.running:
            self.logger.error("Packet_in on unconfigured datapath")
            return []

        if in_port not in self.dp.ports:
            return []

        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        eth_src = eth_pkt.src
        eth_dst = eth_pkt.dst

        # Packet may be for our control plane.
        if eth_dst == self.FAUCET_MAC or not mac_addr_is_unicast(eth_dst):
            arp_pkt = pkt.get_protocol(arp.arp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            if ((arp_pkt is not None and arp_pkt.opcode == 1 and
                    self.to_faucet_ip(arp_pkt.src_ip, arp_pkt.dst_ip)) or
                (icmp_pkt is not None and icmp_pkt.code == 0 and
                    self.to_faucet_ip(ipv4_pkt.src, ipv4_pkt.dst))):
                return self.control_plane_handler(
                    in_port, vlan_vid, eth_src, ipv4_pkt, arp_pkt, icmp_pkt)

        if not mac_addr_is_unicast(eth_src):
            self.logger.info(
                "Packet_in with multicast ethernet source address")
            return []

        self.logger.debug("Packet_in dp_id: %x src:%s in_port:%d vid:%s",
                          dp_id, eth_src, in_port, vlan_vid)

        port = self.dp.ports[in_port]
        vlan = self.dp.vlans[vlan_vid]
        return self.learn_host_on_vlan_port(port, vlan, eth_src)

    def reload_config(self, new_dp):
        if not self.dp.running:
            return []
        self.dp = new_dp
        return self.datapath_connect(self.dp.dp_id, self.dp.ports.keys())
