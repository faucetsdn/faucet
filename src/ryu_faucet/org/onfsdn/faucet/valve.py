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

import logging
from logging.handlers import TimedRotatingFileHandler
import time
import os

from collections import namedtuple

import ipaddr

import aruba.aruba_pipeline as aruba
import valve_of
import util

from ryu.lib import mac
from ryu.lib.packet import arp, ethernet, icmp, icmpv6, ipv4, ipv6, packet
from ryu.lib.packet import vlan as packet_vlan
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_3 as ofp


class LinkNeighbor(object):

    def __init__(self, eth_src, now):
        self.eth_src = eth_src
        self.cache_time = now


class HostCacheEntry(object):

    def __init__(self, eth_src, permanent, now):
        self.eth_src = eth_src
        self.permanent = permanent
        self.cache_time = now


def valve_factory(dp):
    """Return a Valve object based dp's hardware configuration field.

    Arguments:
    dp -- a DP object with the configuration for this valve.
    """
    SUPPORTED_HARDWARE = {
        'Allied-Telesis': Valve,
        'Aruba': ArubaValve,
        'NoviFlow': Valve,
        'Open vSwitch': Valve,
        'ZodiacFX': Valve,
    }

    if dp.hardware in SUPPORTED_HARDWARE:
        return SUPPORTED_HARDWARE[dp.hardware]
    else:
        return None


class Valve(object):
    """Generates the messages to configure a datapath as a l2 learning switch.

    Vendor specific implementations may require sending configuration flows.
    This can be achieved by inheriting from this class and overwriting the
    function switch_features.
    """

    FAUCET_MAC = '0e:00:00:00:00:01'
    TABLE_MATCH_TYPES = {}

    def __init__(self, dp, logname, *args, **kwargs):
        self.dp = dp
        self.logger = logging.getLogger(logname + '.valve')
        self.ofchannel_logger = None
        self.register_table_match_types()

    def register_table_match_types(self):
        self.TABLE_MATCH_TYPES = {
            self.dp.vlan_table: (
                'in_port', 'vlan_vid', 'eth_src', 'eth_dst', 'eth_type'),
            # TODO: eth_src_table matches too many things. It should
            # be split further into two tables for IPv4/IPv6 entries.
            self.dp.eth_src_table: (
                'in_port', 'vlan_vid', 'eth_src', 'eth_dst', 'eth_type',
                'ip_proto',
                'icmpv6_type', 'ipv6_nd_target',
                'arp_tpa', 'ipv4_src'),
            self.dp.ipv4_fib_table: (
                'vlan_vid', 'eth_type', 'ip_proto',
                'ipv4_src', 'ipv4_dst'),
            self.dp.ipv6_fib_table: (
                'vlan_vid', 'eth_type', 'ip_proto',
                'icmpv6_type', 'ipv6_dst'),
            self.dp.eth_dst_table: (
                'vlan_vid', 'eth_dst'),
            self.dp.flood_table: (
                'in_port', 'vlan_vid', 'eth_dst'),
        }

    def in_port_tables(self):
        in_port_tables = [self.dp.acl_table]
        for table_id in self.TABLE_MATCH_TYPES:
            if 'in_port' in self.TABLE_MATCH_TYPES:
                in_port_tables.append(table_id)
        return in_port_tables

    def switch_features(self, dp_id, msg):
        """Send configuration flows necessary for the switch implementation.

        Arguments:
        dp_id -- the Datapath unique ID (64bit int)
        msg -- OFPSwitchFeatures msg sent from switch.

        Vendor specific configuration should be implemented here.
        """
        return []

    def ofchannel_log(self, ofmsgs):
        if self.dp is not None:
            if self.dp.ofchannel_log is not None:
                if self.ofchannel_logger is None:
                    self.ofchannel_logger = logging.getLogger(
                        self.dp.ofchannel_log)
                    logger_handler = TimedRotatingFileHandler(
                        self.dp.ofchannel_log,
                        when='midnight')
                    log_fmt = ('%(asctime)s %(name)-6s '
                               '%(levelname)-8s %(message)s')
                    logger_handler.setFormatter(
                        logging.Formatter(log_fmt, '%b %d %H:%M:%S'))
                    self.ofchannel_logger.addHandler(logger_handler)
                    self.ofchannel_logger.propagate = 0
                    self.ofchannel_logger.setLevel(logging.DEBUG)
                for ofmsg in ofmsgs:
                    self.ofchannel_logger.debug(ofmsg)

    def valve_in_match(self, table_id, in_port=None, vlan=None,
                       eth_type=None, eth_src=None,
                       eth_dst=None, eth_dst_mask=None,
                       ipv6_nd_target=None, icmpv6_type=None,
                       nw_proto=None,
                       nw_src=None, nw_dst=None):
        match_dict = {}
        if in_port is not None:
            match_dict['in_port'] = in_port
        if vlan is not None:
            if vlan.vid == ofp.OFPVID_NONE:
                match_dict['vlan_vid'] = ofp.OFPVID_NONE
            else:
                match_dict['vlan_vid'] = (vlan.vid | ofp.OFPVID_PRESENT)
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
        if icmpv6_type is not None:
            match_dict['icmpv6_type'] = icmpv6_type
        if ipv6_nd_target is not None:
            match_dict['ipv6_nd_target'] = str(ipv6_nd_target.ip)
        if nw_dst is not None:
            nw_dst_masked = (str(nw_dst.ip), str(nw_dst.netmask))
            if eth_type == ether.ETH_TYPE_ARP:
                match_dict['arp_tpa'] = nw_dst_masked
            elif eth_type == ether.ETH_TYPE_IP:
                match_dict['ipv4_dst'] = nw_dst_masked
            else:
                match_dict['ipv6_dst'] = nw_dst_masked
        if eth_type is not None:
            match_dict['eth_type'] = eth_type

        if table_id != self.dp.acl_table:
            assert table_id in self.TABLE_MATCH_TYPES,\
                '%u table not registered' % table_id
            for match_type in match_dict.iterkeys():
                assert match_type in self.TABLE_MATCH_TYPES[table_id],\
                    '%s match not registered for table %u' % (
                        match_type, table_id)

        match = valve_of.match(match_dict)
        return match

    def ignore_dpid(self, dp_id):
        """Ignore all DPIDs except the DPID configured."""
        if dp_id != self.dp.dp_id:
            self.logger.error('Unknown dpid:%s', dp_id)
            return True
        return False

    def all_valve_tables(self):
        return (
            self.dp.vlan_table,
            self.dp.acl_table,
            self.dp.eth_src_table,
            self.dp.ipv4_fib_table,
            self.dp.ipv6_fib_table,
            self.dp.eth_dst_table,
            self.dp.flood_table)

    def valve_flowmod(self, table_id, match=None, priority=None,
                      inst=None, command=ofp.OFPFC_ADD, out_port=0,
                      out_group=0, hard_timeout=0, idle_timeout=0):
        """Helper function to construct a flow mod message with cookie."""
        if match is None:
            match = self.valve_in_match(table_id)
        if priority is None:
            priority = self.dp.lowest_priority
        if inst is None:
            inst = []
        return valve_of.flowmod(
            self.dp.cookie,
            command,
            table_id,
            priority,
            out_port,
            out_group,
            match,
            inst,
            hard_timeout,
            idle_timeout)

    def valve_flowdel(self, table_id, match=None, priority=None,
                      out_port=ofp.OFPP_ANY):
        """Delete matching flows from a table."""
        return [
            self.valve_flowmod(
                table_id,
                match=match,
                priority=priority,
                command=ofp.OFPFC_DELETE,
                out_port=out_port,
                out_group=ofp.OFPG_ANY),
            valve_of.barrier()]

    def valve_flowdrop(self, table_id, match=None, priority=None,
                       hard_timeout=0):
        """Add drop matching flow to a table."""
        return self.valve_flowmod(
            table_id,
            match=match,
            priority=priority,
            hard_timeout=hard_timeout,
            inst=[])

    def valve_flowcontroller(self, table_id, match=None, priority=None,
                             inst=None):
        if inst is None:
            inst = []
        return self.valve_flowmod(
            table_id,
            match=match,
            priority=priority,
            inst=[valve_of.apply_actions(
                [valve_of.output_controller()])] + inst)

    def delete_all_valve_flows(self):
        """Delete all flows from all FAUCET tables."""
        ofmsgs = []
        for table_id in self.all_valve_tables():
            ofmsgs.extend(self.valve_flowdel(table_id))
        return ofmsgs

    def add_default_drop_flows(self):
        """Add default drop rules on all FAUCET tables."""

        # default drop on all tables.
        ofmsgs = []
        for table in self.all_valve_tables():
            ofmsgs.append(self.valve_flowdrop(
                table,
                priority=self.dp.lowest_priority))

        # antispoof for FAUCET's MAC address
        # TODO: antispoof for controller IPs on this VLAN, too.
        ofmsgs.append(self.valve_flowdrop(
            self.dp.vlan_table,
            self.valve_in_match(
                self.dp.vlan_table, eth_src=self.FAUCET_MAC),
            priority=self.dp.high_priority))

        # drop STDP BPDU
        for bpdu_mac in ('01:80:C2:00:00:00', '01:00:0C:CC:CC:CD'):
            ofmsgs.append(self.valve_flowdrop(
                self.dp.vlan_table,
                self.valve_in_match(
                    self.dp.vlan_table, eth_dst=bpdu_mac),
                priority=self.dp.highest_priority))

        # drop LLDP
        ofmsgs.append(self.valve_flowdrop(
            self.dp.vlan_table,
            self.valve_in_match(
                self.dp.vlan_table, eth_type=ether.ETH_TYPE_LLDP),
            priority=self.dp.highest_priority))

        # drop broadcast sources
        ofmsgs.append(self.valve_flowdrop(
            self.dp.vlan_table,
            self.valve_in_match(
                self.dp.vlan_table, eth_src=mac.BROADCAST_STR),
            priority=self.dp.highest_priority))

        return ofmsgs

    def add_vlan_flood_flow(self):
        """Add a flow to flood packets for unknown destinations."""
        return [self.valve_flowmod(
            self.dp.eth_dst_table,
            priority=self.dp.low_priority,
            inst=[valve_of.goto_table(self.dp.flood_table)])]

    def add_controller_learn_flow(self):
        """Add a flow for controller to learn/add flows for destinations."""
        return [self.valve_flowcontroller(
            self.dp.eth_src_table,
            priority=self.dp.low_priority,
            inst=[valve_of.goto_table(self.dp.eth_dst_table)])]

    def add_default_flows(self):
        """Configure datapath with necessary default tables and rules."""
        ofmsgs = []
        ofmsgs.extend(self.delete_all_valve_flows())
        ofmsgs.extend(self.add_default_drop_flows())
        ofmsgs.extend(self.add_vlan_flood_flow())
        ofmsgs.extend(self.add_controller_learn_flow())
        return ofmsgs

    def add_ports_and_vlans(self, discovered_port_nums):
        """Add all configured and discovered ports and VLANs."""
        ofmsgs = []
        all_port_nums = set()

        # add vlan ports
        for vlan in self.dp.vlans.itervalues():
            self.logger.info('Configuring VLAN %s', vlan)
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
            if valve_of.ignore_port(port_num):
                continue
            if port_num not in all_port_nums:
                all_port_nums.add(port_num)

        # now configure all ports
        for port_num in all_port_nums:
            ofmsgs.extend(self.port_add(self.dp.dp_id, port_num))

        return ofmsgs

    @staticmethod
    def build_flood_ports_for_vlan(vlan_ports, exclude_unicast):
        ports = []
        for port in vlan_ports:
            if not port.running():
                continue
            if exclude_unicast:
                if not port.unicast_flood:
                    continue
            ports.append(port)
        return ports

    def build_flood_rule_actions(self, vlan, exclude_unicast, exclude_ports=[]):
        flood_acts = []
        tagged_ports = self.build_flood_ports_for_vlan(
            vlan.tagged, exclude_unicast)
        untagged_ports = self.build_flood_ports_for_vlan(
            vlan.untagged, exclude_unicast)
        for port in tagged_ports:
            if port not in exclude_ports:
                flood_acts.append(valve_of.output_port(port.number))
        if untagged_ports:
            flood_acts.append(valve_of.pop_vlan())
            for port in untagged_ports:
                if port not in exclude_ports:
                    flood_acts.append(valve_of.output_port(port.number))
        return flood_acts

    def vlan_mirrored_ports(self, vlan):
        mirrored_ports = []
        for port in vlan.tagged + vlan.untagged:
            if port.number in self.dp.mirror_from_port:
                mirrored_ports.append(port)
        return mirrored_ports

    def build_flood_rules(self, vlan, modify=False):
        """Add flows to flood packets to unknown destinations on a VLAN."""
        # TODO: not all vendors implement groups well.
        # That means we need flood rules for each input port, outputting
        # to all ports except the input port. When all vendors implement
        # groups correctly we can use them.
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
        vlan_all_ports = self.build_flood_ports_for_vlan(
            vlan.tagged + vlan.untagged, False)
        mirrored_ports = self.vlan_mirrored_ports(vlan)
        for eth_dst, eth_dst_mask in flood_eth_dst_matches:
            for port in vlan_all_ports:
                if eth_dst is None:
                    flood_acts = self.build_flood_rule_actions(
                        vlan, False, exclude_ports=[port])
                else:
                    flood_acts = self.build_flood_rule_actions(
                        vlan, True, exclude_ports=[port])
                ofmsgs.append(self.valve_flowmod(
                    self.dp.flood_table,
                    match=self.valve_in_match(
                        self.dp.flood_table, in_port=port.number, vlan=vlan,
                        eth_dst=eth_dst, eth_dst_mask=eth_dst_mask),
                    command=command,
                    inst=[valve_of.apply_actions(flood_acts)],
                    priority=flood_priority))
            flood_priority += 1
            for port in mirrored_ports:
                mirror_port = self.dp.mirror_from_port[port.number]
                if eth_dst is None:
                    flood_acts = self.build_flood_rule_actions(vlan, False)
                else:
                    flood_acts = self.build_flood_rule_actions(vlan, True)
                mirror_acts = [
                    valve_of.output_port(mirror_port)] + flood_acts
                ofmsgs.append(self.valve_flowmod(
                    self.dp.flood_table,
                    match=self.valve_in_match(
                        self.dp.flood_table,
                        vlan=vlan,
                        in_port=port.number,
                        eth_dst=eth_dst,
                        eth_dst_mask=eth_dst_mask),
                    command=command,
                    inst=[valve_of.apply_actions(mirror_acts)],
                    priority=flood_priority))
            flood_priority += 1
        return ofmsgs

    def datapath_connect(self, dp_id, discovered_port_nums):
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
        if self.ignore_dpid(dp_id):
            return []
        if discovered_port_nums is None:
            discovered_port_nums = []

        self.logger.info('Configuring datapath')
        ofmsgs = []
        ofmsgs.extend(self.add_default_flows())
        ofmsgs.extend(self.add_ports_and_vlans(discovered_port_nums))
        self.dp.running = True
        return ofmsgs

    def datapath_disconnect(self, dp_id):
        """Update n/w state db upon disconnection of datapath with id dp_id."""
        if not self.ignore_dpid(dp_id):
            self.logger.critical('Datapath disconnected')
        return []

    def datapath_down(self, dp_id):
        if not self.ignore_dpid(dp_id):
            self.dp.running = False
            self.logger.warning('Datapath %s down', dp_id)
        return []

    def port_add_acl(self, port_num):
        ofmsgs = []
        forwarding_table = self.dp.eth_src_table
        if port_num in self.dp.acl_in:
            acl_num = self.dp.acl_in[port_num]
            forwarding_table = self.dp.acl_table
            acl_rule_priority = self.dp.highest_priority
            acl_allow_inst = valve_of.goto_table(self.dp.eth_src_table)
            for rule_conf in self.dp.acls[acl_num]:
                acl_inst = []
                match_dict = {}
                for attrib, attrib_value in rule_conf.iteritems():
                    if attrib == 'actions':
                        if 'mirror' in attrib_value:
                            port_no = attrib_value['mirror']
                            acl_inst.append(
                                valve_of.apply_actions([
                                    valve_of.output_port(port_no)]))
                        # if output selected, output packet now
                        # and exit pipeline.
                        if 'output' in attrib_value:
                            output_dict = attrib_value['output']
                            output_actions = []
                            # if destination rewriting selected, rewrite it.
                            if 'dl_dst' in output_dict:
                                output_actions.append(
                                    valve_of.set_eth_dst(output_dict['dl_dst']))
                            # if vlan tag is specified, push it.
                            if 'vlan_vid' in output_dict:
                                output_actions.extend(
                                    valve_of.push_vlan_act(output_dict['vlan_vid']))
                            # output to port
                            port_no = output_dict['port']
                            output_actions.append(
                                valve_of.output_port(port_no))
                            acl_inst.append(
                                valve_of.apply_actions(output_actions))
                            continue
                        if attrib_value['allow'] == 1:
                            acl_inst.append(acl_allow_inst)
                        continue
                    if attrib == 'in_port':
                        continue
                    match_dict[attrib] = attrib_value
                # override in_port always
                match_dict['in_port'] = port_num
                acl_match = valve_of.match_from_dict(match_dict)
                ofmsgs.append(self.valve_flowmod(
                    self.dp.acl_table,
                    acl_match,
                    priority=acl_rule_priority,
                    inst=acl_inst))
                acl_rule_priority -= 1
        return ofmsgs, forwarding_table

    def add_controller_ips(self, controller_ips, vlan):
        ofmsgs = []
        for controller_ip in controller_ips:
            controller_ip_host = ipaddr.IPNetwork(
                '/'.join((str(controller_ip.ip),
                          str(controller_ip.max_prefixlen))))
            max_prefixlen = controller_ip_host.prefixlen
            if controller_ip_host.version == 4:
                ofmsgs.append(self.valve_flowcontroller(
                    self.dp.eth_src_table,
                    self.valve_in_match(
                        self.dp.eth_src_table,
                        eth_type=ether.ETH_TYPE_ARP,
                        nw_dst=controller_ip_host,
                        vlan=vlan),
                    priority=self.dp.highest_priority + max_prefixlen))
                # Initialize IPv4 FIB
                ofmsgs.append(self.valve_flowmod(
                    self.dp.eth_src_table,
                    self.valve_in_match(
                        self.dp.eth_src_table,
                        eth_type=ether.ETH_TYPE_IP,
                        eth_dst=self.FAUCET_MAC,
                        vlan=vlan),
                    priority=self.dp.highest_priority,
                    inst=[valve_of.goto_table(self.dp.ipv4_fib_table)]))
                ofmsgs.append(self.valve_flowcontroller(
                    self.dp.ipv4_fib_table,
                    self.valve_in_match(
                        self.dp.ipv4_fib_table,
                        vlan=vlan,
                        eth_type=ether.ETH_TYPE_IP,
                        nw_proto=inet.IPPROTO_ICMP,
                        nw_src=controller_ip,
                        nw_dst=controller_ip_host),
                    priority=self.dp.highest_priority + max_prefixlen))
            else:
                ofmsgs.append(self.valve_flowcontroller(
                    self.dp.eth_src_table,
                    self.valve_in_match(
                        self.dp.eth_src_table,
                        eth_type=ether.ETH_TYPE_IPV6,
                        vlan=vlan,
                        nw_proto=inet.IPPROTO_ICMPV6,
                        ipv6_nd_target=controller_ip_host,
                        icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT),
                    priority=self.dp.highest_priority + max_prefixlen))
                ofmsgs.append(self.valve_flowcontroller(
                    self.dp.eth_src_table,
                    self.valve_in_match(
                        self.dp.eth_src_table,
                        eth_type=ether.ETH_TYPE_IPV6,
                        eth_dst=self.FAUCET_MAC,
                        vlan=vlan,
                        nw_proto=inet.IPPROTO_ICMPV6,
                        icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT),
                    priority=self.dp.highest_priority + max_prefixlen))
                # Initialize IPv6 FIB
                ofmsgs.append(self.valve_flowmod(
                    self.dp.eth_src_table,
                    self.valve_in_match(
                        self.dp.eth_src_table,
                        eth_type=ether.ETH_TYPE_IPV6,
                        eth_dst=self.FAUCET_MAC,
                        vlan=vlan),
                    priority=self.dp.highest_priority,
                    inst=[valve_of.goto_table(self.dp.ipv6_fib_table)]))
                ofmsgs.append(self.valve_flowcontroller(
                    self.dp.ipv6_fib_table,
                    self.valve_in_match(
                        self.dp.ipv6_fib_table,
                        eth_type=ether.ETH_TYPE_IPV6,
                        vlan=vlan,
                        nw_proto=inet.IPPROTO_ICMPV6,
                        nw_dst=controller_ip_host,
                        icmpv6_type=icmpv6.ICMPV6_ECHO_REQUEST),
                    priority=self.dp.highest_priority + max_prefixlen))
        return ofmsgs

    def port_add_vlan_untagged(self, port, vlan, forwarding_table, mirror_act):
        ofmsgs = []
        ofmsgs.extend(self.add_controller_ips(vlan.controller_ips, vlan))
        push_vlan_act = mirror_act + valve_of.push_vlan_act(vlan.vid)
        push_vlan_inst = [
            valve_of.apply_actions(push_vlan_act),
            valve_of.goto_table(forwarding_table)
        ]
        null_vlan = namedtuple('null_vlan', 'vid')
        null_vlan.vid = ofp.OFPVID_NONE
        ofmsgs.append(self.valve_flowmod(
            self.dp.vlan_table,
            self.valve_in_match(
                self.dp.vlan_table, in_port=port.number, vlan=null_vlan),
            priority=self.dp.low_priority,
            inst=push_vlan_inst))
        ofmsgs.extend(self.build_flood_rules(vlan))
        return ofmsgs

    def port_add_vlan_tagged(self, port, vlan, forwarding_table, mirror_act):
        ofmsgs = []
        ofmsgs.extend(self.add_controller_ips(vlan.controller_ips, vlan))
        vlan_inst = [
            valve_of.goto_table(forwarding_table)
        ]
        if mirror_act:
            vlan_inst = [valve_of.apply_actions(mirror_act)] + vlan_inst
        ofmsgs.append(self.valve_flowmod(
            self.dp.vlan_table,
            self.valve_in_match(
                self.dp.vlan_table, in_port=port.number, vlan=vlan),
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
        """Generate openflow msgs to update the datapath upon addition of port.

        Arguments:
        dp_id -- the unique id of the datapath
        port_num -- the port number of the new port

        Returns
        A list of flow mod messages to be sent to the datapath."""
        if self.ignore_dpid(dp_id) or valve_of.ignore_port(port_num):
            return []

        if port_num not in self.dp.ports:
            self.logger.info(
                'Ignoring port:%u not present in configuration file', port_num)
            return []

        port = self.dp.ports[port_num]
        self.logger.info('Port %s added', port)
        port.phys_up = True

        if not port.running():
            return []

        in_port_match = self.valve_in_match(
            self.dp.vlan_table, in_port=port_num)
        ofmsgs = []
        self.logger.info('Sending config for port %s', port)

        for table in self.in_port_tables():
            ofmsgs.extend(self.valve_flowdel(table, in_port_match))

        # if this port is used as mirror port in any acl - drop input packets
        for acl in self.dp.acls.values():
            for rule_conf in acl:
                for attrib, attrib_value in rule_conf.iteritems():
                    if attrib == 'actions':
                        if 'mirror' in attrib_value:
                            port_no = attrib_value['mirror']
                            mirror_in_port_match = self.valve_in_match(
                                self.dp.vlan_table, in_port=port_no)
                            ofmsgs.append(self.valve_flowdrop(
                                self.dp.vlan_table,
                                mirror_in_port_match))

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
            mirror_act = [valve_of.output_port(mirror_port_num)]

        acl_ofmsgs, forwarding_table = self.port_add_acl(port_num)
        ofmsgs.extend(acl_ofmsgs)
        ofmsgs.extend(self.port_add_vlans(port, forwarding_table, mirror_act))

        return ofmsgs

    def port_delete(self, dp_id, port_num):
        """Generate openflow msgs to update the datapath upon deletion of port.

        Returns
        A list of flow mod messages to be sent to the datapath."""
        if self.ignore_dpid(dp_id) or valve_of.ignore_port(port_num):
            return []

        if port_num not in self.dp.ports:
            return []

        port = self.dp.ports[port_num]
        port.phys_up = False

        self.logger.warning('Port %s down', port)

        ofmsgs = []

        if not port.permanent_learn:
            for table in self.in_port_tables():
                ofmsgs.extend(self.valve_flowdel(
                    table,
                    self.valve_in_match(
                        table, in_port=port_num)))

            # delete eth_dst rules
            ofmsgs.extend(self.valve_flowdel(
                self.dp.eth_dst_table,
                out_port=port_num))

        for vlan in self.dp.vlans.values():
            if port_num in vlan.tagged or port_num in vlan.untagged:
                ofmsgs.extend(self.build_flood_rules(vlan), modify=True)

        return ofmsgs

    def delete_host_from_vlan(self, eth_src, vlan):
        ofmsgs = []
        # delete any existing ofmsgs for this vlan/mac combination on the
        # src mac table
        ofmsgs.extend(self.valve_flowdel(
            self.dp.eth_src_table,
            self.valve_in_match(
                self.dp.eth_src_table, vlan=vlan, eth_src=eth_src)))

        # delete any existing ofmsgs for this vlan/mac combination on the dst
        # mac table
        ofmsgs.extend(self.valve_flowdel(
            self.dp.eth_dst_table,
            self.valve_in_match(
                self.dp.eth_dst_table, vlan=vlan, eth_dst=eth_src)))

        return ofmsgs

    def build_ethernet_pkt(self, eth_dst, in_port, vlan, ethertype):
        pkt = packet.Packet()
        if vlan.port_is_tagged(in_port):
            eth_pkt = ethernet.ethernet(
                eth_dst, self.FAUCET_MAC, ether.ETH_TYPE_8021Q)
            vlan_pkt = packet_vlan.vlan(
                vid=vlan.vid, ethertype=ethertype)
            pkt.add_protocol(eth_pkt)
            pkt.add_protocol(vlan_pkt)
        else:
            eth_pkt = ethernet.ethernet(
                eth_dst, self.FAUCET_MAC, ethertype)
            pkt.add_protocol(eth_pkt)
        return pkt

    def add_route(self, vlan, ip_gw, ip_dst):
        ofmsgs = []
        if ip_dst.version == 6:
            routes = vlan.ipv6_routes
            neighbor_cache = vlan.nd_cache
            eth_type = ether.ETH_TYPE_IPV6
            fib_table = self.dp.ipv6_fib_table
        else:
            routes = vlan.ipv4_routes
            neighbor_cache = vlan.arp_cache
            eth_type = ether.ETH_TYPE_IP
            fib_table = self.dp.ipv4_fib_table
        routes[ip_dst] = ip_gw
        if ip_gw in neighbor_cache:
            eth_dst = neighbor_cache[ip_gw].eth_src
            ofmsgs.extend(
                self.add_resolved_route(
                    eth_type=eth_type,
                    fib_table=fib_table,
                    vlan=vlan,
                    neighbor_cache=neighbor_cache,
                    ip_gw=ip_gw,
                    ip_dst=ip_dst,
                    eth_dst=eth_dst,
                    is_updated=False))
        return ofmsgs

    def del_route(self, vlan, ip_dst):
        ofmsgs = []
        if ip_dst.version == 6:
            if ip_dst in vlan.ipv6_routes:
                del vlan.ipv6_routes[ip_dst]
                route_match = self.valve_in_match(
                    self.dp.ipv6_fib_table, vlan=vlan,
                    eth_type=ether.ETH_TYPE_IPV6, nw_dst=ip_dst)
                ofmsgs.extend(self.valve_flowdel(
                    self.dp.ipv6_fib_table, route_match))
        else:
            if ip_dst in vlan.ipv4_routes:
                del vlan.ipv4_routes[ip_dst]
                route_match = self.valve_in_match(
                    self.dp.ipv4_fib_table, vlan=vlan,
                    eth_type=ether.ETH_TYPE_IP, nw_dst=ip_dst)
                ofmsgs.extend(self.valve_flowdel(
                    self.dp.ipv4_fib_table, route_match))
        return ofmsgs

    def add_resolved_route(self, eth_type, fib_table, vlan, neighbor_cache,
                           ip_gw, ip_dst, eth_dst, is_updated=None):
        ofmsgs = []
        if is_updated is not None:
            in_match = self.valve_in_match(
                fib_table, vlan=vlan, eth_type=eth_type, nw_dst=ip_dst)
            prefixlen = ipaddr.IPNetwork(ip_dst).prefixlen
            priority = self.dp.highest_priority + prefixlen
            if is_updated:
                self.logger.info(
                    'Updating next hop for route %s via %s (%s)',
                    ip_dst, ip_gw, eth_dst)
                ofmsgs.extend(self.valve_flowdel(
                    fib_table,
                    in_match,
                    priority=priority))
            else:
                self.logger.info(
                    'Adding new route %s via %s (%s)',
                    ip_dst, ip_gw, eth_dst)

            ofmsgs.append(self.valve_flowmod(
                fib_table,
                in_match,
                priority=priority,
                inst=[valve_of.apply_actions(
                    [valve_of.set_eth_src(self.FAUCET_MAC),
                     valve_of.set_eth_dst(eth_dst),
                     valve_of.dec_ip_ttl()])] +
                [valve_of.goto_table(self.dp.eth_dst_table)]))
        now = time.time()
        link_neighbor = LinkNeighbor(eth_dst, now)
        neighbor_cache[ip_gw] = link_neighbor
        return ofmsgs

    def control_plane_arp_handler(self, in_port, vlan, eth_src, arp_pkt):
        ofmsgs = []

        if arp_pkt.opcode == arp.ARP_REQUEST:
            pkt = self.build_ethernet_pkt(
                eth_src, in_port, vlan, ether.ETH_TYPE_ARP)
            arp_pkt = arp.arp(
                opcode=arp.ARP_REPLY, src_mac=self.FAUCET_MAC,
                src_ip=arp_pkt.dst_ip, dst_mac=eth_src, dst_ip=arp_pkt.src_ip)
            pkt.add_protocol(arp_pkt)
            pkt.serialize()
            ofmsgs.append(valve_of.packetout(in_port, pkt.data))
            self.logger.info(
                'Responded to ARP request for %s from %s',
                arp_pkt.src_ip, arp_pkt.dst_ip)
        elif arp_pkt.opcode == arp.ARP_REPLY:
            resolved_ip_gw = ipaddr.IPv4Address(arp_pkt.src_ip)
            self.logger.info('ARP response %s for %s', eth_src, resolved_ip_gw)
            is_updated = None
            if resolved_ip_gw in vlan.arp_cache:
                cached_eth_dst = vlan.arp_cache[resolved_ip_gw].eth_src
                if cached_eth_dst != eth_src:
                    is_updated = True
            else:
                is_updated = False

            for ip_dst, ip_gw in vlan.ipv4_routes.iteritems():
                if ip_gw == resolved_ip_gw:
                    ofmsgs.extend(
                        self.add_resolved_route(
                            ether.ETH_TYPE_IP, self.dp.ipv4_fib_table,
                            vlan, vlan.arp_cache,
                            ip_gw, ip_dst, eth_src, is_updated))

        return ofmsgs

    def control_plane_icmp_handler(self, in_port, vlan, eth_src,
                                   ipv4_pkt, icmp_pkt):
        ofmsgs = []

        if icmp_pkt is not None:
            pkt = self.build_ethernet_pkt(
                eth_src, in_port, vlan, ether.ETH_TYPE_IP)
            ipv4_pkt = ipv4.ipv4(
                dst=ipv4_pkt.src, src=ipv4_pkt.dst, proto=ipv4_pkt.proto)
            icmp_pkt = icmp.icmp(
                type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE,
                data=icmp_pkt.data)
            pkt.add_protocol(ipv4_pkt)
            pkt.add_protocol(icmp_pkt)
            pkt.serialize()
            ofmsgs.append(valve_of.packetout(in_port, pkt.data))

        return ofmsgs

    def control_plane_icmpv6_handler(self, in_port, vlan, eth_src,
                                     ipv6_pkt, icmpv6_pkt):
        ofmsgs = []
        pkt = self.build_ethernet_pkt(
            eth_src, in_port, vlan, ether.ETH_TYPE_IPV6)

        if icmpv6_pkt.type_ == icmpv6.ND_NEIGHBOR_SOLICIT:
            dst = icmpv6_pkt.data.dst
            ipv6_reply = ipv6.ipv6(
                src=dst,
                dst=ipv6_pkt.src,
                nxt=inet.IPPROTO_ICMPV6,
                hop_limit=ipv6_pkt.hop_limit)
            pkt.add_protocol(ipv6_reply)
            icmpv6_reply = icmpv6.icmpv6(
                type_=icmpv6.ND_NEIGHBOR_ADVERT,
                data=icmpv6.nd_neighbor(
                    dst=dst,
                    option=icmpv6.nd_option_tla(
                        hw_src=self.FAUCET_MAC), res=7))
            pkt.add_protocol(icmpv6_reply)
            pkt.serialize()
            ofmsgs.extend([valve_of.packetout(in_port, pkt.data)])
        elif icmpv6_pkt.type_ == icmpv6.ND_NEIGHBOR_ADVERT:
            resolved_ip_gw = ipaddr.IPv6Address(icmpv6_pkt.data.dst)
            self.logger.info('ND response %s for %s', eth_src, resolved_ip_gw)
            is_updated = None
            if resolved_ip_gw in vlan.nd_cache:
                cached_eth_dst = vlan.nd_cache[resolved_ip_gw].eth_src
                if cached_eth_dst != eth_src:
                    is_updated = True
            else:
                is_updated = False
            for ip_dst, ip_gw in vlan.ipv6_routes.iteritems():
                if ip_gw == resolved_ip_gw:
                    ofmsgs.extend(
                        self.add_resolved_route(
                            ether.ETH_TYPE_IPV6, self.dp.ipv6_fib_table,
                            vlan, vlan.nd_cache,
                            ip_gw, ip_dst, eth_src, is_updated))
        elif icmpv6_pkt.type_ == icmpv6.ICMPV6_ECHO_REQUEST:
            dst = ipv6_pkt.dst
            ipv6_reply = ipv6.ipv6(
                src=dst,
                dst=ipv6_pkt.src,
                nxt=inet.IPPROTO_ICMPV6,
                hop_limit=ipv6_pkt.hop_limit)
            pkt.add_protocol(ipv6_reply)
            icmpv6_reply = icmpv6.icmpv6(
                type_=icmpv6.ICMPV6_ECHO_REPLY,
                data=icmpv6.echo(
                    id_=icmpv6_pkt.data.id,
                    seq=icmpv6_pkt.data.seq,
                    data=icmpv6_pkt.data.data))
            pkt.add_protocol(icmpv6_reply)
            pkt.serialize()
            ofmsgs.extend([valve_of.packetout(in_port, pkt.data)])

        return ofmsgs

    @staticmethod
    def to_faucet_ip(vlan, src_ip, dst_ip):
        for controller_ip in vlan.controller_ips:
            if src_ip in controller_ip or dst_ip in controller_ip:
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
                self.valve_in_match(
                    self.dp.eth_src_table, vlan=vlan, eth_src=eth_src),
                priority=(self.dp.highest_priority - 2)))
        else:
            learn_timeout = self.dp.timeout
            ofmsgs.extend(self.delete_host_from_vlan(eth_src, vlan))

        mirror_acts = []
        if in_port in self.dp.mirror_from_port:
            mirror_port_num = self.dp.mirror_from_port[in_port]
            mirror_acts = [valve_of.output_port(mirror_port_num)]

        # Update datapath to no longer send packets from this mac to controller
        # note the use of hard_timeout here and idle_timeout for the dst table
        # this is to ensure that the source rules will always be deleted before
        # any rules on the dst table. Otherwise if the dst table rule expires
        # but the src table rule is still being hit intermittantly the switch
        # will flood packets to that dst and not realise it needs to relearn
        # the rule
        # NB: Must be lower than highest priority otherwise it can match
        # flows destined to controller
        ofmsgs.append(self.valve_flowmod(
            self.dp.eth_src_table,
            self.valve_in_match(
                self.dp.eth_src_table, in_port=in_port,
                vlan=vlan, eth_src=eth_src),
            priority=(self.dp.highest_priority - 1),
            inst=[valve_of.goto_table(self.dp.eth_dst_table)],
            hard_timeout=learn_timeout))

        # update datapath to output packets to this mac via the associated port
        if vlan.port_is_tagged(in_port):
            dst_act = [valve_of.output_port(in_port)]
        else:
            dst_act = [
                valve_of.pop_vlan(),
                valve_of.output_port(in_port)]
        if mirror_acts:
            dst_act.extend(mirror_acts)
        inst = [valve_of.apply_actions(dst_act)]
        ofmsgs.append(self.valve_flowmod(
            self.dp.eth_dst_table,
            self.valve_in_match(
                self.dp.eth_dst_table, vlan=vlan, eth_dst=eth_src),
            priority=self.dp.high_priority,
            inst=inst,
            idle_timeout=learn_timeout))
        return ofmsgs

    def handle_control_plane(self, in_port, vlan, eth_src, eth_dst, pkt):
        ofmsgs = []
        if eth_dst == self.FAUCET_MAC or not util.mac_addr_is_unicast(eth_dst):
            arp_pkt = pkt.get_protocol(arp.arp)
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            ipv6_pkt = pkt.get_protocol(ipv6.ipv6)

            if arp_pkt is not None:
                src_ip = ipaddr.IPv4Address(arp_pkt.src_ip)
                dst_ip = ipaddr.IPv4Address(arp_pkt.dst_ip)
                if (arp_pkt.opcode == arp.ARP_REQUEST and
                        self.to_faucet_ip(vlan, src_ip, dst_ip)):
                    ofmsgs.extend(self.control_plane_arp_handler(
                        in_port, vlan, eth_src, arp_pkt))
                elif (arp_pkt.opcode == arp.ARP_REPLY and
                      eth_dst == self.FAUCET_MAC):
                    ofmsgs.extend(self.control_plane_arp_handler(
                        in_port, vlan, eth_src, arp_pkt))
            elif ipv4_pkt is not None:
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt is not None:
                    src_ip = ipaddr.IPv4Address(ipv4_pkt.src)
                    dst_ip = ipaddr.IPv4Address(ipv4_pkt.dst)
                    if self.to_faucet_ip(vlan, src_ip, dst_ip):
                        ofmsgs.extend(self.control_plane_icmp_handler(
                            in_port, vlan, eth_src, ipv4_pkt, icmp_pkt))
            elif ipv6_pkt is not None:
                icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
                if icmpv6_pkt is not None:
                    src_ip = ipaddr.IPv6Address(ipv6_pkt.src)
                    dst_ip = ipaddr.IPv6Address(ipv6_pkt.dst)
                    if self.to_faucet_ip(vlan, src_ip, dst_ip):
                        ofmsgs.extend(self.control_plane_icmpv6_handler(
                            in_port, vlan, eth_src, ipv6_pkt, icmpv6_pkt))

        return ofmsgs

    def known_up_dpid_and_port(self, dp_id, in_port):
        if (not self.ignore_dpid(dp_id) and not valve_of.ignore_port(in_port) and
                self.dp.running and in_port in self.dp.ports):
            return True
        return False

    def rcv_packet(self, dp_id, in_port, vlan_vid, pkt):
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
        if not self.known_up_dpid_and_port(dp_id, in_port):
            return []

        ofmsgs = []
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        eth_src = eth_pkt.src
        eth_dst = eth_pkt.dst
        vlan = self.dp.vlans[vlan_vid]
        port = self.dp.ports[in_port]

        if util.mac_addr_is_unicast(eth_src):
            self.logger.debug(
                'Packet_in dp_id: %x src:%s in_port:%d vid:%s',
                dp_id, eth_src, in_port, vlan_vid)

            ofmsgs.extend(self.handle_control_plane(
                in_port, vlan, eth_src, eth_dst, pkt))

        # ban learning new hosts if max_hosts reached on a VLAN.
        if (vlan.max_hosts is not None and
                len(vlan.host_cache) == vlan.max_hosts and
                eth_src not in vlan.host_cache):
            self.logger.info(
                'max hosts %u reached on vlan %u, ' +
                'temporarily banning learning on this vlan, ' +
                'and not learning %s',
                vlan.max_hosts, vlan.vid, eth_src)
            ofmsgs.extend([self.valve_flowdrop(
                self.dp.eth_src_table,
                self.valve_in_match(
                    self.dp.eth_src_table, vlan=vlan),
                priority=(self.dp.low_priority + 1),
                hard_timeout=self.dp.timeout)])
        else:
            ofmsgs.extend(self.learn_host_on_vlan_port(
                port, vlan, eth_src))
            host_cache_entry = HostCacheEntry(
                eth_src,
                port.permanent_learn,
                time.time())
            vlan.host_cache[eth_src] = host_cache_entry
            self.logger.info(
                'learned %u hosts on vlan %u',
                len(vlan.host_cache), vlan.vid)
        return ofmsgs

    def reload_config(self, new_dp):
        """Reload the config from new_dp

        KW Arguments:
        new_dp -- A new DP object containing the updated config."""
        ofmsgs = []
        if self.dp.running:
            self.dp = new_dp
            ofmsgs = self.datapath_connect(
                self.dp.dp_id, self.dp.ports.keys())
        return ofmsgs

    def arp_for_ip_gw(self, ip_gw, controller_ip, vlan, ports):
        ofmsgs = []
        if ports:
            self.logger.info('Resolving %s', ip_gw)
            arp_pkt = arp.arp(
                opcode=arp.ARP_REQUEST, src_mac=self.FAUCET_MAC,
                src_ip=str(controller_ip.ip), dst_mac=mac.DONTCARE_STR,
                dst_ip=str(ip_gw))
            port_num = ports[0].number
            pkt = self.build_ethernet_pkt(
                mac.BROADCAST_STR, port_num, vlan, ether.ETH_TYPE_ARP)
            pkt.add_protocol(arp_pkt)
            pkt.serialize()
            for port in ports:
                ofmsgs.append(valve_of.packetout(port.number, pkt.data))
        return ofmsgs

    def nd_solicit_ip_gw(self, ip_gw, controller_ip, vlan, ports):
        ofmsgs = []
        if ports:
            self.logger.info('Resolving %s', ip_gw)
            nd_mac = util.ipv6_link_eth_mcast(ip_gw)
            ip_gw_mcast = util.ipv6_link_mcast_from_ucast(ip_gw)
            port_num = ports[0].number
            pkt = self.build_ethernet_pkt(
                nd_mac, port_num, vlan, ether.ETH_TYPE_IPV6)
            ipv6_pkt = ipv6.ipv6(
                src=controller_ip.ip, dst=ip_gw_mcast, nxt=inet.IPPROTO_ICMPV6)
            icmpv6_pkt = icmpv6.icmpv6(
                type_=icmpv6.ND_NEIGHBOR_SOLICIT,
                data=icmpv6.nd_neighbor(
                    dst=ip_gw,
                    option=icmpv6.nd_option_sla(hw_src=self.FAUCET_MAC)))
            pkt.add_protocol(ipv6_pkt)
            pkt.add_protocol(icmpv6_pkt)
            pkt.serialize()
            for port in ports:
                ofmsgs.append(valve_of.packetout(port.number, pkt.data))
        return ofmsgs

    def resolve_gateways(self):
        if not self.dp.running:
            return []
        ofmsgs = []
        now = time.time()
        for vlan in self.dp.vlans.itervalues():
            untagged_ports = self.build_flood_ports_for_vlan(
                vlan.untagged, False)
            tagged_ports = self.build_flood_ports_for_vlan(
                vlan.tagged, False)
            for routes, neighbor_cache, neighbor_resolver in (
                    (vlan.ipv4_routes, vlan.arp_cache, self.arp_for_ip_gw),
                    (vlan.ipv6_routes, vlan.nd_cache, self.nd_solicit_ip_gw)):
                for ip_gw in set(routes.values()):
                    for controller_ip in vlan.controller_ips:
                        if ip_gw in controller_ip:
                            cache_age = None
                            if ip_gw in neighbor_cache:
                                cache_time = neighbor_cache[ip_gw].cache_time
                                cache_age = now - cache_time
                            if (cache_age is None or
                                    cache_age > self.dp.arp_neighbor_timeout):
                                for ports in untagged_ports, tagged_ports:
                                    ofmsgs.extend(neighbor_resolver(
                                        ip_gw, controller_ip, vlan, ports))
        return ofmsgs

    def host_expire(self):
        if not self.dp.running:
            return
        now = time.time()
        for vlan in self.dp.vlans.itervalues():
            expired_hosts = []
            for eth_src, host_cache_entry in vlan.host_cache.iteritems():
                if not host_cache_entry.permanent:
                    host_cache_entry_age = now - host_cache_entry.cache_time
                    if host_cache_entry_age > self.dp.timeout:
                        expired_hosts.append(eth_src)
            if expired_hosts:
                for eth_src in expired_hosts:
                    del vlan.host_cache[eth_src]
                    self.logger.info(
                        'expiring host %s from vlan %u',
                        eth_src, vlan.vid)
                self.logger.info(
                    '%u recently active hosts on vlan %u',
                    len(vlan.host_cache), vlan.vid)


class ArubaValve(Valve):

    def switch_features(self, dp_id, msg):
        ryu_table_loader = aruba.LoadRyuTables()
        ryu_table_loader.load_tables(
            os.path.join(aruba.CFG_PATH, 'aruba_pipeline.json'), parser)
        ofmsgs = [valve_of.table_features(ryu_table_loader.ryu_tables)]
        return ofmsgs
