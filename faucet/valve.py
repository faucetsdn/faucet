"""Implementation of Valve learning layer 2/3 switch."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
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
import time
import os

from collections import namedtuple

import aruba.aruba_pipeline as aruba
import valve_acl
import valve_flood
import valve_host
import valve_of
import valve_packet
import valve_route
import valve_util

from ryu.lib import mac
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser


def valve_factory(dp):
    """Return a Valve object based dp's hardware configuration field.

    Arguments:
    dp -- a DP object with the configuration for this valve.
    """
    SUPPORTED_HARDWARE = {
        'Allied-Telesis': Valve,
        'Aruba': ArubaValve,
        'Netronome': Valve,
        'NoviFlow': Valve,
        'Open vSwitch': Valve,
        'ZodiacFX': Valve,
        'Lagopus': Valve,
    }

    if dp.hardware in SUPPORTED_HARDWARE:
        return SUPPORTED_HARDWARE[dp.hardware]
    else:
        return None


class PacketMeta(object):
    """Original, and parsed Ethernet packet metadata."""

    def __init__(self, pkt, eth_pkt, port, vlan, eth_src, eth_dst):
        self.pkt = pkt
        self.eth_pkt = eth_pkt
        self.port = port
        self.vlan = vlan
        self.eth_src = eth_src
        self.eth_dst = eth_dst


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
        self._packet_in_count_sec = 0
        self._last_packet_in_sec = 0
        self._register_table_match_types()
        # TODO: functional flow managers require too much state.
        # Should interface with a common composer class.
        self.ipv4_route_manager = valve_route.ValveIPv4RouteManager(
            self.logger, self.FAUCET_MAC, self.dp.arp_neighbor_timeout,
            self.dp.max_hosts_per_resolve_cycle, self.dp.max_host_fib_retry_count,
            self.dp.max_resolve_backoff_time,
            self.dp.ipv4_fib_table, self.dp.eth_src_table, self.dp.eth_dst_table,
            self.dp.highest_priority,
            self.valve_in_match, self.valve_flowdel, self.valve_flowmod,
            self.valve_flowcontroller,
            self.dp.group_table, self.dp.routers)
        self.ipv6_route_manager = valve_route.ValveIPv6RouteManager(
            self.logger, self.FAUCET_MAC, self.dp.arp_neighbor_timeout,
            self.dp.max_hosts_per_resolve_cycle, self.dp.max_host_fib_retry_count,
            self.dp.max_resolve_backoff_time,
            self.dp.ipv6_fib_table, self.dp.eth_src_table, self.dp.eth_dst_table,
            self.dp.highest_priority,
            self.valve_in_match, self.valve_flowdel, self.valve_flowmod,
            self.valve_flowcontroller,
            self.dp.group_table, self.dp.routers)
        self.flood_manager = valve_flood.ValveFloodManager(
            self.dp.flood_table, self.dp.low_priority,
            self.valve_in_match, self.valve_flowmod,
            self.dp.stack, self.dp.ports, self.dp.shortest_path_to_root,
            self.dp.group_table)
        self.host_manager = valve_host.ValveHostManager(
            self.logger, self.dp.eth_src_table, self.dp.eth_dst_table,
            self.dp.timeout, self.dp.low_priority, self.dp.highest_priority,
            self.valve_in_match, self.valve_flowmod, self.valve_flowdel,
            self.valve_flowdrop,
            not self.dp.flowremoved)

    def _register_table_match_types(self):
        # TODO: functional flow managers should be able to register
        # the flows they need, themselves.
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

    def _in_port_tables(self):
        """Return list of tables that specify in_port as a match."""
        in_port_tables = [self.dp.port_acl_table, self.dp.vlan_acl_table]
        for table_id, match_types in self.TABLE_MATCH_TYPES.items():
            if 'in_port' in match_types:
                in_port_tables.append(table_id)
        return in_port_tables

    def _vlan_match_tables(self):
        """Return list of tables that specify vlan_vid as a match."""
        vlan_match_tables = []
        for table_id, match_types in self.TABLE_MATCH_TYPES.items():
            if 'vlan_vid' in match_types:
                vlan_match_tables.append(table_id)
        return vlan_match_tables

    def switch_features(self, dp_id, msg):
        """Send configuration flows necessary for the switch implementation.

        Arguments:
        dp_id -- the Datapath unique ID (64bit int)
        msg -- OFPSwitchFeatures msg sent from switch.

        Vendor specific configuration should be implemented here.
        """
        return []

    def debug_match_types(self, ofmsg):
        match_oxm_fields = ofmsg.match.to_jsondict()['OFPMatch']['oxm_fields']
        match_types = []
        for field in match_oxm_fields:
            if isinstance(field, dict):
                value = field['OXMTlv']
                mask = value['mask']
                if mask is None:
                    match_types.append(value['field'])
                else:
                    match_types.append(
                        '/'.join((str(value['field']), str(mask))))
            else:
                match_types.append(field)
        return match_types

    def debug_instruction_types(self, ofmsg):
        inst_types = set()
        action_types = set()
        for inst in ofmsg.instructions:
            for inst_name, inst_value in inst.to_jsondict().items():
                if inst_name == 'OFPInstructionActions':
                    for action in inst_value['actions']:
                        for action_name in action:
                            if action_name == 'OFPActionSetField':
                                oxmtlv = action['OFPActionSetField']['field']['OXMTlv']
                                field = oxmtlv['field']
                                mask = oxmtlv['mask']
                                action_type = '_'.join((action_name, field))
                                if mask is not None:
                                    action_type = '/'.join((action_type, mask))
                                action_types.add(action_type)
                            else:
                                action_types.add(action_name)
                else:
                    inst_types.add(inst_name)
        return list(inst_types), list(action_types)

    def ofchannel_log(self, ofmsgs):
        """Log OpenFlow messages in text format to debugging log."""
        if (self.dp is not None and
                self.dp.ofchannel_log is not None):
            if self.ofchannel_logger is None:
                self.ofchannel_logger = valve_util.get_logger(
                    self.dp.ofchannel_log,
                    self.dp.ofchannel_log,
                    logging.DEBUG,
                    0)
            for i, ofmsg in enumerate(ofmsgs, start=1):
                log_prefix = '%u/%u %s' % (
                    i, len(ofmsgs), valve_util.dpid_log(self.dp.dp_id))
                self.ofchannel_logger.debug(
                    '%s %s', log_prefix, ofmsg)
                # TODO: log group operations as well.
                if valve_of.is_flowmod(ofmsg):
                    match_types = self.debug_match_types(ofmsg)
                    inst_types, action_types = self.debug_instruction_types(ofmsg)
                    self.ofchannel_logger.debug(
                        '%s FlowMod types table: %u match: %s instructions: %s actions: %s',
                        log_prefix, ofmsg.table_id,
                        match_types, inst_types, action_types)

    def valve_in_match(self, table_id, in_port=None, vlan=None,
                       eth_type=None, eth_src=None,
                       eth_dst=None, eth_dst_mask=None,
                       ipv6_nd_target=None, icmpv6_type=None,
                       nw_proto=None, nw_src=None, nw_dst=None):
        """Compose an OpenFlow match rule."""
        match_dict = valve_of.build_match_dict(
            in_port, vlan, eth_type, eth_src,
            eth_dst, eth_dst_mask, ipv6_nd_target, icmpv6_type,
            nw_proto, nw_src, nw_dst)
        if table_id != self.dp.port_acl_table\
                and table_id != self.dp.vlan_acl_table:
            assert table_id in self.TABLE_MATCH_TYPES,\
                '%u table not registered' % table_id
            for match_type in match_dict:
                assert match_type in self.TABLE_MATCH_TYPES[table_id],\
                    '%s match not registered for table %u' % (
                        match_type, table_id)
        match = valve_of.match(match_dict)
        return match

    def _ignore_dpid(self, dp_id):
        """Return True if this datapath ID is not ours.

        Args:
            dp_id (int): datapath ID
        Returns:
            bool: True if this datapath ID is not ours.
        """
        if dp_id != self.dp.dp_id:
            self.logger.error('Unknown %s', valve_util.dpid_log(dp_id))
            return True
        return False

    def _all_valve_tables(self):
        """Return all Valve tables.

        Returns:
            tuple: all Valve tables as ints.
        """
        return (
            self.dp.vlan_table,
            self.dp.port_acl_table,
            self.dp.vlan_acl_table,
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
        flags = ofp.OFPFF_SEND_FLOW_REM if self.dp.flowremoved else 0
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
            idle_timeout,
            flags=flags)

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
                out_group=ofp.OFPG_ANY)]

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
        """Add flow outputting to controller."""
        if inst is None:
            inst = []
        return self.valve_flowmod(
            table_id,
            match=match,
            priority=priority,
            inst=[valve_of.apply_actions(
                [valve_of.output_controller()])] + inst)

    def valve_flowreorder(self, input_ofmsgs):
        """Reorder flows for better OFA performance."""
        # Move all deletes to be first, and add one barrier,
        # while preserving order. Platforms that do parallel delete
        # will perform better and platforms that don't will have
        # at most only one barrier to deal with.
        # TODO: further optimizations may be possible - for example,
        # reorder adds to be in priority order.
        delete_ofmsgs = []
        groupadd_ofmsgs = []
        nondelete_ofmsgs = []
        for ofmsg in input_ofmsgs:
            if valve_of.is_flowdel(ofmsg) or valve_of.is_groupdel(ofmsg):
                delete_ofmsgs.append(ofmsg)
            elif valve_of.is_groupadd(ofmsg):
                # The same group_id may be deleted/added multiple times
                # To avoid group_mod_failed/group_exists error, if the
                # same group_id is already in groupadd_ofmsgs I replace
                # it instead of appending it (the last groupadd in
                # input_ofmsgs is the only one sent to the switch)
                # TODO: optimize the provisioning to avoid having the
                # same group_id multiple times in input_ofmsgs
                new_group_id = True
                for idx in xrange(len(groupadd_ofmsgs)):
                    if groupadd_ofmsgs[idx].group_id == ofmsg.group_id:
                        groupadd_ofmsgs[idx] = ofmsg
                        new_group_id = False
                        break
                if new_group_id:
                    groupadd_ofmsgs.append(ofmsg)
            else:
                nondelete_ofmsgs.append(ofmsg)
        output_ofmsgs = []
        if delete_ofmsgs:
            output_ofmsgs.extend(delete_ofmsgs)
            output_ofmsgs.append(valve_of.barrier())
        if groupadd_ofmsgs:
            output_ofmsgs.extend(groupadd_ofmsgs)
            output_ofmsgs.append(valve_of.barrier())
        output_ofmsgs.extend(nondelete_ofmsgs)
        return output_ofmsgs

    def _delete_all_valve_flows(self):
        """Delete all flows from all FAUCET tables."""
        ofmsgs = []
        for table_id in self._all_valve_tables():
            ofmsgs.extend(self.valve_flowdel(table_id))
        if self.dp.group_table:
            ofmsgs.append(valve_of.groupdel())
        return ofmsgs

    def _delete_all_port_match_flows(self, port):
        """Delete all flows that match an input port from all FAUCET tables."""
        ofmsgs = []
        for table_id in self._in_port_tables():
            in_port_match = self.valve_in_match(table_id, in_port=port.number)
            ofmsgs.extend(self.valve_flowdel(table_id, in_port_match))
        return ofmsgs

    def _add_default_drop_flows(self):
        """Add default drop rules on all FAUCET tables."""

        # default drop on all tables.
        ofmsgs = []
        for table in self._all_valve_tables():
            ofmsgs.append(self.valve_flowdrop(
                table,
                priority=self.dp.lowest_priority))

        # drop broadcast sources
        if self.dp.drop_broadcast_source_address:
            ofmsgs.append(self.valve_flowdrop(
                self.dp.vlan_table,
                self.valve_in_match(
                    self.dp.vlan_table, eth_src=mac.BROADCAST_STR),
                priority=self.dp.highest_priority))

        # antispoof for FAUCET's MAC address
        # TODO: antispoof for controller IPs on this VLAN, too.
        if self.dp.drop_spoofed_faucet_mac:
            ofmsgs.append(self.valve_flowdrop(
                self.dp.vlan_table,
                self.valve_in_match(
                    self.dp.vlan_table, eth_src=self.FAUCET_MAC),
                priority=self.dp.high_priority))

        # drop STP BPDU
        # TODO: compatible bridge loop detection/mitigation.
        if self.dp.drop_bpdu:
            for bpdu_mac in ('01:80:C2:00:00:00', '01:00:0C:CC:CC:CD'):
                ofmsgs.append(self.valve_flowdrop(
                    self.dp.vlan_table,
                    self.valve_in_match(
                        self.dp.vlan_table, eth_dst=bpdu_mac),
                    priority=self.dp.highest_priority))

        # drop LLDP, if configured to.
        if self.dp.drop_lldp:
            ofmsgs.append(self.valve_flowdrop(
                self.dp.vlan_table,
                self.valve_in_match(
                    self.dp.vlan_table, eth_type=ether.ETH_TYPE_LLDP),
                priority=self.dp.highest_priority))

        return ofmsgs

    def _add_vlan_acl(self, vid):
        ofmsgs = []
        if vid in self.dp.vlan_acl_in:
            acl_num = self.dp.vlan_acl_in[vid]
            acl_rule_priority = self.dp.highest_priority
            acl_allow_inst = valve_of.goto_table(self.dp.eth_src_table)
            for rule_conf in self.dp.acls[acl_num].rules:
                acl_match, acl_inst = valve_acl.build_acl_entry(
                    rule_conf, acl_allow_inst, vlan_vid=vid)
                ofmsgs.append(self.valve_flowmod(
                    self.dp.vlan_acl_table,
                    acl_match,
                    priority=acl_rule_priority,
                    inst=acl_inst))
                acl_rule_priority -= 1
        return ofmsgs

    def _add_vlan_flood_flow(self):
        """Add a flow to flood packets for unknown destinations."""
        return [self.valve_flowmod(
            self.dp.eth_dst_table,
            priority=self.dp.low_priority,
            inst=[valve_of.goto_table(self.dp.flood_table)])]

    def _add_controller_learn_flow(self):
        """Add a flow for controller to learn/add flows for destinations."""
        return [self.valve_flowcontroller(
            self.dp.eth_src_table,
            priority=self.dp.low_priority,
            inst=[valve_of.goto_table(self.dp.eth_dst_table)])]

    def _add_packetin_meter(self):
        """Add rate limiting of packet in pps (not supported by many DPs)."""
        if self.dp.packetin_pps:
            return [
                valve_of.controller_pps_meterdel(),
                valve_of.controller_pps_meteradd(pps=self.dp.packetin_pps)]
        else:
            return []

    def _add_default_flows(self):
        """Configure datapath with necessary default tables and rules."""
        ofmsgs = []
        ofmsgs.extend(self._add_packetin_meter())
        ofmsgs.extend(self._delete_all_valve_flows())
        ofmsgs.extend(self._add_default_drop_flows())
        ofmsgs.extend(self._add_vlan_flood_flow())
        ofmsgs.extend(self._add_controller_learn_flow())
        return ofmsgs

    def _add_vlan(self, vlan, all_port_nums):
        """Configure a VLAN."""
        ofmsgs = []
        self.logger.info('Configuring VLAN %s', vlan)
        for port in vlan.get_ports():
            all_port_nums.add(port.number)
        # add mirror destination ports.
        for port in vlan.mirror_destination_ports():
            all_port_nums.add(port.number)
        # install eth_dst_table flood ofmsgs
        ofmsgs.extend(self.flood_manager.build_flood_rules(vlan))
        # add acl rules
        ofmsgs.extend(self._add_vlan_acl(vlan.vid))
        # add controller IPs if configured.
        ofmsgs.extend(self._add_faucet_vips(vlan.faucet_vips, vlan))
        return ofmsgs

    def _del_vlan(self, vlan):
        """Delete a configured VLAN."""
        ofmsgs = []
        tables = self._vlan_match_tables()
        tables.remove(self.dp.vlan_table)
        for table_id in tables:
            match = self.valve_in_match(table_id, vlan=vlan)
            ofmsgs.extend(self.valve_flowdel(table_id, match=match))
        self.logger.info('Delete VLAN %s', vlan)
        return ofmsgs

    def _add_ports_and_vlans(self, discovered_port_nums):
        """Add all configured and discovered ports and VLANs."""
        ofmsgs = []
        all_port_nums = set()

        # add stack ports
        for port in self.dp.stack_ports:
            all_port_nums.add(port.number)

        # add vlan ports
        for vlan in self.dp.vlans.values():
            ofmsgs.extend(self._add_vlan(vlan, all_port_nums))

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

    def datapath_connect(self, dp_id, discovered_up_port_nums):
        """Handle Ryu datapath connection event and provision pipeline.

        Args:
            dp_id (int): datapath ID.
            discovered_up_port_nums (list): datapath ports that are up as ints.
        Returns:
            list: OpenFlow messages to send to datapath.
        """
        if self._ignore_dpid(dp_id):
            return []
        self.logger.info('Configuring %s', valve_util.dpid_log(dp_id))
        ofmsgs = []
        ofmsgs.extend(self._add_default_flows())
        changed_ports = set([])
        for port_no in discovered_up_port_nums:
            if valve_of.ignore_port(port_no):
                continue
            changed_ports.add(port_no)
        changed_vlans = self.dp.vlans.keys()
        changes = ([], changed_ports, [], changed_vlans)
        ofmsgs.extend(self._apply_config_changes(self.dp, changes))
        ofmsgs.extend(self._add_ports_and_vlans(discovered_up_port_nums))
        self.dp.running = True
        return ofmsgs

    def datapath_disconnect(self, dp_id):
        """Handle Ryu datapath disconnection event.

        Args:
            dp_id (int): datapath ID.
        """
        if not self._ignore_dpid(dp_id):
            self.dp.running = False
            self.logger.warning('%s down', valve_util.dpid_log(dp_id))

    def _port_add_acl(self, port_num):
        ofmsgs = []
        acl_allow_inst = valve_of.goto_table(self.dp.vlan_table)
        if port_num in self.dp.port_acl_in:
            acl_num = self.dp.port_acl_in[port_num]
            acl_rule_priority = self.dp.highest_priority
            for rule_conf in self.dp.acls[acl_num].rules:
                acl_match, acl_inst = valve_acl.build_acl_entry(
                    rule_conf, acl_allow_inst, port_num)
                ofmsgs.append(self.valve_flowmod(
                    self.dp.port_acl_table,
                    acl_match,
                    priority=acl_rule_priority,
                    inst=acl_inst))
                acl_rule_priority -= 1
        else:
            ofmsgs.append(self.valve_flowmod(
                self.dp.port_acl_table,
                self.valve_in_match(self.dp.port_acl_table, in_port=port_num),
                priority=self.dp.highest_priority,
                inst=[acl_allow_inst]
                ))
        return ofmsgs

    def _port_add_vlan_rules(self, port, vlan_vid, vlan_inst):
        ofmsgs = []
        ofmsgs.append(self.valve_flowmod(
            self.dp.vlan_table,
            self.valve_in_match(
                self.dp.vlan_table, in_port=port.number, vlan=vlan_vid),
            priority=self.dp.low_priority,
            inst=vlan_inst))
        return ofmsgs

    def _port_add_vlan_untagged(self, port, vlan, forwarding_table, mirror_act):
        push_vlan_act = mirror_act + valve_of.push_vlan_act(vlan.vid)
        push_vlan_inst = [
            valve_of.apply_actions(push_vlan_act),
            valve_of.goto_table(forwarding_table)
        ]
        null_vlan = namedtuple('null_vlan', 'vid')
        null_vlan.vid = ofp.OFPVID_NONE
        return self._port_add_vlan_rules(port, null_vlan, push_vlan_inst)

    def _port_add_vlan_tagged(self, port, vlan, forwarding_table, mirror_act):
        vlan_inst = [
            valve_of.goto_table(forwarding_table)
        ]
        if mirror_act:
            vlan_inst = [valve_of.apply_actions(mirror_act)] + vlan_inst
        return self._port_add_vlan_rules(port, vlan, vlan_inst)

    def _find_forwarding_table(self, vlan):
        if vlan.vid in self.dp.vlan_acl_in:
            return self.dp.vlan_acl_table
        else:
            return self.dp.eth_src_table

    def _port_add_vlans(self, port, mirror_act):
        ofmsgs = []
        vlans = self.dp.vlans.values()
        tagged_vlans_with_port = [
            vlan for vlan in vlans if port in vlan.tagged]
        untagged_vlans_with_port = [
            vlan for vlan in vlans if port in vlan.untagged]
        for vlan in tagged_vlans_with_port:
            ofmsgs.extend(self.flood_manager.build_flood_rules(vlan))
            ofmsgs.extend(self._port_add_vlan_tagged(
                port, vlan, self._find_forwarding_table(vlan), mirror_act))
        for vlan in untagged_vlans_with_port:
            ofmsgs.extend(self.flood_manager.build_flood_rules(vlan))
            ofmsgs.extend(self._port_add_vlan_untagged(
                port, vlan, self._find_forwarding_table(vlan), mirror_act))
        return ofmsgs

    def port_add(self, dp_id, port_num, modify=False):
        """Handle the addition of a port.

        Args:
            dp_id (int): datapath ID.
            port_num (int): port number.
        Returns:
            list: OpenFlow messages, if any.
        """
        if self._ignore_dpid(dp_id) or valve_of.ignore_port(port_num):
            return []

        if port_num not in self.dp.ports:
            self.logger.info(
                'Ignoring port:%u not present in configuration file', port_num)
            return []

        port = self.dp.ports[port_num]
        port.phys_up = True

        ofmsgs = []
        if modify:
            if not port.permanent_learn:
                # delete eth_dst rules
                ofmsgs.extend(self.valve_flowdel(
                    self.dp.eth_dst_table,
                    out_port=port_num))
            self.logger.info('Port %s modified', port)
        else:
            self.logger.info('Port %s added', port)

        if not port.running():
            return ofmsgs

        self.logger.info('Sending config for port %s', port)

        # Delete all flows previously matching this port
        ofmsgs.extend(self._delete_all_port_match_flows(port))

        # Port is a mirror destination; drop all input packets
        if port.mirror_destination:
            ofmsgs.append(self.valve_flowdrop(
                self.dp.vlan_table,
                match=self.valve_in_match(self.dp.vlan_table, in_port=port_num),
                priority=self.dp.highest_priority))
            return ofmsgs

        # Add ACL if any.
        acl_ofmsgs = self._port_add_acl(port_num)
        ofmsgs.extend(acl_ofmsgs)

        # If this is a stacking port, accept all VLANs (came from another FAUCET)
        if port.stack is not None:
            ofmsgs.append(self.valve_flowmod(
                self.dp.vlan_table,
                match=self.valve_in_match(self.dp.vlan_table, in_port=port_num),
                priority=self.dp.low_priority,
                inst=[valve_of.goto_table(self.dp.eth_src_table)]))
            for vlan in self.dp.vlans.values():
                ofmsgs.extend(self.flood_manager.build_flood_rules(vlan))
        else:
            mirror_act = []
            # Add mirroring if any
            if port.mirror:
                mirror_act = [valve_of.output_port(port.mirror)]
            # Add port/to VLAN rules.
            ofmsgs.extend(self._port_add_vlans(port, mirror_act))
        return ofmsgs

    def port_delete(self, dp_id, port_num):
        """Handle the deletion of a port.

        Args:
            dp_id (int): datapath ID.
            port_num (int): port number.
        Returns:
            list: OpenFlow messages, if any.
        """
        if self._ignore_dpid(dp_id) or valve_of.ignore_port(port_num):
            return []

        if port_num not in self.dp.ports:
            return []

        port = self.dp.ports[port_num]
        port.phys_up = False

        self.logger.warning('Port %s down', port)

        ofmsgs = []

        if not port.permanent_learn:
            ofmsgs.extend(self._delete_all_port_match_flows(port))

            # delete eth_dst rules
            ofmsgs.extend(self.valve_flowdel(
                self.dp.eth_dst_table,
                out_port=port_num))

        for vlan in self.dp.vlans.values():
            if port in vlan.get_ports():
                ofmsgs.extend(self.flood_manager.build_flood_rules(
                    vlan, modify=True))

            self.host_manager.expire_hosts_on_port(port_num, vlan)

        return ofmsgs

    def control_plane_handler(self, pkt_meta):
        """Handle a packet probably destined to FAUCET's route managers.

        For example, next hop resolution or ICMP echo requests.

        Args:
            pkt_meta (PacketMeta): packet for control plane.
        Returns:
            list: OpenFlow messages, if any.
        """
        if (pkt_meta.eth_dst == self.FAUCET_MAC or
                not valve_packet.mac_addr_is_unicast(pkt_meta.eth_dst)):
            for handler in (self.ipv4_route_manager.control_plane_handler,
                            self.ipv6_route_manager.control_plane_handler):
                ofmsgs = handler(pkt_meta)
                if ofmsgs:
                    return ofmsgs
        return []

    def _known_up_dpid_and_port(self, dp_id, in_port):
        """Returns True if datapath and port are known and running.

        Args:
            dp_id (int): datapath ID.
            in_port (int): port number.
        Returns:
            bool: True if datapath and port are known and running.
        """
        if (not self._ignore_dpid(dp_id) and not valve_of.ignore_port(in_port) and
                self.dp.running and in_port in self.dp.ports):
            return True
        return False

    def _rate_limit_packet_ins(self):
        """Return True if too many packet ins this second."""
        now_sec = int(time.time())
        if self._last_packet_in_sec != now_sec:
            self._last_packet_in_sec = now_sec
            self._packet_in_count_sec = 0
        self._packet_in_count_sec += 1
        if self.dp.ignore_learn_ins:
            if self._packet_in_count_sec % self.dp.ignore_learn_ins == 0:
                return True
        return False

    def _edge_dp_for_host(self, valves, dp_id, pkt_meta):
        """Simple distributed unicast learning.

        Args:
            valves (list): of all Valves (datapaths).
            dp_id (int): DPID of datapath packet received on.
            pkt_meta (PacketMeta): PacketMeta instance for packet received.
        Returns:
            Valve instance or None (of edge datapath where packet received)
        """
        # TODO: simplest possible unicast learning.
        # We find just one port that is the shortest unicast path to
        # the destination. We could use other factors (eg we could
        # load balance over multiple ports based on destination MAC).
        # TODO: each DP learns independently. An edge DP could
        # call other valves so they learn immediately without waiting
        # for packet in.
        # TODO: edge DPs could use a different forwarding algorithm
        # (for example, just default switch to a neighbor).
        # Find port that forwards closer to destination DP that
        # has already learned this host (if any).
        eth_src = pkt_meta.eth_src
        vlan_vid = pkt_meta.vlan.vid
        for other_dpid, other_valve in valves.items():
            if other_dpid == dp_id:
                continue
            other_dp = other_valve.dp
            other_dp_host_cache = other_dp.vlans[vlan_vid].host_cache
            if eth_src in other_dp_host_cache:
                host = other_dp_host_cache[eth_src]
                if host.edge:
                    return other_dp
        return None

    def _learn_host(self, valves, dp_id, pkt_meta):
        """Possibly learn a host on a port.

        Args:
            dp_id (int): DPID of datapath packet received on.
            valves (list): of all Valves (datapaths).
            pkt_meta (PacketMeta): PacketMeta instance for packet received.
        Returns:
            list: OpenFlow messages, if any.
        """
        learn_port = pkt_meta.port
        ofmsgs = []

        if learn_port.stack is not None:
            edge_dp = self._edge_dp_for_host(valves, dp_id, pkt_meta)
            # No edge DP may have learned this host yet.
            if edge_dp is None:
                return ofmsgs

            learn_port = self.dp.shortest_path_port(edge_dp.name)
            self.logger.info(
                'host learned via stack port to %s', edge_dp.name)

        # TODO: it would be good to be able to notify an external
        # system upon re/learning a host.
        ofmsgs.extend(self.host_manager.learn_host_on_vlan_port(
            learn_port, pkt_meta.vlan, pkt_meta.eth_src))

        # Add FIB entries, if routing is active.
        for route_manager in (
                self.ipv4_route_manager, self.ipv6_route_manager):
            if route_manager:
                ofmsgs.extend(
                    route_manager.add_host_fib_route_from_pkt(pkt_meta))

        return ofmsgs

    def _parse_rcv_packet(self, in_port, vlan_vid, pkt):
        """Parse a received packet into a PacketMeta instance.

        Args:
            in_port (int): port packet was received on.
            vlan_vid (int): VLAN VID of port packet was received on.
            pkt (ryu.lib.packet.packet): packet received.
        Returns:
            PacketMeta instance.
        """
        eth_pkt = valve_packet.parse_pkt(pkt)
        eth_src = eth_pkt.src
        eth_dst = eth_pkt.dst
        vlan = self.dp.vlans[vlan_vid]
        port = self.dp.ports[in_port]
        return PacketMeta(pkt, eth_pkt, port, vlan, eth_src, eth_dst)

    def _vlan_learn_ban_rules(self, pkt_meta):
        """Limit learning to a maximum configured on this VLAN.

        Args:
            pkt_meta: PacketMeta instance.
        Returns:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []
        vlan = pkt_meta.vlan
        eth_src = pkt_meta.eth_src
        if (vlan.max_hosts is not None and
                len(vlan.host_cache) == vlan.max_hosts and
                eth_src not in vlan.host_cache):
            ofmsgs.append(self.host_manager.temp_ban_host_learning_on_vlan(
                vlan))
            self.logger.info(
                'max hosts %u reached on vlan %u, ' +
                'temporarily banning learning on this vlan, ' +
                'and not learning %s',
                vlan.max_hosts, vlan.vid, eth_src)
        return ofmsgs

    def rcv_packet(self, dp_id, valves, in_port, vlan_vid, pkt):
        """Handle a packet from the dataplane (eg to re/learn a host).

        The packet may be sent to us also in response to FAUCET
        initiating IPv6 neighbor discovery, or ARP, to resolve
        a nexthop.

        Args:
            dp_id (int): datapath ID.
            valves (dict): all datapaths, indexed by datapath ID.
            in_port (int): port packet was received on.
            vlan_vid (int): VLAN VID of port packet was received on.
            pkt (ryu.lib.packet.packet): packet received.
        Return:
            list: OpenFlow messages, if any.
        """
        if not self._known_up_dpid_and_port(dp_id, in_port):
            return []

        pkt_meta = self._parse_rcv_packet(in_port, vlan_vid, pkt)
        ofmsgs = []

        if valve_packet.mac_addr_is_unicast(pkt_meta.eth_src):
            self.logger.debug(
                'Packet_in %s src:%s in_port:%d vid:%s',
                valve_util.dpid_log(dp_id),
                pkt_meta.eth_src,
                pkt_meta.port.number,
                pkt_meta.vlan.vid)

            ofmsgs.extend(self.control_plane_handler(pkt_meta))

        if self._rate_limit_packet_ins():
            return ofmsgs

        ban_vlan_rules = self._vlan_learn_ban_rules(pkt_meta)
        if ban_vlan_rules:
            ofmsgs.extend(ban_vlan_rules)
            return ofmsgs

        ofmsgs.extend(self._learn_host(valves, dp_id, pkt_meta))
        return ofmsgs

    def rcv_rule_timeout(self, table_id, match):
        in_port = None
        eth_src = None
        vlan_vid = None
        match_oxm_fields = match.to_jsondict()['OFPMatch']['oxm_fields']
        if table_id == self.dp.eth_src_table:
            for field in match_oxm_fields:
                if isinstance(field, dict):
                    value = field['OXMTlv']
                    if value['field'] == 'eth_src':
                        eth_src = value['value']
                    elif value['field'] == 'vlan_vid':
                        vlan_vid = value['value'] & ~ofp.OFPVID_PRESENT
                    elif value['field'] == 'in_port':
                        in_port = value['value']
            if eth_src and vlan_vid and in_port:
                self.logger.info('host %s on vlan %u, in_port %d has expired',
                        eth_src, vlan_vid, in_port)
                vlan = self.dp.vlans[vlan_vid]
                self.host_manager.host_mark_src_rule_expired(in_port, vlan, eth_src)

    def host_expire(self):
        """Expire hosts not recently re/learned.

        Expire state from the host manager only; the switch does its own flow
        expiry.
        """
        ofmsgs = []
        if not self.dp.running:
            return
        now = time.time()
        for vlan in self.dp.vlans.values():
            ofmsgs.extend(self.host_manager.expire_hosts_from_vlan(vlan, now))

        return ofmsgs

    def _get_config_changes(self, new_dp):
        """Detect any config changes.

        Args:
            new_dp (DP): new dataplane configuration.
        Returns:
            changes (tuple) of:
                deleted_ports (set): deleted port numbers.
                changed_ports (set): changed/added port numbers.
                deleted_vlans (set): deleted VLAN IDs.
                changed_vlans (set): changed/added VLAN IDs.
        """
        changed_acls = {}
        for acl_id, new_acl in new_dp.acls.items():
            if acl_id not in self.dp.acls:
                changed_acls[acl_id] = new_acl
            else:
                if new_acl != self.dp.acls[acl_id]:
                    changed_acls[acl_id] = new_acl

        changed_ports = set([])
        for port_no, new_port in new_dp.ports.items():
            if port_no not in self.dp.ports:
                # Detected a newly configured port
                changed_ports.add(port_no)
            else:
                if new_port != self.dp.ports[port_no]:
                    # An existing port has configs changed
                    changed_ports.add(port_no)
                elif new_port.acl_in in changed_acls:
                    # If the port has its ACL changed
                    changed_ports.add(port_no)

        deleted_vlans = set([])
        for vid in self.dp.vlans.keys():
            if vid not in new_dp.vlans:
                deleted_vlans.add(vid)

        changed_vlans = set([])
        for vid, new_vlan in new_dp.vlans.items():
            if vid not in self.dp.vlans or new_vlan != self.dp.vlans[vid]:
                changed_vlans.add(vid)
            for port in new_vlan.get_ports():
                changed_ports.add(port.number)

        deleted_ports = set([])
        for port_no in self.dp.ports.keys():
            if port_no not in new_dp.ports:
                deleted_ports.add(port_no)

        changes = (deleted_ports, changed_ports, deleted_vlans, changed_vlans)
        return changes

    def _apply_config_changes(self, new_dp, changes):
        """Apply any detected configuration changes.

        Args:
            new_dp: (DP): new dataplane configuration.
            changes (tuple) of:
                deleted_ports (list): deleted port numbers.
                changed_ports (list): changed/added port numbers.
                deleted_vlans (list): deleted VLAN IDs.
                changed_vlans (list): changed/added VLAN IDs.
        Returns:
            ofmsgs (list): OpenFlow messages.
        """
        deleted_ports, changed_ports, deleted_vlans, changed_vlans = changes
        ofmsgs = []
        for port_no in deleted_ports:
            self.logger.info('ports deleted: %s', deleted_ports)
            ofmsgs.extend(self.port_delete(self.dp.dp_id, port_no))
        for vid in deleted_vlans:
            self.logger.info('VLANs deleted: %s', deleted_vlans)
            vlan = self.dp.vlans[vid]
            ofmsgs.extend(self._del_vlan(vlan))
        for vid in changed_vlans:
            vlan = self.dp.vlans[vid]
            ofmsgs.extend(self._del_vlan(vlan))

        self.dp = new_dp
        self.dp.running = True

        for vid in changed_vlans:
            self.logger.info('VLANs changed/added: %s', changed_vlans)
            vlan = self.dp.vlans[vid]
            ofmsgs.extend(self._add_vlan(vlan, set()))
        for port_no in changed_ports:
            self.logger.info('ports changed/added: %s', changed_ports)
            ofmsgs.extend(self.port_add(self.dp.dp_id, port_no, True))
        return ofmsgs

    def reload_config(self, new_dp):
        """Reload configuration new_dp.

        Following config changes are currently supported:
            - Port config: support all available configs (e.g. native_vlan, acl_in)
                & change operations (add, delete, modify) a port
            - ACL config:support any modification, currently reload all rules
                belonging to an ACL
            - VLAN config: enable, disable routing, etc...

        Args:
            new_dp (DP): new dataplane configuration.
        Returns:
            list: OpenFlow messages.
        """
        if self.dp.running:
            return self._apply_config_changes(
                new_dp,
                self._get_config_changes(new_dp))
        else:
            return []

    def _add_faucet_vips(self, faucet_vips, vlan):
        ofmsgs = []
        for faucet_vip in faucet_vips:
            assert self.dp.stack is None, 'stacking + routing not yet supported'
            if faucet_vip.version == 6:
                ofmsgs.extend(self.ipv6_route_manager.add_faucet_vip(
                    vlan, faucet_vip))
            elif faucet_vip.version == 4:
                ofmsgs.extend(self.ipv4_route_manager.add_faucet_vip(
                    vlan, faucet_vip))
        return ofmsgs

    def add_route(self, vlan, ip_gw, ip_dst):
        """Add route to VLAN routing table."""
        if ip_dst.version == 6:
            return self.ipv6_route_manager.add_route(vlan, ip_gw, ip_dst)
        else:
            return self.ipv4_route_manager.add_route(vlan, ip_gw, ip_dst)

    def del_route(self, vlan, ip_dst):
        """Delete route from VLAN routing table."""
        if ip_dst.version == 6:
            return self.ipv6_route_manager.del_route(vlan, ip_dst)
        else:
            return self.ipv4_route_manager.del_route(vlan, ip_dst)

    def resolve_gateways(self):
        """Call route managers to re/resolve gateways.

        Returns:
            list: OpenFlow messages, if any.
        """
        if not self.dp.running:
            return []
        ofmsgs = []
        now = time.time()
        for vlan in self.dp.vlans.values():
            ofmsgs.extend(self.ipv4_route_manager.resolve_gateways(vlan, now))
            ofmsgs.extend(self.ipv6_route_manager.resolve_gateways(vlan, now))
        return ofmsgs

    def get_config_dict(self):
        """Render configuration as a dict, suitable for returning via API call.

        Returns:
            dict: current configuration.
        """
        dps_dict = {
            self.dp.name: self.dp.to_conf()
            }
        vlans_dict = {}
        for vlan in self.dp.vlans.values():
            vlans_dict[vlan.name] = vlan.to_conf()
        acls_dict = {}
        for acl_id, acl in self.dp.acls.items():
            acls_dict[acl_id] = acl.to_conf()
        return {
            'dps': dps_dict,
            'vlans': vlans_dict,
            'acls': acls_dict,
            }


class ArubaValve(Valve):
    """Valve implementation that uses OpenFlow send table features messages."""

    def switch_features(self, dp_id, msg):
        ryu_table_loader = aruba.LoadRyuTables()
        ryu_table_loader.load_tables(
            os.path.join(aruba.CFG_PATH, 'aruba_pipeline.json'), parser)
        ofmsgs = [valve_of.table_features(ryu_table_loader.ryu_tables)]
        return ofmsgs
