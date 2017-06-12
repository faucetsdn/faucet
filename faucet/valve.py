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

import copy
import logging
import time

from collections import namedtuple

import tfm_pipeline
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


def valve_factory(dp):
    """Return a Valve object based dp's hardware configuration field.

    Args:
        dp (DP): DP instance with the configuration for this Valve.
    """
    SUPPORTED_HARDWARE = {
        'Allied-Telesis': Valve,
        'Aruba': ArubaValve,
        'GenericTFM': TfmValve,
        'Lagopus': Valve,
        'Netronome': Valve,
        'NoviFlow': Valve,
        'Open vSwitch': Valve,
        'ZodiacFX': Valve,
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
        self._last_advertise_sec = 0
        self._register_table_match_types()
        # TODO: functional flow managers require too much state.
        # Should interface with a common composer class.
        self.ipv4_route_manager = valve_route.ValveIPv4RouteManager(
            self.logger, self.FAUCET_MAC, self.dp.arp_neighbor_timeout,
            self.dp.max_hosts_per_resolve_cycle, self.dp.max_host_fib_retry_count,
            self.dp.max_resolve_backoff_time, self.dp.proactive_learn,
            self.dp.ipv4_fib_table, self.dp.eth_src_table,
            self.dp.eth_dst_table, self.dp.flood_table,
            self.dp.highest_priority,
            self.valve_in_match, self.valve_flowdel, self.valve_flowmod,
            self.valve_flowcontroller,
            self.dp.group_table, self.dp.routers)
        self.ipv6_route_manager = valve_route.ValveIPv6RouteManager(
            self.logger, self.FAUCET_MAC, self.dp.arp_neighbor_timeout,
            self.dp.max_hosts_per_resolve_cycle, self.dp.max_host_fib_retry_count,
            self.dp.max_resolve_backoff_time, self.dp.proactive_learn,
            self.dp.ipv6_fib_table, self.dp.eth_src_table,
            self.dp.eth_dst_table, self.dp.flood_table,
            self.dp.highest_priority,
            self.valve_in_match, self.valve_flowdel, self.valve_flowmod,
            self.valve_flowcontroller,
            self.dp.group_table, self.dp.routers)
        self.route_manager_by_ipv = {}
        for route_manager in (self.ipv4_route_manager, self.ipv6_route_manager):
            self.route_manager_by_ipv[route_manager.IPV] = route_manager
        self.flood_manager = valve_flood.ValveFloodManager(
            self.dp.flood_table, self.dp.low_priority,
            self.valve_in_match, self.valve_flowmod,
            self.dp.stack, self.dp.ports, self.dp.shortest_path_to_root,
            self.dp.group_table)
        self.host_manager = valve_host.ValveHostManager(
            self.logger, self.dp.eth_src_table, self.dp.eth_dst_table,
            self.dp.timeout, self.dp.learn_jitter, self.dp.learn_ban_timeout,
            self.dp.low_priority, self.dp.highest_priority,
            self.valve_in_match, self.valve_flowmod, self.valve_flowdel,
            self.valve_flowdrop)

    def dpid_log(self, log_msg):
        self.logger.info(
            ' '.join((valve_util.dpid_log(self.dp.dp_id), log_msg)))

    def dpid_warn(self, log_msg):
        self.logger.warning(
            ' '.join((valve_util.dpid_log(self.dp.dp_id), log_msg)))

    def _register_table_match_types(self):
        # TODO: functional flow managers should be able to register
        # the flows they need, themselves.
        self.TABLE_MATCH_TYPES = {
            self.dp.vlan_table: (
                'in_port', 'vlan_vid', 'eth_src', 'eth_dst', 'eth_type'),
            self.dp.eth_src_table: (
                'in_port', 'vlan_vid', 'eth_src', 'eth_dst', 'eth_type',
                'ip_proto', 'icmpv6_type', 'arp_tpa', 'ipv4_src'),
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
        for table_id, match_types in list(self.TABLE_MATCH_TYPES.items()):
            if 'in_port' in match_types:
                in_port_tables.append(table_id)
        return in_port_tables

    def _vlan_match_tables(self):
        """Return list of tables that specify vlan_vid as a match."""
        vlan_match_tables = []
        for table_id, match_types in list(self.TABLE_MATCH_TYPES.items()):
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

    def _debug_match_types(self, ofmsg):
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

    def _debug_action_types(self, actions, action_types):
        for action in actions:
            for action_name in actions:
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

    def _debug_instruction_types(self, ofmsg):
        inst_types = set()
        action_types = set()
        for inst in ofmsg.instructions:
            for inst_name, inst_value in list(inst.to_jsondict().items()):
                if inst_name == 'OFPInstructionActions':
                    self._debug_action_types(
                        inst_value['actions'], action_types)
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
                    match_types = self._debug_match_types(ofmsg)
                    inst_types, action_types = self._debug_instruction_types(ofmsg)
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
                      out_port=ofp.OFPP_ANY, strict=False):
        """Delete matching flows from a table."""
        command = ofp.OFPFC_DELETE
        if strict:
            command = ofp.OFPFC_DELETE_STRICT
        return [
            self.valve_flowmod(
                table_id,
                match=match,
                priority=priority,
                command=command,
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
                             inst=None, max_len=96):
        """Add flow outputting to controller."""
        if inst is None:
            inst = []
        return self.valve_flowmod(
            table_id,
            match=match,
            priority=priority,
            inst=[valve_of.apply_actions(
                [valve_of.output_controller(max_len)])] + inst)

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
                for i, groupadd_ofmsg in enumerate(groupadd_ofmsgs):
                    if groupadd_ofmsg.group_id == ofmsg.group_id:
                        groupadd_ofmsgs[i] = ofmsg
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
        return ofmsgs

    def _add_vlan(self, vlan, all_port_nums):
        """Configure a VLAN."""
        ofmsgs = []
        self.dpid_log('Configuring VLAN %s' % vlan)
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
        for ipv in vlan.ipvs():
            route_manager = self.route_manager_by_ipv[ipv]
            ofmsgs.extend(self._add_faucet_vips(
                route_manager, vlan, vlan.faucet_vips_by_ipv(ipv)))
        return ofmsgs

    def _del_vlan(self, vlan):
        """Delete a configured VLAN."""
        ofmsgs = []
        tables = self._vlan_match_tables()
        tables.remove(self.dp.vlan_table)
        for table_id in tables:
            match = self.valve_in_match(table_id, vlan=vlan)
            ofmsgs.extend(self.valve_flowdel(table_id, match=match))
        self.dpid_log('Delete VLAN %s' % vlan)
        return ofmsgs

    def _add_ports_and_vlans(self, discovered_port_nums):
        """Add all configured and discovered ports and VLANs."""
        ofmsgs = []
        all_port_nums = set()

        # add stack ports
        for port in self.dp.stack_ports:
            all_port_nums.add(port.number)

        # add vlan ports
        for vlan in list(self.dp.vlans.values()):
            ofmsgs.extend(self._add_vlan(vlan, all_port_nums))

        # add any ports discovered but not configured
        for port_num in discovered_port_nums:
            if valve_of.ignore_port(port_num):
                continue
            if port_num not in all_port_nums:
                all_port_nums.add(port_num)

        # now configure all ports
        ofmsgs.extend(self.ports_add(
            self.dp.dp_id, all_port_nums, cold_start=True))

        return ofmsgs

    def port_status_handler(self, dp_id, port_no, reason, port_status):
        if reason == ofp.OFPPR_ADD:
            return self.port_add(dp_id, port_no)
        elif reason == ofp.OFPPR_DELETE:
            return self.port_delete(dp_id, port_no)
        elif reason == ofp.OFPPR_MODIFY:
            ofmsgs = []
            ofmsgs.extend(self.port_delete(dp_id, port_no))
            if port_status:
                ofmsgs.extend(self.port_add(dp_id, port_no))
            return ofmsgs
        self.dpid_warn('Unhandled port status %s for port %u' % (
            reason, port_no))
        return []

    def advertise(self):
        """Called periodically to advertise services (eg. IPv6 RAs)."""
        ofmsgs = []
        now = time.time()
        if (self.dp.advertise_interval and
                now - self._last_advertise_sec > self.dp.advertise_interval):
            for vlan in list(self.dp.vlans.values()):
                ofmsgs.extend(
                    self.ipv6_route_manager.advertise(vlan))
            self._last_advertise_sec = now
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
        self.dpid_log('Cold start configuring DP')
        ofmsgs = []
        ofmsgs.extend(self._add_default_flows())
        ofmsgs.extend(self._add_ports_and_vlans(discovered_up_port_nums))
        ofmsgs.extend(self._add_controller_learn_flow())
        self.dp.running = True
        return ofmsgs

    def datapath_disconnect(self, dp_id):
        """Handle Ryu datapath disconnection event.

        Args:
            dp_id (int): datapath ID.
        """
        if not self._ignore_dpid(dp_id):
            self.dp.running = False
            self.dpid_warn('datapath down')

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

    def _port_add_vlans(self, port, mirror_act,
                        tagged_vlans_with_port, untagged_vlans_with_port):
        ofmsgs = []
        for vlan in tagged_vlans_with_port:
            ofmsgs.extend(self._port_add_vlan_tagged(
                port, vlan, self._find_forwarding_table(vlan), mirror_act))
        for vlan in untagged_vlans_with_port:
            ofmsgs.extend(self._port_add_vlan_untagged(
                port, vlan, self._find_forwarding_table(vlan), mirror_act))
        return ofmsgs

    def _port_delete_flows(self, port, old_eth_srcs):
        ofmsgs = []
        ofmsgs.extend(self._delete_all_port_match_flows(port))
        ofmsgs.extend(self.valve_flowdel(
            self.dp.eth_dst_table, out_port=port.number))
        if port.permanent_learn:
            for eth_src in old_eth_srcs:
                ofmsgs.extend(self.valve_flowdel(
                    self.dp.eth_src_table,
                    match=self.valve_in_match(
                        self.dp.eth_src_table, eth_src=eth_src)))
        return ofmsgs

    def ports_add(self, dp_id, port_nums, cold_start=False):
        """Handle the addition of ports.

        Args:
            dp_id (int): datapath ID.
            port_num (list): list of port numbers.
            cold_start (bool): True if configuring datapath from scratch.
        Returns:
            list: OpenFlow messages, if any.
        """
        if self._ignore_dpid(dp_id):
            return []

        ofmsgs = []
        vlans_with_ports_added = set()

        for port_num in port_nums:
            if valve_of.ignore_port(port_num):
                continue
            if port_num not in self.dp.ports:
                self.dpid_log(
                    'Ignoring port:%u not present in configuration file' % port_num)
                continue

            port = self.dp.ports[port_num]
            port.phys_up = True
            self.dpid_log('Sending config for port %s' % port)

            if not port.running():
                continue

            # Port is a mirror destination; drop all input packets
            if port.mirror_destination:
                ofmsgs.append(self.valve_flowdrop(
                    self.dp.vlan_table,
                    match=self.valve_in_match(self.dp.vlan_table, in_port=port_num),
                    priority=self.dp.highest_priority))
                continue

            # Add ACL if any.
            acl_ofmsgs = self._port_add_acl(port_num)
            ofmsgs.extend(acl_ofmsgs)

            tagged_vlans_with_port = port.tagged_vlans
            untagged_vlans_with_port = [
                vlan for vlan in [port.native_vlan] if vlan is not None]
            port_vlans = tagged_vlans_with_port + untagged_vlans_with_port

            # If this is a stacking port, accept all VLANs (came from another FAUCET)
            if port.stack is not None:
                ofmsgs.append(self.valve_flowmod(
                    self.dp.vlan_table,
                    match=self.valve_in_match(self.dp.vlan_table, in_port=port_num),
                    priority=self.dp.low_priority,
                    inst=[valve_of.goto_table(self.dp.eth_src_table)]))
                port_vlans = list(self.dp.vlans.values())
            else:
                mirror_act = []
                # Add mirroring if any
                if port.mirror:
                    mirror_act = [valve_of.output_port(port.mirror)]
                # Add port/to VLAN rules.
                ofmsgs.extend(self._port_add_vlans(
                    port, mirror_act, tagged_vlans_with_port, untagged_vlans_with_port))

            for vlan in port_vlans:
                vlans_with_ports_added.add(vlan)

        # Only update flooding rules if not cold starting.
        if not cold_start:
            for vlan in vlans_with_ports_added:
                ofmsgs.extend(self.flood_manager.build_flood_rules(vlan))

        return ofmsgs

    def port_add(self, dp_id, port_num):
        return self.ports_add(dp_id, [port_num])

    def ports_delete(self, dp_id, port_nums):
        """Handle the deletion of ports.

        Args:
            dp_id (int): datapath ID.
            port_nums (list): list of port numbers.
        Returns:
            list: OpenFlow messages, if any.
        """
        if self._ignore_dpid(dp_id):
            return []

        ofmsgs = []
        vlans_with_deleted_ports = set()

        for port_num in port_nums:
            if valve_of.ignore_port(port_num):
                continue
            if port_num not in self.dp.ports:
                continue
            port = self.dp.ports[port_num]
            port.phys_up = False
            self.dpid_warn('%s down' % port)

            ofmsgs.extend(
                self._port_delete_flows(
                    port,
                    self._get_eth_srcs_learned_on_port(self.dp, port.number)))
            untagged_vlans_with_port = [
                vlan for vlan in [port.native_vlan] if vlan is not None]
            port_vlans = port.tagged_vlans + untagged_vlans_with_port
            for vlan in port_vlans:
                vlans_with_deleted_ports.add(vlan)

        for vlan in vlans_with_deleted_ports:
            ofmsgs.extend(self.flood_manager.build_flood_rules(
                vlan, modify=True))

        return ofmsgs

    def port_delete(self, dp_id, port_num):
        return self.ports_delete(dp_id, [port_num])

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
        for other_dpid, other_valve in list(valves.items()):
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
            self.dpid_log(
                'host learned via stack port to %s' % edge_dp.name)

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

    def _port_learn_ban_rules(self, pkt_meta):
        """Limit learning to a maximum configured on this port.

        Args:
            pkt_meta: PacketMeta instance.
        Returns:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []

        port = pkt_meta.port
        eth_src = pkt_meta.eth_src

        old_eth_srcs = self._get_eth_srcs_learned_on_port(self.dp, port.number)
        if len(old_eth_srcs) == self.dp.ports[port.number].max_hosts:
            ofmsgs.append(self.host_manager.temp_ban_host_learning_on_port(
                port))
            self.dpid_log(
                'max hosts %u reached on port %u, '
                'temporarily banning learning on this port, '
                'and not learning %s' % (
                    port.max_hosts, port.number, eth_src))
            return ofmsgs
        return ofmsgs

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
        hosts_count = self.host_manager.hosts_learned_on_vlan_count(
            vlan)
        if (vlan.max_hosts is not None and
                hosts_count == vlan.max_hosts and
                eth_src not in vlan.host_cache):
            ofmsgs.append(self.host_manager.temp_ban_host_learning_on_vlan(
                vlan))
            self.dpid_log(
                'max hosts %u reached on vlan %u, '
                'temporarily banning learning on this vlan, '
                'and not learning %s' % (
                    vlan.max_hosts, vlan.vid, eth_src))
        return ofmsgs

    def update_config_metrics(self, metrics):
        """Update gauge/metrics for configuration.

        metrics (FaucetMetrics): container of Prometheus metrics.
        """
        metrics.faucet_config_dp_name.labels(
            dpid=hex(self.dp.dp_id), name=self.dp.name).set(
                self.dp.dp_id)
        metrics.faucet_config_table_names.labels(
            dpid=hex(self.dp.dp_id), name='port_acl').set(
                self.dp.port_acl_table)
        metrics.faucet_config_table_names.labels(
            dpid=hex(self.dp.dp_id), name='vlan').set(
                self.dp.vlan_table)
        metrics.faucet_config_table_names.labels(
            dpid=hex(self.dp.dp_id), name='vlan_acl').set(
                self.dp.vlan_acl_table)
        metrics.faucet_config_table_names.labels(
            dpid=hex(self.dp.dp_id), name='eth_src').set(
                self.dp.eth_src_table)
        metrics.faucet_config_table_names.labels(
            dpid=hex(self.dp.dp_id), name='ipv4_fib').set(
                self.dp.ipv4_fib_table)
        metrics.faucet_config_table_names.labels(
            dpid=hex(self.dp.dp_id), name='ipv6_fib').set(
                self.dp.ipv6_fib_table)
        metrics.faucet_config_table_names.labels(
            dpid=hex(self.dp.dp_id), name='eth_dst').set(
                self.dp.eth_dst_table)
        metrics.faucet_config_table_names.labels(
            dpid=hex(self.dp.dp_id), name='flood').set(
                self.dp.flood_table)

    def update_metrics(self, metrics):
        """Update gauge/metrics.

        metrics (FaucetMetrics or None): container of Prometheus metrics.
        """
        # Clear the exported MAC learning.
        dpid = hex(self.dp.dp_id)
        for _, label_dict, _ in metrics.learned_macs.collect()[0].samples:
            if label_dict['dpid'] == dpid:
                metrics.learned_macs.labels(
                    dpid=label_dict['dpid'], vlan=label_dict['vlan'],
                    port=label_dict['port'], n=label_dict['n']).set(0)

        for vlan in list(self.dp.vlans.values()):
            hosts_count = self.host_manager.hosts_learned_on_vlan_count(
                vlan)
            metrics.vlan_hosts_learned.labels(
                dpid=dpid, vlan=vlan.vid).set(hosts_count)
            for ipv in vlan.ipvs():
                neigh_cache_size = len(vlan.neigh_cache_by_ipv(ipv))
                metrics.vlan_neighbors.labels(
                    dpid=dpid, vlan=vlan.vid, ipv=ipv).set(neigh_cache_size)
            # Repopulate MAC learning.
            hosts_on_port = {}
            for eth_src, host_cache_entry in sorted(list(vlan.host_cache.items())):
                port_num = str(host_cache_entry.port_num)
                mac_int = int(eth_src.replace(':', ''), 16)
                if port_num not in hosts_on_port:
                    hosts_on_port[port_num] = []
                hosts_on_port[port_num].append(mac_int)
            for port_num, hosts in list(hosts_on_port.items()):
                for i, mac_int in enumerate(hosts):
                    metrics.learned_macs.labels(
                        dpid=dpid, vlan=vlan.vid,
                        port=port_num, n=i).set(mac_int)

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
        if not vlan_vid in self.dp.vlans:
            self.dpid_log('Packet_in for unexpected VLAN %s' % (vlan_vid))
            return []

        pkt_meta = self._parse_rcv_packet(in_port, vlan_vid, pkt)
        ofmsgs = []

        if valve_packet.mac_addr_is_unicast(pkt_meta.eth_src):
            self.dpid_log(
                'Packet_in src:%s in_port:%d vid:%s' % (
                    pkt_meta.eth_src,
                    pkt_meta.port.number,
                    pkt_meta.vlan.vid))

            ofmsgs.extend(self.control_plane_handler(pkt_meta))

        if self._rate_limit_packet_ins():
            return ofmsgs

        ban_port_rules = self._port_learn_ban_rules(pkt_meta)
        if ban_port_rules:
            ofmsgs.extend(ban_port_rules)
            return ofmsgs

        ban_vlan_rules = self._vlan_learn_ban_rules(pkt_meta)
        if ban_vlan_rules:
            ofmsgs.extend(ban_vlan_rules)
            return ofmsgs

        ofmsgs.extend(self._learn_host(valves, dp_id, pkt_meta))
        return ofmsgs

    def host_expire(self):
        """Expire hosts not recently re/learned.

        Expire state from the host manager only; the switch does its own flow
        expiry.
        """
        if not self.dp.running:
            return
        now = time.time()
        for vlan in list(self.dp.vlans.values()):
            self.host_manager.expire_hosts_from_vlan(vlan, now)

    def _get_eth_srcs_learned_on_port(self, dp, port_no):
        old_eth_srcs = []
        if port_no in dp.ports:
            port = dp.ports[port_no]
            for vlan in [port.native_vlan] + port.tagged_vlans:
                if vlan is None:
                    continue
                for eth_src, host_cache_entry in list(vlan.host_cache.items()):
                    if host_cache_entry.port_num == port_no:
                        old_eth_srcs.append(eth_src)
        return old_eth_srcs

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
                all_ports_changed (bool): True if all ports changed.
        """
        all_ports_changed = False
        changed_acls = {}
        for acl_id, new_acl in list(new_dp.acls.items()):
            if acl_id not in self.dp.acls:
                changed_acls[acl_id] = new_acl
                self.dpid_log('ACL %s new' % acl_id)
            else:
                if new_acl != self.dp.acls[acl_id]:
                    changed_acls[acl_id] = new_acl
                    self.dpid_log('ACL %s changed' % acl_id)

        changed_ports = set([])
        for port_no, new_port in list(new_dp.ports.items()):
            if port_no not in self.dp.ports:
                # Detected a newly configured port
                changed_ports.add(port_no)
                self.dpid_log('port %s added' % port_no)
            else:
                old_port = self.dp.ports[port_no]
                if new_port != old_port:
                    # An existing port has configs changed
                    changed_ports.add(port_no)
                    self.dpid_log('port %s reconfigured' % port_no)
                elif new_port.acl_in in changed_acls:
                    # If the port has its ACL changed
                    changed_ports.add(port_no)
                    self.dpid_log('port %s ACL changed' % port_no)

        deleted_vlans = set([])
        for vid in list(self.dp.vlans.keys()):
            if vid not in new_dp.vlans:
                deleted_vlans.add(vid)

        changed_vlans = set([])
        for vid, new_vlan in list(new_dp.vlans.items()):
            if vid not in self.dp.vlans:
                changed_vlans.add(vid)
                self.dpid_log('VLAN %s added' % vid)
            else:
                old_vlan = self.dp.vlans[vid]
                if old_vlan != new_vlan:
                    old_vlan_new_ports = copy.deepcopy(old_vlan)
                    old_vlan_new_ports.tagged = new_vlan.tagged
                    old_vlan_new_ports.untagged = new_vlan.untagged
                    if old_vlan_new_ports != new_vlan:
                        changed_vlans.add(vid)
                        self.dpid_log('VLAN %s config changed' % vid)

        for vid in changed_vlans:
            for port in new_dp.vlans[vid].get_ports():
                changed_ports.add(port.number)

        deleted_ports = set([])
        for port_no in list(self.dp.ports.keys()):
            if port_no not in new_dp.ports:
                deleted_ports.add(port_no)

        if changed_ports == set(new_dp.ports.keys()):
            self.dpid_log('all ports config changed')
            all_ports_changed = True
        elif not changed_ports and not deleted_ports:
            self.dpid_log('no port config changes')

        if not deleted_vlans and not changed_vlans:
            self.dpid_log('no VLAN config changes')

        changes = (
            deleted_ports, changed_ports, deleted_vlans, changed_vlans,
            all_ports_changed)
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
                all_ports_changed (bool): True if all ports changed.
        Returns:
            tuple:
                cold_start (bool): whether cold starting.
                ofmsgs (list): OpenFlow messages.
        """
        (deleted_ports, changed_ports, deleted_vlans, changed_vlans,
         all_ports_changed) = changes
        new_dp.running = True
        cold_start = True
        ofmsgs = []

        if all_ports_changed:
            self.dp = new_dp
            ofmsgs.extend(self.datapath_connect(self.dp.dp_id, changed_ports))
        else:
            cold_start = False
            if deleted_ports:
                self.dpid_log('ports deleted: %s' % deleted_ports)
                ofmsgs.extend(self.ports_delete(self.dp.dp_id, deleted_ports))
            if deleted_vlans:
                self.dpid_log('VLANs deleted: %s' % deleted_vlans)
                for vid in deleted_vlans:
                    vlan = self.dp.vlans[vid]
                    ofmsgs.extend(self._del_vlan(vlan))
            if changed_ports:
                ofmsgs.extend(self.ports_delete(self.dp.dp_id, changed_ports))
            self.dp = new_dp
            if changed_vlans:
                self.dpid_log('VLANs changed/added: %s' % changed_vlans)
                for vid in changed_vlans:
                    vlan = self.dp.vlans[vid]
                    ofmsgs.extend(self._del_vlan(vlan))
                    ofmsgs.extend(self._add_vlan(vlan, set()))
            if changed_ports:
                self.dpid_log('ports changed/added: %s' % changed_ports)
                ofmsgs.extend(self.ports_add(self.dp.dp_id, changed_ports))
        return cold_start, ofmsgs

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
            tuple of:
                cold_start (bool): whether cold starting.
                ofmsgs (list): OpenFlow messages.
        """
        if self.dp.running:
            self.dpid_log('reload configuration')
            return self._apply_config_changes(
                new_dp,
                self._get_config_changes(new_dp))
        else:
            self.dpid_log('skipping configuration because datapath not up')
            return (False, [])

    def _add_faucet_vips(self, route_manager, vlan, faucet_vips):
        ofmsgs = []
        for faucet_vip in faucet_vips:
            assert self.dp.stack is None, 'stacking + routing not yet supported'
            ofmsgs.extend(route_manager.add_faucet_vip(vlan, faucet_vip))
        return ofmsgs

    def add_route(self, vlan, ip_gw, ip_dst):
        """Add route to VLAN routing table."""
        route_manager = self.route_manager_by_ipv[ip_dst.version]
        return route_manager.add_route(vlan, ip_gw, ip_dst)

    def del_route(self, vlan, ip_dst):
        """Delete route from VLAN routing table."""
        route_manager = self.route_manager_by_ipv[ip_dst.version]
        return route_manager.del_route(vlan, ip_dst)

    def resolve_gateways(self):
        """Call route managers to re/resolve gateways.

        Returns:
            list: OpenFlow messages, if any.
        """
        if not self.dp.running:
            return []
        ofmsgs = []
        now = time.time()
        for vlan in list(self.dp.vlans.values()):
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
        for vlan in list(self.dp.vlans.values()):
            vlans_dict[vlan.name] = vlan.to_conf()
        acls_dict = {}
        for acl_id, acl in list(self.dp.acls.items()):
            acls_dict[acl_id] = acl.to_conf()
        return {
            'dps': dps_dict,
            'vlans': vlans_dict,
            'acls': acls_dict,
            }


class TfmValve(Valve):
    """Valve implementation that uses OpenFlow send table features messages."""

    PIPELINE_CONF = 'tfm_pipeline.json'

    def switch_features(self, dp_id, msg):
        ryu_table_loader = tfm_pipeline.LoadRyuTables(
            self.dp.pipeline_config_dir, self.PIPELINE_CONF)
        self.dpid_log('loading pipeline configuration')
        return [valve_of.table_features(ryu_table_loader.load_tables())]


class ArubaValve(TfmValve):
    """Valve implementation that uses OpenFlow send table features messages."""

    PIPELINE_CONF = 'aruba_pipeline.json'
