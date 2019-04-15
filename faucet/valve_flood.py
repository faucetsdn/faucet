"""Manage flooding to ports on VLANs."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from faucet import valve_of
from faucet import valve_packet
from faucet.faucet_pipeline import STACK_LOOP_PROTECT_FIELD
from faucet.valve_manager_base import ValveManagerBase


class ValveFloodManager(ValveManagerBase):
    """Implement dataplane based flooding for standalone dataplanes."""

    # Enumerate possible eth_dst flood destinations.
    # First bool says whether to flood this destination, if the VLAN
    # has unicast flooding enabled (if unicast flooding is enabled,
    # then we flood all destination eth_dsts).
    FLOOD_DSTS = (
        (True, None, None),
        (False, valve_packet.BRIDGE_GROUP_ADDRESS, valve_packet.mac_byte_mask(3)), # 802.x
        (False, '01:00:5E:00:00:00', valve_packet.mac_byte_mask(3)), # IPv4 multicast
        (False, '33:33:00:00:00:00', valve_packet.mac_byte_mask(2)), # IPv6 multicast
        (False, valve_of.mac.BROADCAST_STR, valve_packet.mac_byte_mask(6)), # eth broadcasts
    )

    def __init__(self, logger, flood_table, pipeline,
                 use_group_table, groups, combinatorial_port_flood):
        self.logger = logger
        self.flood_table = flood_table
        self.pipeline = pipeline
        self.use_group_table = use_group_table
        self.groups = groups
        self.combinatorial_port_flood = combinatorial_port_flood
        self.bypass_priority = self._FILTER_PRIORITY
        self.flood_priority = self._MATCH_PRIORITY
        self.classification_offset = 0x100

    def initialise_tables(self):
        """Initialise the flood table with filtering flows."""
        ofmsgs = []
        for eth_dst, eth_dst_mask in (
                (valve_packet.CISCO_CDP_VTP_UDLD_ADDRESS, valve_packet.mac_byte_mask(6)),
                (valve_packet.CISCO_SPANNING_GROUP_ADDRESS, valve_packet.mac_byte_mask(6)),
                (valve_packet.BRIDGE_GROUP_ADDRESS, valve_packet.BRIDGE_GROUP_MASK)):
            ofmsgs.append(self.flood_table.flowdrop(
                self.flood_table.match(eth_dst=eth_dst, eth_dst_mask=eth_dst_mask),
                priority=self._mask_flood_priority(eth_dst_mask)))
        return ofmsgs

    def _mask_flood_priority(self, eth_dst_mask):
        return self.flood_priority + valve_packet.mac_mask_bits(eth_dst_mask)

    @staticmethod
    def _vlan_all_ports(vlan, exclude_unicast):
        """Return list of all ports that should be flooded to on a VLAN."""
        return list(vlan.flood_ports(vlan.get_ports(), exclude_unicast))

    @staticmethod
    def _build_flood_local_rule_actions(vlan, exclude_unicast, in_port, exclude_all_external):
        """Return a list of flood actions to flood packets from a port."""
        external_ports = vlan.loop_protect_external_ports_up()
        exclude_ports = vlan.exclude_same_lag_member_ports(in_port)
        if external_ports:
            if (exclude_all_external or
                    in_port is not None and in_port.loop_protect_external):
                exclude_ports |= set(external_ports)
        return valve_of.flood_port_outputs(
            vlan.tagged_flood_ports(exclude_unicast),
            vlan.untagged_flood_ports(exclude_unicast),
            in_port=in_port,
            exclude_ports=exclude_ports)

    def _build_flood_rule_actions(self, vlan, exclude_unicast, in_port, exclude_all_external=False):
        return self._build_flood_local_rule_actions(
            vlan, exclude_unicast, in_port, exclude_all_external)

    def _build_flood_rule(self, match, command, flood_acts, flood_priority):
        return self.flood_table.flowmod(
            match=match,
            command=command,
            inst=[valve_of.apply_actions(flood_acts)],
            priority=flood_priority)

    def _vlan_flood_priority(self, eth_dst_mask):
        return self._mask_flood_priority(eth_dst_mask)

    def _build_flood_rule_for_vlan(self, vlan, eth_dst, eth_dst_mask, # pylint: disable=too-many-arguments
                                   exclude_unicast, command):
        flood_priority = self._vlan_flood_priority(eth_dst_mask)
        match = self.flood_table.match(
            vlan=vlan, eth_dst=eth_dst, eth_dst_mask=eth_dst_mask)
        flood_acts = self._build_flood_rule_actions(
            vlan, exclude_unicast, None)
        return (self._build_flood_rule(match, command, flood_acts, flood_priority), flood_acts)

    @staticmethod
    def _output_non_output_actions(flood_acts):
        output_ports = set()
        all_nonoutput_actions = set()
        deduped_acts = []
        # avoid dedupe_ofmsgs() here, as it's expensive - most of the time we are comparing
        # port numbers as integers which is much cheaper.
        for act in flood_acts:
            if valve_of.is_output(act):
                if act.port in output_ports:
                    continue
                output_ports.add(act.port)
            else:
                str_act = str(act)
                if str_act in all_nonoutput_actions:
                    continue
                all_nonoutput_actions.add(str_act)
            deduped_acts.append(act)
        nonoutput_actions = all_nonoutput_actions - set([str(valve_of.pop_vlan())])
        return (deduped_acts, output_ports, nonoutput_actions)

    def _build_flood_acts_for_port(self, vlan, exclude_unicast, port,
                                   exclude_all_external=False):
        flood_acts = []
        port_output_ports = []
        port_non_output_acts = []
        if port.dyn_phys_up:
            flood_acts = self._build_flood_rule_actions(
                vlan, exclude_unicast, port, exclude_all_external)
            flood_acts, port_output_ports, port_non_output_acts = self._output_non_output_actions(
                flood_acts)
        return (flood_acts, port_output_ports, port_non_output_acts)

    def _build_flood_rule_for_port(self, vlan, eth_dst, eth_dst_mask, # pylint: disable=too-many-arguments
                                   command, port, flood_acts, add_match=None):
        ofmsgs = []
        if add_match is None:
            add_match = {}
        flood_priority = self._vlan_flood_priority(eth_dst_mask) + 1
        match = self.flood_table.match(
            vlan=vlan, in_port=port.number,
            eth_dst=eth_dst, eth_dst_mask=eth_dst_mask,
            **add_match)
        ofmsgs = self._build_flood_rule(match, command, flood_acts, flood_priority)
        return ofmsgs

    def _build_mask_flood_rules(self, vlan, eth_dst, eth_dst_mask, # pylint: disable=too-many-arguments
                                exclude_unicast, command):
        ofmsgs = []
        if self.combinatorial_port_flood:
            for port in self._vlan_all_ports(vlan, exclude_unicast):
                flood_acts, port_output_ports, _ = self._build_flood_acts_for_port(
                    vlan, exclude_unicast, port)
                if port_output_ports:
                    port_flood_ofmsg = self._build_flood_rule_for_port(
                        vlan, eth_dst, eth_dst_mask, command, port, flood_acts)
                    ofmsgs.append(port_flood_ofmsg)
        else:
            vlan_flood_ofmsg, vlan_flood_acts = self._build_flood_rule_for_vlan(
                vlan, eth_dst, eth_dst_mask,
                exclude_unicast, command)
            if not self.use_group_table:
                ofmsgs.append(vlan_flood_ofmsg)
            flood_acts, vlan_output_ports, vlan_non_output_acts = self._output_non_output_actions(
                vlan_flood_acts)
            for port in self._vlan_all_ports(vlan, exclude_unicast):
                flood_acts, port_output_ports, port_non_output_acts = self._build_flood_acts_for_port(
                    vlan, exclude_unicast, port)
                if port_output_ports:
                    port_output_ports.add(port.number)
                    if (vlan_output_ports == port_output_ports and
                            vlan_non_output_acts == port_non_output_acts):
                        continue
                    port_flood_ofmsg = self._build_flood_rule_for_port(
                        vlan, eth_dst, eth_dst_mask, command, port, flood_acts)
                    ofmsgs.append(port_flood_ofmsg)
        return ofmsgs

    def _build_multiout_flood_rules(self, vlan, command):
        """Build flooding rules for a VLAN without using groups."""
        ofmsgs = []
        for unicast_eth_dst, eth_dst, eth_dst_mask in self.FLOOD_DSTS:
            if unicast_eth_dst and not vlan.unicast_flood:
                continue
            ofmsgs.extend(self._build_mask_flood_rules(
                vlan, eth_dst, eth_dst_mask,
                unicast_eth_dst, command))
        return ofmsgs

    def _build_group_flood_rules(self, vlan, modify, command):
        """Build flooding rules for a VLAN using groups."""
        ofmsgs = []
        groups_by_unicast_eth = {}

        _, vlan_flood_acts = self._build_flood_rule_for_vlan(
            vlan, None, None, False, command)

        group_id = vlan.vid
        group = self.groups.get_entry(
            group_id, valve_of.build_group_flood_buckets(vlan_flood_acts))
        groups_by_unicast_eth[False] = group
        groups_by_unicast_eth[True] = group

        # Only configure unicast flooding group if has different output
        # actions to non unicast flooding.
        _, unicast_eth_vlan_flood_acts = self._build_flood_rule_for_vlan(
            vlan, None, None, True, command)
        unicast_eth_vlan_flood_acts, unicast_output_ports, _ = self._output_non_output_actions(
            unicast_eth_vlan_flood_acts)
        vlan_flood_acts, vlan_output_ports, _ = self._output_non_output_actions(vlan_flood_acts)
        if unicast_output_ports != vlan_output_ports:
            group_id += valve_of.VLAN_GROUP_OFFSET
            group = self.groups.get_entry(
                group_id, valve_of.build_group_flood_buckets(unicast_eth_vlan_flood_acts))
            groups_by_unicast_eth[True] = group

        for group in groups_by_unicast_eth.values():
            if modify:
                ofmsgs.append(group.modify())
            else:
                ofmsgs.extend(group.add())

        for unicast_eth_dst, eth_dst, eth_dst_mask in self.FLOOD_DSTS:
            if unicast_eth_dst and not vlan.unicast_flood:
                continue
            group = groups_by_unicast_eth[unicast_eth_dst]
            match = self.flood_table.match(
                vlan=vlan, eth_dst=eth_dst, eth_dst_mask=eth_dst_mask)
            flood_priority = self._mask_flood_priority(eth_dst_mask)
            ofmsgs.append(self.flood_table.flowmod(
                match=match,
                command=command,
                inst=[valve_of.apply_actions([valve_of.group_act(group.group_id)])],
                priority=flood_priority))
        return ofmsgs

    def add_vlan(self, vlan):
        return self.build_flood_rules(vlan)

    def build_flood_rules(self, vlan, modify=False):
        """Add flows to flood packets to unknown destinations on a VLAN."""
        command = valve_of.ofp.OFPFC_ADD
        if modify:
            command = valve_of.ofp.OFPFC_MODIFY_STRICT
        ofmsgs = self._build_multiout_flood_rules(vlan, command)
        if self.use_group_table:
            ofmsgs.extend(self._build_group_flood_rules(vlan, modify, command))
        return ofmsgs

    @staticmethod
    def update_stack_topo(event, dp, port=None): # pylint: disable=unused-argument,invalid-name
        """Update the stack topology. It has nothing to do for non-stacking DPs."""
        return

    @staticmethod
    def edge_learn_port(_other_valves, pkt_meta):
        """Possibly learn a host on a port.

        Args:
            other_valves (list): All Valves other than this one.
            pkt_meta (PacketMeta): PacketMeta instance for packet received.
        Returns:
            port to learn host on.
        """
        return pkt_meta.port


class ValveFloodStackManager(ValveFloodManager):
    """Implement dataplane based flooding for stacked dataplanes."""

    EXT_PORT_FLAG = 1
    NONEXT_PORT_FLAG = 0

    def __init__(self, logger, flood_table, pipeline, # pylint: disable=too-many-arguments
                 use_group_table, groups,
                 combinatorial_port_flood,
                 stack, stack_ports,
                 dp_shortest_path_to_root, shortest_path_port):
        super(ValveFloodStackManager, self).__init__(
            logger, flood_table, pipeline,
            use_group_table, groups,
            combinatorial_port_flood)
        self.stack = stack
        self.stack_ports = stack_ports
        self.shortest_path_port = shortest_path_port
        self.dp_shortest_path_to_root = dp_shortest_path_to_root
        self._reset_peer_distances()
        self._flood_actions_func = self._flood_actions
        if self.stack_size == 2:
            self._flood_actions_func = self._flood_actions_size2


    def _set_ext_flag(self, ext_flag):
        return self.flood_table.set_field(**{STACK_LOOP_PROTECT_FIELD: ext_flag})

    def _reset_peer_distances(self):
        """Reset distances to/from root for this DP."""
        port_peer_distances = [
            (port, len(port.stack['dp'].shortest_path_to_root())) for port in self.stack_ports]
        my_root_distance = len(self.dp_shortest_path_to_root())
        self.towards_root_stack_ports = [
            port for port, port_peer_distance in port_peer_distances
            if port_peer_distance < my_root_distance]
        self.away_from_root_stack_ports = [
            port for port, port_peer_distance in port_peer_distances
            if port_peer_distance > my_root_distance]
        self.stack_size = self.stack.get('longest_path_to_root_len', None)
        self.externals = self.stack.get('externals', False)
        self.ext_flood_needed = []
        self.ext_flood_not_needed = []
        if self.externals:
            self.ext_flood_needed = [self._set_ext_flag(self.EXT_PORT_FLAG)]
            self.ext_flood_not_needed = [self._set_ext_flag(self.NONEXT_PORT_FLAG)]

    def _flood_actions_size2(self, in_port, external_ports,
                             away_flood_actions, toward_flood_actions, local_flood_actions):
        if not in_port or in_port in self.stack_ports:
            flood_prefix = []
        else:
            flood_prefix = self.ext_flood_not_needed if in_port.loop_protect_external else self.ext_flood_needed

        # Special case for stack with maximum distance 2 - we don't need to reflect off of the root.
        flood_actions = (
            flood_prefix + away_flood_actions + local_flood_actions)

        if self._dp_is_root():
            # Default strategy is flood locally and to non-roots.
            if in_port:
                # If we have external ports, let the non-roots know we have already flooded
                # externally, locally.
                if external_ports:
                    flood_actions = (
                        flood_prefix + away_flood_actions + local_flood_actions)
        else:
            # Default strategy is flood locally and then to the root.
            flood_actions = (
                flood_prefix + toward_flood_actions + local_flood_actions)

            if in_port:
                # If packet came from the root, flood it locally.
                if in_port in self.towards_root_stack_ports:
                    flood_actions = (
                        flood_prefix + local_flood_actions)
                # If we have external ports on this switch, then let the root know
                # we have already flooded externally, locally.
                elif external_ports:
                    flood_actions = (
                        flood_prefix + toward_flood_actions + local_flood_actions)

        return flood_actions

    def _flood_actions(self, in_port, external_ports,
                       away_flood_actions, toward_flood_actions, local_flood_actions):
        # General case for stack with maximum distance > 2
        if self._dp_is_root():
            flood_actions = (
                self.ext_flood_needed + away_flood_actions + local_flood_actions)

            if in_port:
                if in_port in self.away_from_root_stack_ports:
                    # Packet from a non-root switch, flood locally and to all non-root switches
                    # (reflect it).
                    flood_actions = (
                        away_flood_actions + [valve_of.output_in_port()] + local_flood_actions)
                    # If we have external ports, let the non-roots know they don't have to
                    # flood externally.
                    if external_ports:
                        flood_actions = self.ext_flood_not_needed + flood_actions
                    else:
                        flood_actions = self.ext_flood_needed + flood_actions
                elif external_ports:
                    # Packet from an external switch, locally. As above, let the non-roots
                    # know they don't have to flood externally again.
                    flood_actions = (
                        self.ext_flood_not_needed + away_flood_actions + local_flood_actions)

        else:
            # Default non-root strategy is flood towards root.
            flood_actions = self.ext_flood_needed + toward_flood_actions

            if in_port:
                # Packet from switch further away, flood it to the root.
                if in_port in self.away_from_root_stack_ports:
                    flood_actions = toward_flood_actions
                # Packet from the root.
                elif in_port in self.towards_root_stack_ports:
                    # If we have external ports, and packet hasn't already been flooded
                    # externally, flood it externally before passing it to further away switches,
                    # and mark it flooded.
                    if external_ports:
                        flood_actions = (
                            self.ext_flood_not_needed + away_flood_actions + local_flood_actions)
                    else:
                        flood_actions = (
                            away_flood_actions + self.ext_flood_not_needed + local_flood_actions)
                # Packet from external port, locally. Mark it already flooded externally and
                # flood to root (it came from an external switch so keep it within the stack).
                elif in_port.loop_protect_external:
                    flood_actions = self.ext_flood_not_needed + toward_flood_actions

        return flood_actions

    def _build_flood_rule_actions(self, vlan, exclude_unicast, in_port, exclude_all_external=False):
        """Calculate flooding destinations based on this DP's position.

        If a standalone switch, then flood to local VLAN ports.

        If a distributed switch where all switches are directly
        connected to the root (star topology), edge switches flood locally
        and to the root, and the root floods to the other edges.

        If a non-star distributed switch topologies, use selective
        flooding (see the following example).

                               Hosts
                               ||||
                               ||||
                 +----+       +----+       +----+
              ---+1   |       |1234|       |   1+---
        Hosts ---+2   |       |    |       |   2+--- Hosts
              ---+3   |       |    |       |   3+---
              ---+4  5+-------+5  6+-------+5  4+---
                 +----+       +----+       +----+

                 Root DP

        Non-root switches flood only to the root. The root switch
        reflects incoming floods back out. Non-root switches
        flood packets from the root locally and further away.
        Flooding is entirely implemented in the dataplane.

        A host connected to a non-root switch can receive a copy
        of its own flooded packet (because the non-root switch
        does not know it has seen the packet already).

        A host connected to the root switch does not have this problem
        (because flooding is always away from the root). Therefore,
        connections to other non-FAUCET stacking networks should only
        be made to the root.

        On the root switch (left), flood destinations are:

        1: 2 3 4 5(s)
        2: 1 3 4 5(s)
        3: 1 2 4 5(s)
        4: 1 2 3 5(s)
        5: 1 2 3 4 5(s, note reflection)

        On the middle switch:

        1: 5(s)
        2: 5(s)
        3: 5(s)
        4: 5(s)
        5: 1 2 3 4 6(s)
        6: 5(s)

        On the rightmost switch:

        1: 5(s)
        2: 5(s)
        3: 5(s)
        4: 5(s)
        5: 1 2 3 4
        """
        exclude_ports = []
        external_ports = vlan.loop_protect_external_ports_up()

        if in_port and in_port in self.stack_ports:
            in_port_peer_dp = in_port.stack['dp']
            exclude_ports = [
                port for port in self.stack_ports
                if port.stack['dp'] == in_port_peer_dp]
        local_flood_actions = self._build_flood_local_rule_actions(
            vlan, exclude_unicast, in_port, exclude_all_external)
        away_flood_actions = valve_of.flood_tagged_port_outputs(
            self.away_from_root_stack_ports, in_port, exclude_ports=exclude_ports)
        toward_flood_actions = valve_of.flood_tagged_port_outputs(
            self.towards_root_stack_ports, in_port)
        flood_acts = self._flood_actions_func(
            in_port, external_ports, away_flood_actions,
            toward_flood_actions, local_flood_actions)
        return flood_acts

    def _build_mask_flood_rules(self, vlan, eth_dst, eth_dst_mask, # pylint: disable=too-many-arguments
                                exclude_unicast, command):
        # Stack ports aren't in VLANs, so need special rules to cause flooding from them.
        ofmsgs = super(ValveFloodStackManager, self)._build_mask_flood_rules(
            vlan, eth_dst, eth_dst_mask, exclude_unicast, command)
        external_ports = vlan.loop_protect_external_ports_up()
        for port in self.stack_ports:
            if self.externals and external_ports:
                # If external flag is set, flood to external ports, otherwise exclude them.
                for ext_port_flag, exclude_all_external in (
                        (self.NONEXT_PORT_FLAG, True),
                        (self.EXT_PORT_FLAG, False)):
                    flood_acts, port_output_ports, _ = self._build_flood_acts_for_port(
                        vlan, exclude_unicast, port, exclude_all_external=exclude_all_external)
                    if not port_output_ports:
                        continue
                    port_flood_ofmsg = self._build_flood_rule_for_port(
                        vlan, eth_dst, eth_dst_mask, command, port, flood_acts,
                        add_match={STACK_LOOP_PROTECT_FIELD: ext_port_flag})
                    ofmsgs.append(port_flood_ofmsg)
            else:
                flood_acts, port_output_ports, _ = self._build_flood_acts_for_port(
                    vlan, exclude_unicast, port)
                if not port_output_ports:
                    continue
                port_flood_ofmsg = self._build_flood_rule_for_port(
                    vlan, eth_dst, eth_dst_mask, command, port, flood_acts)
                ofmsgs.append(port_flood_ofmsg)
            if not self._dp_is_root():
                # Drop bridge local traffic immediately.
                bridge_local_match = {
                    'in_port': port.number,
                    'vlan': vlan,
                    'eth_dst': valve_packet.BRIDGE_GROUP_ADDRESS,
                    'eth_dst_mask': valve_packet.BRIDGE_GROUP_MASK
                    }
                ofmsgs.extend(self.pipeline.filter_packets(
                    bridge_local_match, priority_offset=self.classification_offset))
                # Because stacking uses reflected broadcasts from the root,
                # don't try to learn broadcast sources from stacking ports.
                if eth_dst is not None:
                    match = {
                        'in_port': port.number,
                        'vlan': vlan,
                        'eth_dst': eth_dst,
                        'eth_dst_mask': eth_dst_mask
                        }
                    ofmsgs.extend(self.pipeline.select_packets(
                        self.flood_table, match,
                        priority_offset=self.classification_offset
                        ))
        return ofmsgs

    def _dp_is_root(self):
        """Return True if this datapath is the root of the stack."""
        return 'priority' in self.stack

    def _edge_dp_for_host(self, other_valves, pkt_meta):
        """Simple distributed unicast learning.

        Args:
            other_valves (list): All Valves other than this one.
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
        # TODO: stacking handles failure of redundant links between DPs,
        # but not failure of an entire DP (should be able to find
        # shortest path via alternate DP).
        if pkt_meta.port.stack:
            peer_dp = pkt_meta.port.stack['dp']
            if peer_dp.is_stack_edge() or peer_dp.is_stack_root():
                return peer_dp
        stacked_valves = [valve for valve in other_valves if valve.dp.stack is not None]
        eth_src = pkt_meta.eth_src
        vlan_vid = pkt_meta.vlan.vid
        for other_valve in stacked_valves:
            if vlan_vid in other_valve.dp.vlans:
                other_dp_vlan = other_valve.dp.vlans[vlan_vid]
                entry = other_dp_vlan.cached_host(eth_src)
                if entry and not entry.port.stack:
                    return other_valve.dp
        return None

    def update_stack_topo(self, event, dp, port=None):
        """Update the stack topo according to the event."""

        def _stack_topo_up_dp(_dp): # pylint: disable=invalid-name
            for port in [port for port in _dp.stack_ports]:
                if port.is_stack_up():
                    _stack_topo_up_port(_dp, port)
                else:
                    _stack_topo_down_port(_dp, port)

        def _stack_topo_down_dp(_dp): # pylint: disable=invalid-name
            for port in [port for port in _dp.stack_ports]:
                _stack_topo_down_port(_dp, port)

        def _stack_topo_up_port(_dp, _port): # pylint: disable=invalid-name
            _dp.add_stack_link(self.stack['graph'], _dp, _port)

        def _stack_topo_down_port(_dp, _port): # pylint: disable=invalid-name
            _dp.remove_stack_link(self.stack['graph'], _dp, _port)

        if port:
            if event:
                _stack_topo_up_port(dp, port)
            else:
                _stack_topo_down_port(dp, port)
        else:
            if event:
                _stack_topo_up_dp(dp)
            else:
                _stack_topo_down_dp(dp)
        return True

    def edge_learn_port(self, other_valves, pkt_meta):
        """Possibly learn a host on a port.

        Args:
            other_valves (list): All Valves other than this one.
            pkt_meta (PacketMeta): PacketMeta instance for packet received.
        Returns:
            port to learn host on, or None.
        """
        if pkt_meta.port.stack:
            edge_dp = self._edge_dp_for_host(other_valves, pkt_meta)
            # No edge DP may have learned this host yet.
            if edge_dp is None:
                return None
            return self.shortest_path_port(edge_dp.name)
        return super(ValveFloodStackManager, self).edge_learn_port(
            other_valves, pkt_meta)
