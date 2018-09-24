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


class ValveFloodManager:
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
        (False, valve_of.mac.BROADCAST_STR, None), # flood on ethernet broadcasts
    )

    def __init__(self, flood_table, eth_src_table, # pylint: disable=too-many-arguments
                 flood_priority, bypass_priority,
                 use_group_table, groups,
                 combinatorial_port_flood):
        self.flood_table = flood_table
        self.eth_src_table = eth_src_table
        self.bypass_priority = bypass_priority
        self.flood_priority = flood_priority
        self.use_group_table = use_group_table
        self.groups = groups
        self.combinatorial_port_flood = combinatorial_port_flood

    @staticmethod
    def _vlan_all_ports(vlan, exclude_unicast):
        """Return list of all ports that should be flooded to on a VLAN."""
        return list(vlan.flood_ports(vlan.get_ports(), exclude_unicast))

    @staticmethod
    def _build_flood_local_rule_actions(vlan, exclude_unicast, in_port):
        """Return a list of flood actions to flood packets from a port."""
        flood_acts = []
        exclude_ports = set()
        lags = vlan.lags()
        lags_up = vlan.lags_up()
        if lags:
            if in_port is not None and in_port.lacp:
                # Don't flood from one LACP bundle member, to another.
                exclude_ports.update(lags[in_port.lacp])
            # Pick one up bundle member to flood to.
            for lag, ports in list(lags.items()):
                ports_up = lags_up[lag]
                if ports_up:
                    exclude_ports.update(ports[1:])
                else:
                    exclude_ports.update(ports)
        tagged_ports = vlan.tagged_flood_ports(exclude_unicast)
        flood_acts.extend(valve_of.flood_tagged_port_outputs(
            tagged_ports, in_port=in_port, exclude_ports=exclude_ports))
        untagged_ports = vlan.untagged_flood_ports(exclude_unicast)
        flood_acts.extend(valve_of.flood_untagged_port_outputs(
            untagged_ports, in_port=in_port, exclude_ports=exclude_ports))
        return flood_acts

    def _build_flood_rule_actions(self, vlan, exclude_unicast, in_port):
        return self._build_flood_local_rule_actions(
            vlan, exclude_unicast, in_port)

    def _build_flood_rule_for_vlan(self, vlan, eth_dst, eth_dst_mask, # pylint: disable=too-many-arguments
                                   exclude_unicast, command, flood_priority,
                                   preflood_acts):
        ofmsgs = []
        match = self.flood_table.match(
            vlan=vlan, eth_dst=eth_dst, eth_dst_mask=eth_dst_mask)
        flood_acts = self._build_flood_rule_actions(
            vlan, exclude_unicast, None)
        ofmsgs.append(self.flood_table.flowmod(
            match=match,
            command=command,
            inst=[valve_of.apply_actions(preflood_acts + flood_acts)],
            priority=flood_priority))
        return ofmsgs

    def _build_flood_rule_for_port(self, vlan, eth_dst, eth_dst_mask, # pylint: disable=too-many-arguments
                                   exclude_unicast, command, flood_priority,
                                   port, preflood_acts):
        ofmsgs = []
        match = self.flood_table.match(
            vlan=vlan, in_port=port.number,
            eth_dst=eth_dst, eth_dst_mask=eth_dst_mask)
        flood_acts = self._build_flood_rule_actions(
            vlan, exclude_unicast, port)
        ofmsgs.append(self.flood_table.flowmod(
            match=match,
            command=command,
            inst=[valve_of.apply_actions(preflood_acts + flood_acts)],
            priority=flood_priority))
        return ofmsgs

    def _combinatorial_port_flood(self, vlan, eth_dst, eth_dst_mask, # pylint: disable=too-many-arguments
                                  exclude_unicast, command, flood_priority,
                                  mirror_acts):
        ofmsgs = []
        # TODO: hairpin rules should use higher priority rules so we
        # can use default non-combinatorial rules.
        if self.combinatorial_port_flood or vlan.hairpin_ports():
            for port in self._vlan_all_ports(vlan, exclude_unicast):
                ofmsgs.extend(self._build_flood_rule_for_port(
                    vlan, eth_dst, eth_dst_mask,
                    exclude_unicast, command, flood_priority,
                    port, mirror_acts))
        return ofmsgs

    def _build_mask_flood_rules(self, vlan, eth_dst, eth_dst_mask, # pylint: disable=too-many-arguments
                                exclude_unicast, command, flood_priority,
                                mirror_acts):
        ofmsgs = self._combinatorial_port_flood(
            vlan, eth_dst, eth_dst_mask,
            exclude_unicast, command, flood_priority, mirror_acts)
        if not ofmsgs:
            ofmsgs.extend(self._build_flood_rule_for_vlan(
                vlan, eth_dst, eth_dst_mask,
                exclude_unicast, command, flood_priority, mirror_acts))
        return ofmsgs

    def _build_multiout_flood_rules(self, vlan, command):
        """Build flooding rules for a VLAN without using groups."""
        flood_priority = self.flood_priority
        mirror_acts = []
        for mirrored_port in vlan.mirrored_ports():
            for act in mirrored_port.mirror_actions():
                mirror_acts.append(act)
        mirror_acts = valve_of.dedupe_output_port_acts(mirror_acts)
        ofmsgs = []
        for unicast_eth_dst, eth_dst, eth_dst_mask in self.FLOOD_DSTS:
            if unicast_eth_dst and not vlan.unicast_flood:
                continue
            ofmsgs.extend(self._build_mask_flood_rules(
                vlan, eth_dst, eth_dst_mask,
                unicast_eth_dst, command, flood_priority, list(mirror_acts)))
            flood_priority += 1
        return ofmsgs

    @staticmethod
    def _build_group_buckets(vlan, unicast_flood):
        buckets = []
        tagged_flood_ports = vlan.tagged_flood_ports(unicast_flood)
        buckets.extend(valve_of.group_flood_buckets(tagged_flood_ports, False))
        untagged_flood_ports = vlan.untagged_flood_ports(unicast_flood)
        buckets.extend(valve_of.group_flood_buckets(untagged_flood_ports, True))
        return buckets

    def _build_group_flood_rules(self, vlan, modify, command):
        """Build flooding rules for a VLAN using groups."""
        flood_priority = self.flood_priority
        broadcast_group = self.groups.get_entry(
            vlan.vid,
            self._build_group_buckets(vlan, False))
        unicast_group = self.groups.get_entry(
            vlan.vid + valve_of.VLAN_GROUP_OFFSET,
            self._build_group_buckets(vlan, vlan.unicast_flood))
        ofmsgs = []
        if modify:
            ofmsgs.append(broadcast_group.modify())
            ofmsgs.append(unicast_group.modify())
        else:
            ofmsgs.extend(broadcast_group.add())
            ofmsgs.extend(unicast_group.add())
        for unicast_eth_dst, eth_dst, eth_dst_mask in self.FLOOD_DSTS:
            if unicast_eth_dst and not vlan.unicast_flood:
                continue
            group = broadcast_group
            if not eth_dst:
                group = unicast_group
            match = self.flood_table.match(
                vlan=vlan, eth_dst=eth_dst, eth_dst_mask=eth_dst_mask)
            ofmsgs.append(self.flood_table.flowmod(
                match=match,
                command=command,
                inst=[valve_of.apply_actions([valve_of.group_act(group.group_id)])],
                priority=flood_priority))
            flood_priority += 1
        return ofmsgs

    def build_flood_rules(self, vlan, modify=False):
        """Add flows to flood packets to unknown destinations on a VLAN."""
        # TODO: group table support is still fairly uncommon, so
        # group tables are currently optional.
        command = valve_of.ofp.OFPFC_ADD
        if modify:
            command = valve_of.ofp.OFPFC_MODIFY_STRICT
        if self.use_group_table and not vlan.hairpin_ports():
            # TODO: hairpin flooding modes.
            # TODO: avoid loopback flood on LAG ports
            return self._build_group_flood_rules(vlan, modify, command)
        return self._build_multiout_flood_rules(vlan, command)

    def update_stack_topo(self, event, dp, port=None): # pylint: disable=unused-argument,invalid-name
        """Update the stack topology. It has nothing to do for non-stacking DPs."""
        pass

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

    def __init__(self, flood_table, eth_src_table, # pylint: disable=too-many-arguments
                 flood_priority, bypass_priority,
                 use_group_table, groups,
                 combinatorial_port_flood,
                 stack, stack_ports,
                 dp_shortest_path_to_root, shortest_path_port):
        super(ValveFloodStackManager, self).__init__(
            flood_table, eth_src_table,
            flood_priority, bypass_priority,
            use_group_table, groups,
            combinatorial_port_flood)
        self.stack = stack
        self.stack_ports = stack_ports
        self.shortest_path_port = shortest_path_port
        self.dp_shortest_path_to_root = dp_shortest_path_to_root
        self._reset_peer_distances()

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

    def _build_flood_rule_actions(self, vlan, exclude_unicast, in_port):
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
        dp_local_in_port = self._port_is_dp_local(in_port)
        if not dp_local_in_port:
            in_port_peer_dp = in_port.stack['dp']
            exclude_ports = [
                port for port in self.stack_ports
                if port.stack and port.stack['dp'] == in_port_peer_dp]
        local_flood_actions = self._build_flood_local_rule_actions(
            vlan, exclude_unicast, in_port)
        away_flood_actions = valve_of.flood_tagged_port_outputs(
            self.away_from_root_stack_ports, in_port, exclude_ports=exclude_ports)
        toward_flood_actions = valve_of.flood_tagged_port_outputs(
            self.towards_root_stack_ports, in_port)
        flood_all_except_self = away_flood_actions + local_flood_actions

        # TODO: optimization for 2 layer stack - no need to reflect off root.
        # We should generalize the edge switch case, too.
        if self.stack.get('longest_path_to_root_len', None) == 2:
            if self._dp_is_root():
                return away_flood_actions + local_flood_actions
            if dp_local_in_port:
                return toward_flood_actions + local_flood_actions
            return local_flood_actions

        if self._dp_is_root():
            if dp_local_in_port:
                return flood_all_except_self
            # If input port non-local, then flood outward again
            return [valve_of.output_in_port()] + flood_all_except_self

        # We are not the root of the distributed switch
        # If input port was connected to a switch closer to the root,
        # then flood outwards (local VLAN and stacks further than us)
        if in_port in self.towards_root_stack_ports:
            return flood_all_except_self
        # If input port local or from a further away switch, flood
        # towards the root.
        return toward_flood_actions

    def _build_mask_flood_rules(self, vlan, eth_dst, eth_dst_mask, # pylint: disable=too-many-arguments
                                exclude_unicast, command, flood_priority,
                                mirror_acts):
        ofmsgs = self._combinatorial_port_flood(
            vlan, eth_dst, eth_dst_mask,
            exclude_unicast, command, flood_priority, mirror_acts)
        if not ofmsgs:
            for port in self.stack_ports:
                ofmsgs.extend(self._build_flood_rule_for_port(
                    vlan, eth_dst, eth_dst_mask,
                    exclude_unicast, command, flood_priority + 1,
                    port, mirror_acts))
            ofmsgs.extend(self._build_flood_rule_for_vlan(
                vlan, eth_dst, eth_dst_mask,
                exclude_unicast, command, flood_priority, mirror_acts))
        return ofmsgs

    def build_flood_rules(self, vlan, modify=False):
        """Add flows to flood packets to unknown destinations on a VLAN."""
        command = valve_of.ofp.OFPFC_ADD
        if modify:
            command = valve_of.ofp.OFPFC_MODIFY_STRICT
        # TODO: group tables for stacking
        ofmsgs = self._build_multiout_flood_rules(vlan, command)
        if self._dp_is_root():
            return ofmsgs
        # Because stacking uses reflected broadcasts from the root,
        # don't try to learn broadcast sources from stacking ports.
        for port in self.stack_ports:
            ofmsgs.append(self.eth_src_table.flowdrop(
                self.eth_src_table.match(
                    in_port=port.number,
                    vlan=vlan,
                    eth_dst=valve_packet.BRIDGE_GROUP_ADDRESS,
                    eth_dst_mask=valve_packet.BRIDGE_GROUP_MASK),
                priority=self.bypass_priority+1))
        for unicast_eth_dst, eth_dst, eth_dst_mask in self.FLOOD_DSTS:
            if unicast_eth_dst:
                continue
            for port in self.stack_ports:
                match = self.eth_src_table.match(
                    in_port=port.number,
                    vlan=vlan,
                    eth_dst=eth_dst,
                    eth_dst_mask=eth_dst_mask)
                ofmsgs.append(self.eth_src_table.flowmod(
                    match=match,
                    command=command,
                    inst=[self.eth_src_table.goto(self.flood_table)],
                    priority=self.bypass_priority))
        return ofmsgs

    def _vlan_all_ports(self, vlan, exclude_unicast):
        vlan_all_ports = super(ValveFloodStackManager, self)._vlan_all_ports(
            vlan, exclude_unicast)
        vlan_all_ports.extend(self.away_from_root_stack_ports)
        vlan_all_ports.extend(self.towards_root_stack_ports)
        return vlan_all_ports

    def _dp_is_root(self):
        """Return True if this datapath is the root of the stack."""
        return 'priority' in self.stack

    def _port_is_dp_local(self, port):
        """Return True if port is on this datapath."""
        if (port in self.away_from_root_stack_ports or
                port in self.towards_root_stack_ports):
            return False
        return True

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
