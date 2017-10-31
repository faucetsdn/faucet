"""Manage flooding to ports on VLANs."""

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
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from faucet import valve_of
from faucet import valve_packet


class ValveFloodManager(object):
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

    def __init__(self, flood_table, flood_priority,
                 use_group_table, groups):
        self.flood_table = flood_table
        self.flood_priority = flood_priority
        self.use_group_table = use_group_table
        self.groups = groups

    @staticmethod
    def _vlan_all_ports(vlan, exclude_unicast):
        """Return list of all ports that should be flooded to on a VLAN."""
        return vlan.flood_ports(vlan.get_ports(), exclude_unicast)

    @staticmethod
    def _build_flood_local_rule_actions(vlan, exclude_unicast, in_port):
        """Return a list of flood actions to flood packets from a port."""
        flood_acts = []
        exclude_ports = []
        if in_port.lacp:
            lags = vlan.lags()
            exclude_ports = lags[in_port.lacp]
        tagged_ports = vlan.tagged_flood_ports(exclude_unicast)
        flood_acts.extend(valve_of.flood_tagged_port_outputs(
            tagged_ports, in_port, exclude_ports=exclude_ports))
        untagged_ports = vlan.untagged_flood_ports(exclude_unicast)
        flood_acts.extend(valve_of.flood_untagged_port_outputs(
            untagged_ports, in_port, exclude_ports=exclude_ports))
        return flood_acts

    def _build_flood_rule_actions(self, vlan, exclude_unicast, in_port):
        return self._build_flood_local_rule_actions(
            vlan, exclude_unicast, in_port)

    def _build_flood_rule_for_port(self, vlan, eth_dst, eth_dst_mask,
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

    def _build_unmirrored_flood_rules(self, vlan, eth_dst, eth_dst_mask,
                                      exclude_unicast, command, flood_priority):
        ofmsgs = []
        for port in self._vlan_all_ports(vlan, exclude_unicast):
            ofmsgs.extend(self._build_flood_rule_for_port(
                vlan, eth_dst, eth_dst_mask,
                exclude_unicast, command, flood_priority,
                port, []))
        return ofmsgs

    def _build_mirrored_flood_rules(self, vlan, eth_dst, eth_dst_mask,
                                    exclude_unicast, command, flood_priority):
        ofmsgs = []
        mirrored_ports = vlan.mirrored_ports()
        for port in mirrored_ports:
            mirror_acts = [valve_of.output_port(port.mirror)]
            ofmsgs.extend(self._build_flood_rule_for_port(
                vlan, eth_dst, eth_dst_mask,
                exclude_unicast, command, flood_priority,
                port, mirror_acts))
        return ofmsgs

    def _build_multiout_flood_rules(self, vlan, command):
        """Build flooding rules for a VLAN without using groups."""
        flood_priority = self.flood_priority
        ofmsgs = []
        for unicast_eth_dst, eth_dst, eth_dst_mask in self.FLOOD_DSTS:
            if unicast_eth_dst and not vlan.unicast_flood:
                continue
            ofmsgs.extend(self._build_unmirrored_flood_rules(
                vlan, eth_dst, eth_dst_mask,
                unicast_eth_dst, command, flood_priority))
            flood_priority += 1
            ofmsgs.extend(self._build_mirrored_flood_rules(
                vlan, eth_dst, eth_dst_mask,
                unicast_eth_dst, command, flood_priority))
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
        if self.use_group_table:
            hairpin_ports = vlan.hairpin_ports()
            # TODO: hairpin flooding modes.
            # TODO: avoid loopback flood on LAG ports
            if not hairpin_ports:
                return self._build_group_flood_rules(vlan, modify, command)
        return self._build_multiout_flood_rules(vlan, command)

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

    def __init__(self, flood_table, flood_priority,
                 use_group_table, groups,
                 stack, stack_ports,
                 dp_shortest_path_to_root, shortest_path_port):
        super(ValveFloodStackManager, self).__init__(
            flood_table, flood_priority, use_group_table, groups)
        self.stack = stack
        self.stack_ports = stack_ports
        my_root_distance = dp_shortest_path_to_root()
        self.shortest_path_port = shortest_path_port
        self.towards_root_stack_ports = []
        self.away_from_root_stack_ports = []
        for port in self.stack_ports:
            peer_dp = port.stack['dp']
            peer_root_distance = peer_dp.shortest_path_to_root()
            if peer_root_distance > my_root_distance:
                self.away_from_root_stack_ports.append(port)
            elif peer_root_distance < my_root_distance:
                self.towards_root_stack_ports.append(port)

    def _build_flood_rule_actions(self, vlan, exclude_unicast, in_port):
        """Calculate flooding destinations based on this DP's position.

        If a standalone switch, then flood to local VLAN ports.

        If a distributed switch, see the following example.

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

        The basic strategy is flood-towards-root. The root
        reflects the flood back out. There are no loops and flooding
        is done entirely in the dataplane.

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
        local_flood_actions = self._build_flood_local_rule_actions(
            vlan, exclude_unicast, in_port)
        away_flood_actions = valve_of.flood_tagged_port_outputs(
            self.away_from_root_stack_ports, in_port)
        toward_flood_actions = valve_of.flood_tagged_port_outputs(
            self.towards_root_stack_ports, in_port)
        flood_all_except_self = away_flood_actions + local_flood_actions

        # If we're the root of a distributed switch..
        if self._dp_is_root():
            # If the input port was local, then flood local VLAN and stacks.
            if self._port_is_dp_local(in_port):
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

    def build_flood_rules(self, vlan, modify=False):
        """Add flows to flood packets to unknown destinations on a VLAN."""
        command = valve_of.ofp.OFPFC_ADD
        if modify:
            command = valve_of.ofp.OFPFC_MODIFY_STRICT
        # TODO: group tables for stacking
        return self._build_multiout_flood_rules(vlan, command)

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

    @staticmethod
    def _edge_dp_for_host(other_valves, pkt_meta):
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
        eth_src = pkt_meta.eth_src
        vlan_vid = pkt_meta.vlan.vid
        for other_valve in other_valves:
            other_dp_host_cache = other_valve.dp.vlans[vlan_vid].host_cache
            if eth_src in other_dp_host_cache:
                host = other_dp_host_cache[eth_src]
                if host.port.stack is None:
                    return other_valve.dp
        return None

    def edge_learn_port(self, other_valves, pkt_meta):
        """Possibly learn a host on a port.

        Args:
            other_valves (list): All Valves other than this one.
            pkt_meta (PacketMeta): PacketMeta instance for packet received.
        Returns:
            port to learn host on, or None.
        """
        if pkt_meta.port.stack is None:
            return super(ValveFloodStackManager, self).edge_learn_port(
                other_valves, pkt_meta)
        edge_dp = self._edge_dp_for_host(other_valves, pkt_meta)
        # No edge DP may have learned this host yet.
        if edge_dp is None:
            return None
        return self.shortest_path_port(edge_dp.name)
