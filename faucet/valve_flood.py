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
# distributed under the License is distributed on an "AS IS" BASISo
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import valve_of

from ryu.lib import mac
from ryu.ofproto import ofproto_v1_3 as ofp


class ValveFloodManager(object):

    # Enumerate possible eth_dst flood destinations.
    # First bool says whether to flood this destination, if the VLAN
    # has unicast flooding enabled (if unicast flooding is enabled,
    # then we flood all destination eth_dsts).
    FLOOD_DSTS = (
        (True, None, None),
        (False, '01:80:C2:00:00:00', 'ff:ff:ff:00:00:00'), # 802.x
        (False, '01:00:5E:00:00:00', 'ff:ff:ff:00:00:00'), # IPv4 multicast
        (False, '33:33:00:00:00:00', 'ff:ff:00:00:00:00'), # IPv6 multicast
        (False, mac.BROADCAST_STR, None), # flood on ethernet broadcasts
    )

    def __init__(self, flood_table, flood_priority,
                 valve_in_match, valve_flowmod,
                 dp_stack, dp_ports, dp_shortest_path_to_root,
                 use_group_table):
        self.flood_table = flood_table
        self.flood_priority = flood_priority
        self.valve_in_match = valve_in_match
        self.valve_flowmod = valve_flowmod
        self.stack = dp_stack
        self.use_group_table = use_group_table
        self.stack_ports = [
            port for port in list(dp_ports.values()) if port.stack is not None]
        self.towards_root_stack_ports = []
        self.away_from_root_stack_ports = []
        my_root_distance = dp_shortest_path_to_root()
        for port in self.stack_ports:
            peer_dp = port.stack['dp']
            peer_root_distance = peer_dp.shortest_path_to_root()
            if peer_root_distance > my_root_distance:
                self.away_from_root_stack_ports.append(port)
            elif peer_root_distance < my_root_distance:
                self.towards_root_stack_ports.append(port)

    def _build_flood_port_outputs(self, ports, exclude_port):
        flood_acts = []
        for port in ports:
            if port == exclude_port:
                continue
            flood_acts.append(valve_of.output_port(port.number))
        return flood_acts

    def _build_flood_local_rule_actions(self, vlan, exclude_unicast, in_port):
        flood_acts = []
        tagged_ports = vlan.tagged_flood_ports(exclude_unicast)
        flood_acts.extend(self._build_flood_port_outputs(
            tagged_ports, in_port))
        untagged_ports = vlan.untagged_flood_ports(exclude_unicast)
        if untagged_ports:
            flood_acts.append(valve_of.pop_vlan())
            flood_acts.extend(self._build_flood_port_outputs(
                untagged_ports, in_port))
        return flood_acts

    def _port_is_dp_local(self, port):
        if (port in self.away_from_root_stack_ports or
                port in self.towards_root_stack_ports):
            return False
        return True

    def _dp_is_root(self):
        return self.stack is not None and 'priority' in self.stack

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
        # If we're a standalone switch, then flood local VLAN
        if self.stack is None:
            return local_flood_actions

        away_flood_actions = self._build_flood_port_outputs(
            self.away_from_root_stack_ports, in_port)
        toward_flood_actions = self._build_flood_port_outputs(
            self.towards_root_stack_ports, in_port)
        flood_all_except_self = local_flood_actions + away_flood_actions

        # If we're the root of a distributed switch..
        if self._dp_is_root():
            # If the input port was local, then flood local VLAN and stacks.
            if self._port_is_dp_local(in_port):
                return flood_all_except_self
            # If input port non-local, then flood outward again
            else:
                return [valve_of.output_in_port()] + flood_all_except_self
        # We are not the root of the distributed switch
        else:
            # If input port was connected to a switch closer to the root,
            # then flood outwards (local VLAN and stacks further than us)
            if in_port in self.towards_root_stack_ports:
                return flood_all_except_self
            # If input port local or from a further away switch, flood
            # towards the root.
            else:
                return toward_flood_actions

    def _build_flood_rule_for_port(self, vlan, eth_dst, eth_dst_mask,
                                   exclude_unicast, command, flood_priority,
                                   port, preflood_acts):
        ofmsgs = []
        match = self.valve_in_match(
            self.flood_table, vlan=vlan, in_port=port.number,
            eth_dst=eth_dst, eth_dst_mask=eth_dst_mask)
        flood_acts = self._build_flood_rule_actions(
            vlan, exclude_unicast, port)
        ofmsgs.append(self.valve_flowmod(
            self.flood_table,
            match=match,
            command=command,
            inst=[valve_of.apply_actions(preflood_acts + flood_acts)],
            priority=flood_priority))
        return ofmsgs

    def _build_unmirrored_flood_rules(self, vlan, eth_dst, eth_dst_mask,
                                      exclude_unicast, command, flood_priority):
        ofmsgs = []
        vlan_all_ports = []
        vlan_all_ports.extend(vlan.flood_ports(vlan.get_ports(), exclude_unicast))
        vlan_all_ports.extend(self.away_from_root_stack_ports)
        vlan_all_ports.extend(self.towards_root_stack_ports)
        for port in vlan_all_ports:
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

    def _build_group_buckets(self, vlan, unicast_flood):
        buckets = []
        for port in vlan.tagged_flood_ports(unicast_flood):
            buckets.append(valve_of.bucket(
                actions=[valve_of.output_port(port.number)]))
        for port in vlan.untagged_flood_ports(unicast_flood):
            buckets.append(valve_of.bucket(
                actions=[
                    valve_of.pop_vlan(),
                    valve_of.output_port(port.number)]))
        return buckets

    def _build_group_flood_rules(self, vlan, modify, command):
        flood_priority = self.flood_priority
        broadcast_buckets = self._build_group_buckets(vlan, False)
        unicast_buckets = self._build_group_buckets(vlan, vlan.unicast_flood)
        group_id = vlan.vid
        ofmsgs = []
        group_mod_method = valve_of.groupadd
        if modify:
            group_mod_method = valve_of.groupmod
        else:
            ofmsgs.append(
                valve_of.groupdel(group_id=group_id))
            ofmsgs.append(
                valve_of.groupdel(group_id=group_id+valve_of.VLAN_GROUP_OFFSET))
        ofmsgs.append(
            group_mod_method(group_id=group_id, buckets=broadcast_buckets))
        ofmsgs.append(
            group_mod_method(group_id=group_id+valve_of.VLAN_GROUP_OFFSET,
                             buckets=unicast_buckets))
        for unicast_eth_dst, eth_dst, eth_dst_mask in self.FLOOD_DSTS:
            if unicast_eth_dst and not vlan.unicast_flood:
                continue
            group_id = vlan.vid
            if not eth_dst:
                group_id = group_id + valve_of.VLAN_GROUP_OFFSET
            match = self.valve_in_match(
                self.flood_table, vlan=vlan,
                eth_dst=eth_dst, eth_dst_mask=eth_dst_mask)
            ofmsgs.append(self.valve_flowmod(
                self.flood_table,
                match=match,
                command=command,
                inst=[valve_of.apply_actions([valve_of.group_act(group_id)])],
                priority=flood_priority))
            flood_priority += 1
        return ofmsgs

    def _build_multiout_flood_rules(self, vlan, command):
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

    def build_flood_rules(self, vlan, modify=False):
        """Add flows to flood packets to unknown destinations on a VLAN."""
        # TODO: not all vendors implement groups well.
        # That means we need flood rules for each input port, outputting
        # to all ports except the input port. When all vendors implement
        # groups correctly we can use them.
        command = ofp.OFPFC_ADD
        if modify:
            command = ofp.OFPFC_MODIFY_STRICT
        if self.use_group_table and self.stack is None:
            return self._build_group_flood_rules(vlan, modify, command)
        else:
            return self._build_multiout_flood_rules(vlan, command)
