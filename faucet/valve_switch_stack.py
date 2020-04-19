"""Manage flooding/learning on stacked datapaths."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
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

from collections import defaultdict
from faucet import valve_of
from faucet.valve_switch_standalone import ValveSwitchManager
from faucet.vlan import NullVLAN


class ValveSwitchStackManagerBase(ValveSwitchManager):
    """Base class for dataplane based flooding/learning on stacked dataplanes."""

    # By default, no reflection used for flooding algorithms.
    _USES_REFLECTION = False

    def __init__(self, logger, ports, vlans,  # pylint: disable=too-many-arguments
                 vlan_table, vlan_acl_table, eth_src_table, eth_dst_table, eth_dst_hairpin_table,
                 flood_table, classification_table,
                 pipeline,
                 use_group_table, groups,
                 combinatorial_port_flood, canonical_port_order,
                 restricted_bcast_arpnd, has_externals,
                 learn_ban_timeout, learn_timeout, learn_jitter, cache_update_guard_time, idle_dst,
                 stack_ports, dp_shortest_path_to_root, shortest_path_port,
                 is_stack_root, is_stack_root_candidate,
                 is_stack_edge, graph):
        super(ValveSwitchStackManagerBase, self).__init__(
            logger, ports, vlans,
            vlan_table, vlan_acl_table, eth_src_table, eth_dst_table, eth_dst_hairpin_table,
            flood_table, classification_table,
            pipeline,
            use_group_table, groups,
            combinatorial_port_flood,
            canonical_port_order,
            restricted_bcast_arpnd,
            has_externals,
            learn_ban_timeout,
            learn_timeout,
            learn_jitter,
            cache_update_guard_time,
            idle_dst)
        self.stack_ports = stack_ports
        self.canonical_port_order = canonical_port_order
        self.shortest_path_port = shortest_path_port
        self.dp_shortest_path_to_root = dp_shortest_path_to_root
        self.is_stack_root = is_stack_root
        self.is_stack_root_candidate = is_stack_root_candidate
        self.is_stack_edge = is_stack_edge
        self.graph = graph
        self._set_ext_port_flag = ()
        self._set_nonext_port_flag = ()
        self.external_root_only = False
        if self.has_externals:
            self.logger.info('external ports present, using loop protection')
            self._set_ext_port_flag = (self.flood_table.set_external_forwarding_requested(),)
            self._set_nonext_port_flag = (self.flood_table.set_no_external_forwarding_requested(),)
            if not self.is_stack_root() and self.is_stack_root_candidate():
                self.logger.info('external flooding on root only')
                self.external_root_only = True
        self._reset_peer_distances()

    def _external_forwarding_requested(self, port):
        external_forwarding_requested = None
        if self.has_externals:
            if port.tagged_vlans and port.loop_protect_external:
                external_forwarding_requested = False
            elif not port.stack:
                external_forwarding_requested = True
        return external_forwarding_requested

    def learn_host_intervlan_routing_flows(self, port, vlan, eth_src, eth_dst):
        """Returns flows for the eth_src_table that enable packets that have been
           routed to be accepted from an adjacent DP and then switched to the destination.
           Eth_src_table flow rule to match on port, eth_src, eth_dst and vlan

        Args:
            port (Port): Port to match on.
            vlan (VLAN): VLAN to match on
            eth_src: source MAC address (should be the router MAC)
            eth_dst: destination MAC address
        """
        ofmsgs = []
        (src_rule_idle_timeout, src_rule_hard_timeout, _) = self._learn_host_timeouts(port, eth_src)
        src_match = self.eth_src_table.match(vlan=vlan, eth_src=eth_src, eth_dst=eth_dst)
        src_priority = self.host_priority - 1
        inst = [self.eth_src_table.goto(self.output_table)]
        ofmsgs.extend([self.eth_src_table.flowmod(
            match=src_match,
            priority=src_priority,
            inst=inst,
            hard_timeout=src_rule_hard_timeout,
            idle_timeout=src_rule_idle_timeout)])
        return ofmsgs

    def _build_flood_acts_for_port(self, vlan, exclude_unicast, port,  # pylint: disable=too-many-arguments
                                   exclude_all_external=False,
                                   exclude_restricted_bcast_arpnd=False):
        if self.external_root_only:
            exclude_all_external = True
        return super(ValveSwitchStackManagerBase, self)._build_flood_acts_for_port(
            vlan, exclude_unicast, port,
            exclude_all_external=exclude_all_external,
            exclude_restricted_bcast_arpnd=exclude_restricted_bcast_arpnd)

    def _flood_actions(self, in_port, external_ports,
                       away_flood_actions, toward_flood_actions, local_flood_actions):
        raise NotImplementedError

    def _reset_peer_distances(self):
        """Reset distances to/from root for this DP."""
        self.all_towards_root_stack_ports = set()
        self.towards_root_stack_ports = set()
        self.away_from_root_stack_ports = set()
        all_peer_ports = set(self._canonical_stack_up_ports(self.stack_ports))

        if self.is_stack_root():
            self.away_from_root_stack_ports = all_peer_ports
        else:
            port_peer_distances = {
                port: len(port.stack['dp'].shortest_path_to_root()) for port in all_peer_ports}
            shortest_peer_distance = None
            for port, port_peer_distance in port_peer_distances.items():
                if shortest_peer_distance is None:
                    shortest_peer_distance = port_peer_distance
                    continue
                shortest_peer_distance = min(shortest_peer_distance, port_peer_distance)
            self.all_towards_root_stack_ports = {
                port for port, port_peer_distance in port_peer_distances.items()
                if port_peer_distance == shortest_peer_distance}
            if self.all_towards_root_stack_ports:
                # Choose the port that is the chosen shortest path towards the root
                shortest_path = self.dp_shortest_path_to_root()
                if shortest_path and len(shortest_path) > 1:
                    first_peer_dp = self.dp_shortest_path_to_root()[1]
                else:
                    first_peer_port = self.canonical_port_order(
                        self.all_towards_root_stack_ports)[0]
                    first_peer_dp = first_peer_port.stack['dp'].name
                self.towards_root_stack_ports = {
                    port for port in self.all_towards_root_stack_ports
                    if port.stack['dp'].name == first_peer_dp}
            self.away_from_root_stack_ports = all_peer_ports - self.all_towards_root_stack_ports
            if self.towards_root_stack_ports:
                self.logger.info(
                    'shortest path to root is via %s' % self.towards_root_stack_ports)
            else:
                self.logger.info('no path available to root')

    def _build_flood_rule_actions(self, vlan, exclude_unicast, in_port,
                                  exclude_all_external=False, exclude_restricted_bcast_arpnd=False):
        exclude_ports = self._inactive_away_stack_ports()
        external_ports = vlan.loop_protect_external_ports()

        if in_port and in_port in self.stack_ports:
            in_port_peer_dp = in_port.stack['dp']
            exclude_ports = exclude_ports + [
                port for port in self.stack_ports
                if port.stack['dp'] == in_port_peer_dp]
        local_flood_actions = tuple(self._build_flood_local_rule_actions(
            vlan, exclude_unicast, in_port, exclude_all_external, exclude_restricted_bcast_arpnd))
        away_flood_actions = tuple(valve_of.flood_tagged_port_outputs(
            self.away_from_root_stack_ports, in_port, exclude_ports=exclude_ports))
        toward_flood_actions = tuple(valve_of.flood_tagged_port_outputs(
            self.towards_root_stack_ports, in_port))
        flood_acts = self._flood_actions(
            in_port, external_ports, away_flood_actions,
            toward_flood_actions, local_flood_actions)
        return flood_acts

    def _inactive_away_stack_ports(self):
        all_peer_ports = set(self._canonical_stack_up_ports(self.stack_ports))
        shortest_path = self.dp_shortest_path_to_root()
        if not shortest_path or len(shortest_path) < 2:
            return []
        self_dp = shortest_path[0]
        inactive = []
        for port in all_peer_ports:
            shortest_path = port.stack['dp'].shortest_path_to_root()
            if len(shortest_path) > 1 and shortest_path[1] != self_dp:
                inactive.append(port)
        return inactive

    def _canonical_stack_up_ports(self, ports):
        return self.canonical_port_order([port for port in ports if port.is_stack_up()])

    def _build_mask_flood_rules(self, vlan, eth_type, eth_dst, eth_dst_mask,  # pylint: disable=too-many-arguments
                                exclude_unicast, exclude_restricted_bcast_arpnd, command):
        # Stack ports aren't in VLANs, so need special rules to cause flooding from them.
        ofmsgs = super(ValveSwitchStackManagerBase, self)._build_mask_flood_rules(
            vlan, eth_type, eth_dst, eth_dst_mask,
            exclude_unicast, exclude_restricted_bcast_arpnd, command)
        away_up_ports_by_dp = defaultdict(list)
        for port in self._canonical_stack_up_ports(self.away_from_root_stack_ports):
            away_up_ports_by_dp[port.stack['dp']].append(port)
        towards_up_port = None
        towards_up_ports = self._canonical_stack_up_ports(self.towards_root_stack_ports)
        if towards_up_ports:
            towards_up_port = towards_up_ports[0]
        replace_priority_offset = (
            self.classification_offset - (
                self.pipeline.filter_priority - self.pipeline.select_priority))

        for port in self.stack_ports:
            remote_dp = port.stack['dp']
            away_up_port = None
            away_up_ports = away_up_ports_by_dp.get(remote_dp, None)
            if away_up_ports:
                # Pick the lowest port number on the remote DP.
                remote_away_ports = self.canonical_port_order(
                    [away_port.stack['port'] for away_port in away_up_ports])
                away_up_port = remote_away_ports[0].stack['port']
            away_port = port in self.away_from_root_stack_ports
            towards_port = not away_port
            flood_acts = []

            match = {'in_port': port.number, 'vlan': vlan}
            if eth_dst is not None:
                match.update({'eth_dst': eth_dst, 'eth_dst_mask': eth_dst_mask})
                # Prune broadcast flooding where multiply connected to same DP
                if towards_port:
                    prune = port != towards_up_port
                else:
                    prune = port != away_up_port
            else:
                # Do not prune unicast, may be reply from directly connected DP.
                prune = False

            priority_offset = replace_priority_offset
            if eth_dst is None:
                priority_offset -= 1
            if prune:
                # Allow the prune rule to be replaced with OF strict matching if
                # this port is unpruned later.
                ofmsgs.extend(self.pipeline.filter_packets(
                    match, priority_offset=priority_offset))
            else:
                ofmsgs.extend(self.pipeline.remove_filter(
                    match, priority_offset=priority_offset))
                # Control learning from multicast/broadcast on non-root DPs.
                if not self.is_stack_root() and eth_dst is not None and self._USES_REFLECTION:
                    # If ths is an edge DP, we don't have to learn from
                    # hosts that only broadcast.  If we're an intermediate
                    # DP, only learn from broadcasts further away from
                    # the root (and ignore the reflected broadcast for
                    # learning purposes).
                    if self.is_stack_edge() or towards_port:
                        ofmsgs.extend(self.pipeline.select_packets(
                            self.flood_table, match,
                            priority_offset=self.classification_offset))

            if self.has_externals:
                # If external flag is set, flood to external ports, otherwise exclude them.
                for ext_port_flag, exclude_all_external in (
                        (valve_of.PCP_NONEXT_PORT_FLAG, True),
                        (valve_of.PCP_EXT_PORT_FLAG, False)):
                    if not prune:
                        flood_acts, _, _ = self._build_flood_acts_for_port(
                            vlan, exclude_unicast, port,
                            exclude_all_external=exclude_all_external,
                            exclude_restricted_bcast_arpnd=exclude_restricted_bcast_arpnd)
                    port_flood_ofmsg = self._build_flood_rule_for_port(
                        vlan, eth_type, eth_dst, eth_dst_mask, command, port, flood_acts,
                        add_match={valve_of.EXTERNAL_FORWARDING_FIELD: ext_port_flag})
                    ofmsgs.append(port_flood_ofmsg)
            else:
                if not prune:
                    flood_acts, _, _ = self._build_flood_acts_for_port(
                        vlan, exclude_unicast, port,
                        exclude_restricted_bcast_arpnd=exclude_restricted_bcast_arpnd)
                port_flood_ofmsg = self._build_flood_rule_for_port(
                    vlan, eth_type, eth_dst, eth_dst_mask, command, port, flood_acts)
                ofmsgs.append(port_flood_ofmsg)

        return ofmsgs

    def update_stack_topo(self, event, dp, port):
        """Update the stack topo according to the event."""

        if self.graph is None:
            return

        if event:
            dp.add_stack_link(self.graph, dp, port)
        else:
            dp.remove_stack_link(self.graph, dp, port)

        self._reset_peer_distances()

    def shortest_path_root(self, edge_dp_name):
        """Return the port along the shortest path to/from root for edge learning"""
        path_to_root = self.dp_shortest_path_to_root()
        if not path_to_root:
            return self.shortest_path_port(edge_dp_name)

        this_dp = path_to_root[0]
        path_from_edge = self.dp_shortest_path_to_root(edge_dp_name)

        # If this is the edge switch, then learn using default algorithm.
        if not path_from_edge or this_dp == path_from_edge[0]:
            return self.shortest_path_port(edge_dp_name)

        # If this switch is along the path towards the edge, then head away.
        if this_dp in path_from_edge:
            away_dp = path_from_edge[path_from_edge.index(this_dp) - 1]
            all_away_up_ports = self._canonical_stack_up_ports(self.away_from_root_stack_ports)
            away_up_ports = [port for port in all_away_up_ports if port.stack['dp'].name == away_dp]
            return away_up_ports[0] if away_up_ports else None

        # If not, then head towards the root.
        towards_up_ports = self._canonical_stack_up_ports(self.towards_root_stack_ports)
        return towards_up_ports[0] if towards_up_ports else None

    def _edge_learn_port_towards(self, pkt_meta, edge_dp):
        if pkt_meta.vlan.edge_learn_stack_root:
            return self.shortest_path_root(edge_dp.name)
        return self.shortest_path_port(edge_dp.name)

    def edge_learn_port(self, other_valves, pkt_meta):
        """
        Find a port towards the edge DP where the packet originated from

        Args:
            other_valves (list): All Valves other than this one.
            pkt_meta (PacketMeta): PacketMeta instance for packet received.
        Returns:
            port to learn host on, or None.
        """
        # Got a packet from another DP.
        if pkt_meta.port.stack:
            edge_dp = self._edge_dp_for_host(other_valves, pkt_meta)
            if edge_dp:
                return self._edge_learn_port_towards(pkt_meta, edge_dp)
            # Assuming no DP has learned this host.
            return None

        # Got a packet locally.
        # If learning on an external port, check another DP hasn't
        # already learned on a local/non-external port.
        if pkt_meta.port.loop_protect_external:
            edge_dp = self._non_stack_learned(other_valves, pkt_meta)
            if edge_dp:
                return self._edge_learn_port_towards(pkt_meta, edge_dp)
        # Locally learn.
        return super(ValveSwitchStackManagerBase, self).edge_learn_port(
            other_valves, pkt_meta)

    def _edge_dp_for_host(self, other_valves, pkt_meta):
        """Simple distributed unicast learning.

        Args:
            other_valves (list): All Valves other than this one.
            pkt_meta (PacketMeta): PacketMeta instance for packet received.
        Returns:
            Valve instance or None (of edge datapath where packet received)
        """
        raise NotImplementedError

    def _non_stack_learned(self, other_valves, pkt_meta):
        other_local_dp_entries = []
        other_external_dp_entries = []
        vlan_vid = pkt_meta.vlan.vid
        for other_valve in other_valves:
            other_dp_vlan = other_valve.dp.vlans.get(vlan_vid, None)
            if other_dp_vlan is not None:
                entry = other_dp_vlan.cached_host(pkt_meta.eth_src)
                if not entry:
                    continue
                if not entry.port.non_stack_forwarding():
                    continue
                if entry.port.loop_protect_external:
                    other_external_dp_entries.append(other_valve.dp)
                else:
                    other_local_dp_entries.append(other_valve.dp)
        # Another DP has learned locally, has priority.
        if other_local_dp_entries:
            return other_local_dp_entries[0]
        # No other DP has learned locally, but at least one has learned externally.
        if other_external_dp_entries:
            entry = pkt_meta.vlan.cached_host(pkt_meta.eth_src)
            # This DP has not learned the host either, use other's external.
            if entry is None:
                return other_external_dp_entries[0]
        return None

    def _stack_flood_ports(self):
        """Return output ports of a DP that have been pruned and follow reflection rules"""
        # TODO: Consolidate stack port selection logic,
        #           this reuses logic from _build_mask_flood_rules()
        away_flood_ports = []
        towards_flood_ports = []
        # Obtain away ports
        away_up_ports_by_dp = defaultdict(list)
        for port in self._canonical_stack_up_ports(self.away_from_root_stack_ports):
            away_up_ports_by_dp[port.stack['dp']].append(port)
        # Obtain the towards root path port (this is the designated root port)
        towards_up_port = None
        towards_up_ports = self._canonical_stack_up_ports(self.towards_root_stack_ports)
        if towards_up_ports:
            towards_up_port = towards_up_ports[0]
        # Figure out what stack ports will need to be flooded
        for port in self.stack_ports:
            remote_dp = port.stack['dp']
            away_up_port = None
            away_up_ports = away_up_ports_by_dp.get(remote_dp, None)
            if away_up_ports:
                # Pick the lowest port number on the remote DP.
                remote_away_ports = self.canonical_port_order(
                    [away_port.stack['port'] for away_port in away_up_ports])
                away_up_port = remote_away_ports[0].stack['port']
            # Is the port to an away DP, (away from the stack root)
            away_port = port in self.away_from_root_stack_ports
            # Otherwise it is towards the stack root
            towards_port = not away_port

            # Prune == True for ports that do not need to be flooded
            if towards_port:
                # If towards the stack root, then if the port is not the chosen
                #   root path port, then we do not need to flood to it
                prune = port != towards_up_port
                if not prune and not self.is_stack_root():
                    # Port is chosen towards port and not the root so flood
                    #   towards the root
                    towards_flood_ports.append(port)
            else:
                # If away from stack root, then if the port is not the chosen
                #   away port for that DP, we do not need to flood to it
                prune = port != away_up_port
                if not prune and self.is_stack_root():
                    # Port is chosen away port and the root switch
                    #   so flood away from the root
                    away_flood_ports.append(port)

        # Also need to turn off inactive away ports (for DPs that have a better way to get to root)
        exclude_ports = self._inactive_away_stack_ports()
        away_flood_ports = [port for port in away_flood_ports if port not in exclude_ports]
        return towards_flood_ports + away_flood_ports

    def add_port(self, port):
        ofmsgs = super(ValveSwitchStackManagerBase, self).add_port(port)
        # If this is a stacking port, accept all VLANs (came from another FAUCET)
        if port.stack:
            # Actual stack traffic will have VLAN tags.
            ofmsgs.append(self.vlan_table.flowdrop(
                match=self.vlan_table.match(
                    in_port=port.number,
                    vlan=NullVLAN()),
                priority=self.low_priority+1))
            ofmsgs.append(self.vlan_table.flowmod(
                match=self.vlan_table.match(in_port=port.number),
                priority=self.low_priority,
                inst=self.pipeline.accept_to_classification()))
        return ofmsgs

    def del_port(self, port):
        ofmsgs = super(ValveSwitchStackManagerBase, self).del_port(port)
        if port.stack:
            for vlan in self.vlans.values():
                vlan.clear_cache_hosts_on_port(port)
        return ofmsgs


class ValveSwitchStackManagerNoReflection(ValveSwitchStackManagerBase):
    """Stacks of size 2 - all switches directly connected to root.

    Root switch simply floods to all other switches.

    Non-root switches simply flood to the root.
    """

    def _flood_actions(self, in_port, external_ports,
                       away_flood_actions, toward_flood_actions, local_flood_actions):
        if not in_port or in_port in self.stack_ports:
            flood_prefix = ()
        else:
            if external_ports:
                flood_prefix = self._set_nonext_port_flag
            else:
                flood_prefix = self._set_ext_port_flag

        flood_actions = (
            flood_prefix + toward_flood_actions + away_flood_actions + local_flood_actions)

        return flood_actions

    def _edge_dp_for_host(self, other_valves, pkt_meta):
        """Size 2 means root shortest path is always directly connected."""
        peer_dp = pkt_meta.port.stack['dp']
        if peer_dp.dyn_running:
            return self._non_stack_learned(other_valves, pkt_meta)
        # Fall back to assuming peer knows if we are not the peer's controller.
        return peer_dp


class ValveSwitchStackManagerReflection(ValveSwitchStackManagerBase):
    """Stacks size > 2 reflect floods off of root (selective flooding).

       .. code-block:: none

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
       reflects incoming floods back out. Non-root switches flood
       packets from the root locally and to switches further away
       from the root. Flooding is entirely implemented in the dataplane.

       A host connected to a non-root switch can receive a copy of its
       own flooded packet (because the non-root switch does not know
       it has seen the packet already).

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

    # Indicate to base class use of reflection required.
    _USES_REFLECTION = True

    def _learn_cache_check(self, entry, vlan, now, eth_src, port, ofmsgs,  # pylint: disable=unused-argument
                           cache_port, cache_age,
                           delete_existing, refresh_rules):
        learn_exit = False
        update_cache = True
        if cache_port is not None:
            # packet was received on same member of a LAG.
            same_lag = (port.lacp and port.lacp == cache_port.lacp)
            # stacks of size > 2 will have an unknown MAC flooded towards the root,
            # and flooded down again. If we learned the MAC on a local port and
            # heard the reflected flooded copy, discard the reflection.
            local_stack_learn = port.stack and not cache_port.stack
            guard_time = self.cache_update_guard_time
            if cache_port == port or same_lag or local_stack_learn:
                # aggressively re-learn on LAGs, and prefer recently learned
                # locally learned hosts on a stack.
                if same_lag or local_stack_learn:
                    guard_time = 2
                # port didn't change status, and recent cache update, don't do anything.
                if (cache_age < guard_time and
                        port.dyn_update_time is not None and
                        port.dyn_update_time <= entry.cache_time):
                    update_cache = False
                    learn_exit = True
                # skip delete if host didn't change ports or on same LAG.
                elif cache_port == port or same_lag:
                    delete_existing = False
                    refresh_rules = True
        return (learn_exit, ofmsgs, cache_port, update_cache, delete_existing, refresh_rules)

    def _flood_actions(self, in_port, external_ports,
                       away_flood_actions, toward_flood_actions, local_flood_actions):
        if self.is_stack_root():
            if external_ports:
                flood_prefix = self._set_nonext_port_flag
            else:
                flood_prefix = self._set_ext_port_flag
            flood_actions = (away_flood_actions + local_flood_actions)

            if in_port and in_port in self.away_from_root_stack_ports:
                # Packet from a non-root switch, flood locally and to all non-root switches
                # (reflect it).
                flood_actions = (
                    away_flood_actions + (valve_of.output_in_port(),) + local_flood_actions)

            flood_actions = flood_prefix + flood_actions
        else:
            # Default non-root strategy is flood towards root.
            if external_ports:
                flood_actions = self._set_nonext_port_flag + toward_flood_actions
            else:
                flood_actions = self._set_ext_port_flag + toward_flood_actions

            if in_port:
                # Packet from switch further away, flood it to the root.
                if in_port in self.away_from_root_stack_ports:
                    flood_actions = toward_flood_actions
                # Packet from the root.
                elif in_port in self.all_towards_root_stack_ports:
                    # If we have external ports, and packet hasn't already been flooded
                    # externally, flood it externally before passing it to further away switches,
                    # and mark it flooded.
                    if external_ports:
                        flood_actions = (
                            self._set_nonext_port_flag + away_flood_actions + local_flood_actions)
                    else:
                        flood_actions = (
                            away_flood_actions + self._set_nonext_port_flag + local_flood_actions)
                # Packet from external port, locally. Mark it already flooded externally and
                # flood to root (it came from an external switch so keep it within the stack).
                elif in_port.loop_protect_external:
                    flood_actions = self._set_nonext_port_flag + toward_flood_actions
                else:
                    flood_actions = self._set_ext_port_flag + toward_flood_actions

        return flood_actions

    def _edge_dp_for_host(self, other_valves, pkt_meta):
        """For stacks size > 2."""
        # TODO: currently requires controller to manage all switches
        # in the stack to keep each DP's graph consistent.
        # TODO: simplest possible unicast learning.
        # We find just one port that is the shortest unicast path to
        # the destination. We could use other factors (eg we could
        # load balance over multiple ports based on destination MAC).
        # Find port that forwards closer to destination DP that
        # has already learned this host (if any).
        peer_dp = pkt_meta.port.stack['dp']
        if peer_dp.dyn_running:
            return self._non_stack_learned(other_valves, pkt_meta)
        # Fall back to peer knows if edge or root if we are not the peer's controller.
        if peer_dp.is_stack_edge() or peer_dp.is_stack_root():
            return peer_dp
        # No DP has learned this host, yet. Take no action to allow remote learning to occur.
        return None
