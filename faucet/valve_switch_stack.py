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

import copy

from faucet import valve_of
from faucet.valve_switch_standalone import ValveSwitchManager
from faucet.vlan import NullVLAN


class ValveSwitchStackManagerBase(ValveSwitchManager):
    """Base class for dataplane based flooding/learning on stacked dataplanes."""

    # By default, no reflection used for flooding algorithms.
    _USES_REFLECTION = False

    def __init__(self, stack_manager, **kwargs):
        super().__init__(**kwargs)

        self.stack_manager = stack_manager

        self._set_ext_port_flag = ()
        self._set_nonext_port_flag = ()
        self.external_root_only = False
        if self.has_externals:
            self.logger.info('external ports present, using loop protection')
            self._set_ext_port_flag = (self.flood_table.set_external_forwarding_requested(),)
            self._set_nonext_port_flag = (self.flood_table.set_no_external_forwarding_requested(),)
            if (not self.stack_manager.stack.is_root() and
                    self.stack_manager.stack.is_root_candidate()):
                self.logger.info('external flooding on root only')
                self.external_root_only = True

    @staticmethod
    def _non_stack_learned(other_valves, pkt_meta):
        """
        Obtain DP that has learnt the host that sent the packet

        Args:
            other_valves (list): Other valves
            pkt_meta (PacketMeta): Packet meta sent by the host
        Returns:
            DP: DP that has learnt the host
        """
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

    def _external_forwarding_requested(self, port):
        external_forwarding_requested = None
        if self.has_externals:
            if port.tagged_vlans and port.loop_protect_external:
                external_forwarding_requested = False
            elif not port.stack:
                external_forwarding_requested = True
        return external_forwarding_requested

    def _build_flood_acts_for_port(self, vlan, exclude_unicast, port,  # pylint: disable=too-many-arguments
                                   exclude_all_external=False,
                                   exclude_restricted_bcast_arpnd=False):
        if self.external_root_only:
            exclude_all_external = True
        return super()._build_flood_acts_for_port(
            vlan, exclude_unicast, port,
            exclude_all_external=exclude_all_external,
            exclude_restricted_bcast_arpnd=exclude_restricted_bcast_arpnd)

    def _flood_actions(self, in_port, external_ports,  # pylint: disable=too-many-arguments
                       away_flood_actions, toward_flood_actions, local_flood_actions):
        raise NotImplementedError

    def _build_flood_rule_actions(self, vlan, exclude_unicast, in_port,  # pylint: disable=too-many-arguments
                                  exclude_all_external=False, exclude_restricted_bcast_arpnd=False):
        """Compiles all the possible flood rule actions for a port on a stack node"""
        exclude_ports = list(self.stack_manager.inactive_away_ports)
        external_ports = vlan.loop_protect_external_ports()
        if in_port and self.stack_manager.is_stack_port(in_port):
            in_port_peer_dp = in_port.stack['dp']
            exclude_ports = exclude_ports + self.stack_manager.adjacent_stack_ports(in_port_peer_dp)
        local_flood_actions = tuple(self._build_flood_local_rule_actions(
            vlan, exclude_unicast, in_port, exclude_all_external, exclude_restricted_bcast_arpnd))
        away_flood_actions = tuple(valve_of.flood_tagged_port_outputs(
            self.stack_manager.away_ports, in_port, exclude_ports=exclude_ports))
        toward_flood_actions = tuple(valve_of.flood_tagged_port_outputs(
            self.stack_manager.chosen_towards_ports, in_port))
        flood_acts = self._flood_actions(
            in_port, external_ports, away_flood_actions,
            toward_flood_actions, local_flood_actions)
        return flood_acts

    def _build_mask_flood_rules_filters(self, port, vlan, eth_dst, eth_dst_mask, prune):
        """Builds filter for the input table to filter packets on ports that are pruned"""
        ofmsgs = []

        match = {'in_port': port.number, 'vlan': vlan}
        if eth_dst is not None:
            match.update({'eth_dst': eth_dst, 'eth_dst_mask': eth_dst_mask})

        replace_priority_offset = (self.classification_offset - (
            self.pipeline.filter_priority - self.pipeline.select_priority))

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
            if (not self.stack_manager.stack.is_root() and
                    eth_dst is not None and self._USES_REFLECTION):
                # If this is an edge DP, we don't have to learn from
                # hosts that only broadcast.  If we're an intermediate
                # DP, only learn from broadcasts further away from
                # the root (and ignore the reflected broadcast for
                # learning purposes).
                if self.stack_manager.stack.is_edge() or self.stack_manager.is_towards_root(port):
                    ofmsgs.extend(self.pipeline.select_packets(
                        self.flood_table, match,
                        priority_offset=self.classification_offset))
        return ofmsgs

    def _build_mask_flood_rules_flood_acts(self, vlan, eth_type, eth_dst, eth_dst_mask,
                                           exclude_unicast, exclude_restricted_bcast_arpnd,
                                           command, cold_start, prune, port):
        """Builds the flood rules for the flood table to forward packets along the stack topology"""
        ofmsgs = []
        flood_acts = []
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

    def _build_mask_flood_rules(self, vlan, eth_type, eth_dst, eth_dst_mask,  # pylint: disable=too-many-arguments
                                exclude_unicast, exclude_restricted_bcast_arpnd,
                                command, cold_start):
        """Builds that flood rules for each mask for each port in the stack.
        This takes into account the pruned and non-pruned ports and returns
            the appropriate flood rule actions"""
        # Stack ports aren't in VLANs, so need special rules to cause flooding from them.
        ofmsgs = super()._build_mask_flood_rules(
            vlan, eth_type, eth_dst, eth_dst_mask,
            exclude_unicast, exclude_restricted_bcast_arpnd,
            command, cold_start)

        for port in self.stack_manager.stack_ports():

            if eth_dst is not None:
                # Prune broadcast flooding where multiply connected to same DP
                prune = self.stack_manager.is_pruned_port(port)
            else:
                # Do not prune unicast, may be reply from directly connected DP.
                prune = False

            ofmsgs.extend(self._build_mask_flood_rules_filters(
                port, vlan, eth_dst, eth_dst_mask, prune))
            ofmsgs.extend(self._build_mask_flood_rules_flood_acts(
                vlan, eth_type, eth_dst, eth_dst_mask,
                exclude_unicast, exclude_restricted_bcast_arpnd,
                command, cold_start, prune, port))

        return ofmsgs

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
            # Received packet from
            edge_dp = self._edge_dp_for_host(other_valves, pkt_meta)
            if edge_dp:
                return self.stack_manager.edge_learn_port_towards(pkt_meta, edge_dp)
            # Assuming no DP has learned this host.
            return None

        # Got a packet locally.
        # If learning on an external port, check another DP hasn't
        # already learned on a local/non-external port.
        if pkt_meta.port.loop_protect_external:
            edge_dp = self._non_stack_learned(other_valves, pkt_meta)
            if edge_dp:
                return self.stack_manager.edge_learn_port_towards(pkt_meta, edge_dp)
        # Locally learn.
        return super().edge_learn_port(
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

    def add_drop_spoofed_faucet_mac_rules(self, vlan):
        """Install rules to drop spoofed faucet mac"""
        # antispoof for FAUCET's MAC address
        # TODO: antispoof for controller IPs on this VLAN, too.
        ofmsgs = []
        if self.drop_spoofed_faucet_mac:
            for port in self.ports.values():
                if not port.stack:
                    ofmsgs.extend(self.pipeline.filter_packets(
                        {'eth_src': vlan.faucet_mac, 'in_port': port.number}))
        return ofmsgs

    def add_port(self, port):
        ofmsgs = super().add_port(port)
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
        ofmsgs = super().del_port(port)
        if port.stack:
            for vlan in self.vlans.values():
                vlan.clear_cache_hosts_on_port(port)
            ofmsgs.extend(self._del_host_flows(port))
        return ofmsgs

    def get_lacp_dpid_nomination(self, lacp_id, valve, other_valves):
        """Chooses the DP for a given LAG.

        The DP will be nominated by the following conditions in order:
            1) Number of LAG ports
            2) Root DP
            3) Lowest DPID

        Args:
            lacp_id: The LACP LAG ID
            other_valves (list): list of other valves
        Returns:
            nominated_dpid, reason
        """
        if not other_valves:
            return None, ''
        stacked_other_valves = self.stack_manager.stacked_valves(other_valves)
        all_stacked_valves = {valve}.union(stacked_other_valves)
        ports = {}
        no_sync_ports = {}
        root_dpid = None
        for stack_valve in all_stacked_valves:
            all_lags = stack_valve.dp.lags_up()
            if lacp_id in all_lags:
                ports[stack_valve.dp.dp_id] = len(all_lags[lacp_id])
            nosync_lags = stack_valve.dp.lags_nosync()
            for lacp_id in nosync_lags:
                ports.setdefault(stack_valve.dp.dp_id, 0)
                no_sync_ports[stack_valve.dp.dp_id] = len(nosync_lags.get(lacp_id, 0))
            if stack_valve.dp.stack.is_root():
                root_dpid = stack_valve.dp.dp_id
        # Order by number of ports
        port_order = sorted(ports,
                            key=lambda port: (ports.get(port, 0), no_sync_ports.get(port, 0)),
                            reverse=True)
        if not port_order:
            return None, ''
        most_ports_dpid = port_order[0]
        most_ports_dpids = [dpid for dpid, num in ports.items() if num == ports[most_ports_dpid]]
        if len(most_ports_dpids) > 1:
            # There are several dpids that have the same number of lags
            if root_dpid in most_ports_dpids:
                # root_dpid is the chosen DPID
                return root_dpid, 'root dp'
            # Order by lowest DPID
            return sorted(most_ports_dpids), 'lowest dpid'
        # Most_ports_dpid is the chosen DPID
        return most_ports_dpid, 'most LAG ports'

    def _learn_host_intervlan_routing_flows(self, port, vlan, eth_src, eth_dst):
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
        inst = (self.eth_src_table.goto(self.output_table),)
        ofmsgs.extend([self.eth_src_table.flowmod(
            match=src_match,
            priority=src_priority,
            inst=inst,
            hard_timeout=src_rule_hard_timeout,
            idle_timeout=src_rule_idle_timeout)])
        return ofmsgs

    def _valve_learn_host_from_pkt(self, valve, now, pkt_meta, other_valves):
        """Add L3 forwarding rule if necessary for inter-VLAN routing."""
        ofmsgs_by_valve = super().learn_host_from_pkt(
            valve, now, pkt_meta, other_valves)
        if self.stack_manager.stack.route_learning and not self.stack_manager.stack.is_root():
            if pkt_meta.eth_src == pkt_meta.vlan.faucet_mac:
                ofmsgs_by_valve[valve].extend(self._learn_host_intervlan_routing_flows(
                    pkt_meta.port, pkt_meta.vlan, pkt_meta.eth_src, pkt_meta.eth_dst))
            elif pkt_meta.eth_dst == pkt_meta.vlan.faucet_mac:
                ofmsgs_by_valve[valve].extend(self._learn_host_intervlan_routing_flows(
                    pkt_meta.port, pkt_meta.vlan, pkt_meta.eth_dst, pkt_meta.eth_src))
        return ofmsgs_by_valve

    def learn_host_from_pkt(self, valve, now, pkt_meta, other_valves):
        ofmsgs_by_valve = {}

        if self.stack_manager.stack.route_learning:
            stacked_other_valves = self.stack_manager.stacked_valves(other_valves)
            all_stacked_valves = {valve}.union(stacked_other_valves)

            # NOTE: multi DP routing requires learning from directly attached switch first.
            if pkt_meta.port.stack:
                peer_dp = pkt_meta.port.stack['dp']
                if peer_dp.dyn_running:
                    faucet_macs = {pkt_meta.vlan.faucet_mac}.union(
                        {valve.dp.faucet_dp_mac for valve in all_stacked_valves})
                    # Must always learn FAUCET VIP, but rely on neighbor
                    # to learn other hosts first.
                    if pkt_meta.eth_src not in faucet_macs:
                        return ofmsgs_by_valve

            for other_valve in stacked_other_valves:
                stack_port = other_valve.stack_manager.relative_port_towards(
                    self.stack_manager.stack.name)
                valve_vlan = other_valve.dp.vlans.get(pkt_meta.vlan.vid, None)
                if stack_port and valve_vlan:
                    valve_pkt_meta = copy.copy(pkt_meta)
                    valve_pkt_meta.vlan = valve_vlan
                    valve_pkt_meta.port = stack_port
                    valve_other_valves = all_stacked_valves - {other_valve}
                    ofmsgs_by_valve.update(self._valve_learn_host_from_pkt(
                        other_valve, now, valve_pkt_meta, valve_other_valves))

        ofmsgs_by_valve.update(
            self._valve_learn_host_from_pkt(valve, now, pkt_meta, other_valves))
        return ofmsgs_by_valve


class ValveSwitchStackManagerNoReflection(ValveSwitchStackManagerBase):
    """Stacks of size 2 - all switches directly connected to root.

    Root switch simply floods to all other switches.

    Non-root switches simply flood to the root.
    """

    def _flood_actions(self, in_port, external_ports,  # pylint: disable=too-many-arguments
                       away_flood_actions, toward_flood_actions, local_flood_actions):
        if not in_port or self.stack_manager.is_stack_port(in_port):
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
                port_cache_valid = (
                    port.dyn_update_time is not None and port.dyn_update_time <= entry.cache_time)
                # aggressively re-learn on LAGs, and prefer recently learned
                # locally learned hosts on a stack.
                if same_lag or local_stack_learn:
                    guard_time = 2
                # port didn't change status, and recent cache update, don't do anything.
                if cache_age < guard_time and port_cache_valid:
                    update_cache = False
                    learn_exit = True
                # skip delete if host didn't change ports or on same LAG.
                elif cache_port == port or same_lag:
                    delete_existing = False
                    if port_cache_valid:
                        refresh_rules = True
        return (learn_exit, ofmsgs, cache_port, update_cache, delete_existing, refresh_rules)

    def _flood_actions(self, in_port, external_ports,  # pylint: disable=too-many-arguments
                       away_flood_actions, toward_flood_actions, local_flood_actions):
        if self.stack_manager.stack.is_root():
            if external_ports:
                flood_prefix = self._set_nonext_port_flag
            else:
                flood_prefix = self._set_ext_port_flag
            flood_actions = (away_flood_actions + local_flood_actions)

            if in_port and self.stack_manager.is_away(in_port):
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
                if self.stack_manager.is_away(in_port):
                    flood_actions = toward_flood_actions
                # Packet from the root.
                elif self.stack_manager.is_towards_root(in_port):
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
        if peer_dp.stack.is_edge() or peer_dp.stack.is_root():
            return peer_dp
        # No DP has learned this host, yet. Take no action to allow remote learning to occur.
        return None
