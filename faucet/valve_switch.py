"""Manage flooding to ports on VLANs."""

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

import functools
from collections import defaultdict

from faucet import valve_of
from faucet import valve_packet
from faucet.valve_manager_base import ValveManagerBase


class ValveHostManager(ValveManagerBase):
    """Manage host learning on VLANs."""

    def __init__(self, logger, ports, vlans, eth_src_table, eth_dst_table,
                 eth_dst_hairpin_table, pipeline, learn_timeout, learn_jitter,
                 learn_ban_timeout, cache_update_guard_time, idle_dst, stack_graph,
                 has_externals, stack_root_flood_reflection):
        self.logger = logger
        self.ports = ports
        self.vlans = vlans
        self.eth_src_table = eth_src_table
        self.eth_dst_table = eth_dst_table
        self.eth_dst_hairpin_table = eth_dst_hairpin_table
        self.pipeline = pipeline
        self.learn_timeout = learn_timeout
        self.learn_jitter = learn_jitter
        self.learn_ban_timeout = learn_ban_timeout
        self.low_priority = self._LOW_PRIORITY
        self.host_priority = self._MATCH_PRIORITY
        self.high_priority = self._HIGH_PRIORITY
        self.cache_update_guard_time = cache_update_guard_time
        self.output_table = self.eth_dst_table
        self.idle_dst = idle_dst
        self.stack_graph = stack_graph
        self.has_externals = has_externals
        self.stack_root_flood_reflection = stack_root_flood_reflection
        if self.eth_dst_hairpin_table:
            self.output_table = self.eth_dst_hairpin_table

    def ban_rules(self, pkt_meta):
        """Limit learning to a maximum configured on this port/VLAN.

        Args:
            pkt_meta: PacketMeta instance.
        Returns:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []

        port = pkt_meta.port
        eth_src = pkt_meta.eth_src
        vlan = pkt_meta.vlan

        entry = vlan.cached_host(eth_src)
        if entry is None:
            if port.max_hosts:
                if port.hosts_count() == port.max_hosts:
                    ofmsgs.append(self._temp_ban_host_learning(
                        self.eth_src_table.match(in_port=port.number)))
                    port.dyn_learn_ban_count += 1
                    self.logger.info(
                        'max hosts %u reached on %s, '
                        'temporarily banning learning on this port, '
                        'and not learning %s' % (
                            port.max_hosts, port, eth_src))
            if vlan is not None and vlan.max_hosts:
                hosts_count = vlan.hosts_count()
                if hosts_count == vlan.max_hosts:
                    ofmsgs.append(self._temp_ban_host_learning(self.eth_src_table.match(vlan=vlan)))
                    vlan.dyn_learn_ban_count += 1
                    self.logger.info(
                        'max hosts %u reached on VLAN %u, '
                        'temporarily banning learning on this VLAN, '
                        'and not learning %s on %s' % (
                            vlan.max_hosts, vlan.vid, eth_src, port))
        return ofmsgs

    def add_port(self, port):
        ofmsgs = []
        if port.coprocessor:
            ofmsgs.append(self.eth_src_table.flowmod(
                match=self.eth_src_table.match(in_port=port.number),
                priority=self.high_priority,
                inst=[self.eth_src_table.goto(self.output_table)]))
        return ofmsgs

    def del_port(self, port):
        ofmsgs = []
        ofmsgs.append(
            self.eth_src_table.flowdel(self.eth_src_table.match(in_port=port.number)))
        for table in (self.eth_dst_table, self.eth_dst_hairpin_table):
            if table:
                # per OF 1.3.5 B.6.23, the OFA will match flows
                # that have an action targeting this port.
                ofmsgs.append(table.flowdel(out_port=port.number))
        vlans = port.vlans()
        if port.stack:
            vlans = self.vlans.values()
        for vlan in vlans:
            vlan.clear_cache_hosts_on_port(port)
        return ofmsgs

    def add_vlan(self, vlan):
        ofmsgs = []
        ofmsgs.append(self.eth_src_table.flowcontroller(
            match=self.eth_src_table.match(vlan=vlan),
            priority=self.low_priority,
            inst=[self.eth_src_table.goto(self.output_table)]))
        return ofmsgs

    def _temp_ban_host_learning(self, match):
        return self.eth_src_table.flowdrop(
            match,
            priority=(self.low_priority + 1),
            hard_timeout=self.learn_ban_timeout)

    def delete_host_from_vlan(self, eth_src, vlan):
        """Delete a host from a VLAN."""
        ofmsgs = [self.eth_src_table.flowdel(
            self.eth_src_table.match(vlan=vlan, eth_src=eth_src))]
        for table in (self.eth_dst_table, self.eth_dst_hairpin_table):
            if table:
                ofmsgs.append(table.flowdel(table.match(vlan=vlan, eth_dst=eth_src)))
        return ofmsgs

    def expire_hosts_from_vlan(self, vlan, now):
        """Expire hosts from VLAN cache."""
        expired_hosts = vlan.expire_cache_hosts(now, self.learn_timeout)
        if expired_hosts:
            vlan.dyn_last_time_hosts_expired = now
            self.logger.info(
                '%u recently active hosts on VLAN %u, expired %s' % (
                    vlan.hosts_count(), vlan.vid, expired_hosts))
        return expired_hosts

    def _jitter_learn_timeout(self, base_learn_timeout, port, eth_dst):
        """Calculate jittered learning timeout to avoid synchronized host timeouts."""
        # Hosts on this port never timeout.
        if port.permanent_learn:
            return 0
        if not base_learn_timeout:
            return 0
        # Jitter learn timeout based on eth address, so timeout processing is jittered,
        # the same hosts will timeout approximately the same time on a stack.
        jitter = hash(eth_dst) % self.learn_jitter
        min_learn_timeout = base_learn_timeout - self.learn_jitter
        return int(max(abs(min_learn_timeout + jitter), self.cache_update_guard_time))

    def learn_host_timeouts(self, port, eth_src):
        """Calculate flow timeouts for learning on a port."""
        learn_timeout = self._jitter_learn_timeout(self.learn_timeout, port, eth_src)

        # Update datapath to no longer send packets from this mac to controller
        # note the use of hard_timeout here and idle_timeout for the dst table
        # this is to ensure that the source rules will always be deleted before
        # any rules on the dst table. Otherwise if the dst table rule expires
        # but the src table rule is still being hit intermittantly the switch
        # will flood packets to that dst and not realise it needs to relearn
        # the rule
        # NB: Must be lower than highest priority otherwise it can match
        # flows destined to controller
        src_rule_idle_timeout = 0
        src_rule_hard_timeout = learn_timeout
        dst_rule_idle_timeout = learn_timeout + self.cache_update_guard_time
        if not self.idle_dst:
            dst_rule_idle_timeout = 0
        return (src_rule_idle_timeout, src_rule_hard_timeout, dst_rule_idle_timeout)

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
        (src_rule_idle_timeout, src_rule_hard_timeout, _) = self.learn_host_timeouts(port, eth_src)
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

    def learn_host_on_vlan_port_flows(self, port, vlan, eth_src,
                                      delete_existing, refresh_rules,
                                      src_rule_idle_timeout,
                                      src_rule_hard_timeout,
                                      dst_rule_idle_timeout):
        """Return flows that implement learning a host on a port."""
        ofmsgs = []

        # Delete any existing entries for MAC.
        if delete_existing:
            ofmsgs.extend(self.delete_host_from_vlan(eth_src, vlan))

        # Associate this MAC with source port.
        src_match = self.eth_src_table.match(
            in_port=port.number, vlan=vlan, eth_src=eth_src)
        src_priority = self.host_priority - 1

        inst = []

        inst.append(self.eth_src_table.goto(self.output_table))

        ofmsgs.append(self.eth_src_table.flowmod(
            match=src_match,
            priority=src_priority,
            inst=inst,
            hard_timeout=src_rule_hard_timeout,
            idle_timeout=src_rule_idle_timeout))

        hairpinning = port.hairpin or port.hairpin_unicast
        # If we are refreshing only and not in hairpin mode, leave existing eth_dst alone.
        if refresh_rules and not hairpinning:
            return ofmsgs

        external_forwarding_requested = None
        match_dict = {
            'vlan': vlan, 'eth_dst': eth_src, valve_of.EXTERNAL_FORWARDING_FIELD: None}
        if self.has_externals:
            match_dict.update({
                valve_of.EXTERNAL_FORWARDING_FIELD: valve_of.PCP_EXT_PORT_FLAG})
            if port.tagged_vlans and port.loop_protect_external and self.stack_graph:
                external_forwarding_requested = False
            elif not port.stack:
                external_forwarding_requested = True

        inst = self.pipeline.output(
            port, vlan, external_forwarding_requested=external_forwarding_requested)

        # Output packets for this MAC to specified port.
        ofmsgs.append(self.eth_dst_table.flowmod(
            self.eth_dst_table.match(**match_dict),
            priority=self.host_priority,
            inst=inst,
            idle_timeout=dst_rule_idle_timeout))

        if self.has_externals and not port.loop_protect_external:
            match_dict.update({
                valve_of.EXTERNAL_FORWARDING_FIELD: valve_of.PCP_NONEXT_PORT_FLAG})
            ofmsgs.append(self.eth_dst_table.flowmod(
                self.eth_dst_table.match(**match_dict),
                priority=self.host_priority,
                inst=inst,
                idle_timeout=dst_rule_idle_timeout))

        # If port is in hairpin mode, install a special rule
        # that outputs packets destined to this MAC back out the same
        # port they came in (e.g. multiple hosts on same WiFi AP,
        # and FAUCET is switching between them on the same port).
        if hairpinning:
            ofmsgs.append(self.eth_dst_hairpin_table.flowmod(
                self.eth_dst_hairpin_table.match(in_port=port.number, vlan=vlan, eth_dst=eth_src),
                priority=self.host_priority,
                inst=self.pipeline.output(port, vlan, hairpin=True),
                idle_timeout=dst_rule_idle_timeout))

        return ofmsgs

    def learn_host_on_vlan_ports(self, now, port, vlan, eth_src,
                                 delete_existing=True,
                                 last_dp_coldstart_time=None):
        """Learn a host on a port."""
        ofmsgs = []
        cache_port = None
        cache_age = None
        entry = vlan.cached_host(eth_src)
        refresh_rules = False

        # Host not cached, and no hosts expired since we cold started
        # Enable faster learning by assuming there's no previous host to delete
        if entry is None:
            if (last_dp_coldstart_time and
                    (vlan.dyn_last_time_hosts_expired is None or
                     vlan.dyn_last_time_hosts_expired < last_dp_coldstart_time)):
                delete_existing = False
        elif entry.port.permanent_learn:
            if entry.port != port:
                ofmsgs.extend(self.pipeline.filter_packets(
                    {'eth_src': eth_src, 'in_port': port.number}))
            return (ofmsgs, entry.port, False)
        else:
            cache_age = now - entry.cache_time
            cache_port = entry.port

        if cache_port is not None:
            # packet was received on same member of a LAG.
            same_lag = (port.lacp and port.lacp == cache_port.lacp)
            # stacks of size > 2 will have an unknown MAC flooded towards the root,
            # and flooded down again. If we learned the MAC on a local port and
            # heard the reflected flooded copy, discard the reflection.
            local_stack_learn = (
                self.stack_root_flood_reflection and port.stack and not cache_port.stack)
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
                    return (ofmsgs, cache_port, False)
                # skip delete if host didn't change ports or on same LAG.
                if cache_port == port or same_lag:
                    delete_existing = False
                    refresh_rules = True

        if port.loop_protect:
            ban_age = None
            learn_ban = False

            # if recently in loop protect mode and still receiving packets,
            # prolong the ban
            if port.dyn_last_ban_time:
                ban_age = now - port.dyn_last_ban_time
                if ban_age < self.cache_update_guard_time:
                    learn_ban = True

            # if not in protect mode and we get a rapid move, enact protect mode
            if not learn_ban and entry is not None:
                if port != cache_port and cache_age < self.cache_update_guard_time:
                    learn_ban = True
                    port.dyn_learn_ban_count += 1
                    self.logger.info('rapid move of %s from %s to %s, temp loop ban %s' % (
                        eth_src, cache_port, port, port))

            # already, or newly in protect mode, apply the ban rules.
            if learn_ban:
                port.dyn_last_ban_time = now
                ofmsgs.append(self._temp_ban_host_learning(
                    self.eth_src_table.match(in_port=port.number)))
                return (ofmsgs, cache_port, False)

        (src_rule_idle_timeout,
         src_rule_hard_timeout,
         dst_rule_idle_timeout) = self.learn_host_timeouts(port, eth_src)

        ofmsgs.extend(self.learn_host_on_vlan_port_flows(
            port, vlan, eth_src, delete_existing, refresh_rules,
            src_rule_idle_timeout, src_rule_hard_timeout,
            dst_rule_idle_timeout))

        return (ofmsgs, cache_port, True)

    def flow_timeout(self, _now, _table_id, _match):
        """Handle a flow timed out message from dataplane."""
        return []


class ValveHostFlowRemovedManager(ValveHostManager):
    """Trigger relearning on flow removed notifications.

    .. note::

        not currently reliable.
    """

    def flow_timeout(self, now, table_id, match):
        ofmsgs = []
        if table_id in (self.eth_src_table.table_id, self.eth_dst_table.table_id):
            if 'vlan_vid' in match:
                vlan = self.vlans[valve_of.devid_present(match['vlan_vid'])]
                in_port = None
                eth_src = None
                eth_dst = None
                for field, value in match.items():
                    if field == 'in_port':
                        in_port = value
                    elif field == 'eth_src':
                        eth_src = value
                    elif field == 'eth_dst':
                        eth_dst = value
                if eth_src and in_port:
                    port = self.ports[in_port]
                    ofmsgs.extend(self._src_rule_expire(vlan, port, eth_src))
                elif eth_dst:
                    ofmsgs.extend(self._dst_rule_expire(now, vlan, eth_dst))
        return ofmsgs

    def expire_hosts_from_vlan(self, _vlan, _now):
        return []

    def learn_host_timeouts(self, port, eth_src):
        """Calculate flow timeouts for learning on a port."""
        learn_timeout = self._jitter_learn_timeout(self.learn_timeout, port, eth_src)

        # Disable hard_time, dst rule expires after src rule.
        src_rule_idle_timeout = learn_timeout
        src_rule_hard_timeout = 0
        dst_rule_idle_timeout = learn_timeout + self.cache_update_guard_time
        return (src_rule_idle_timeout, src_rule_hard_timeout, dst_rule_idle_timeout)

    def _src_rule_expire(self, vlan, port, eth_src):
        """When a src rule expires, the host is probably inactive or active in
        receiving but not sending. We mark just mark the host as expired."""
        ofmsgs = []
        entry = vlan.cached_host_on_port(eth_src, port)
        if entry is not None:
            vlan.expire_cache_host(eth_src)
            self.logger.info('expired src_rule for host %s' % eth_src)
        return ofmsgs

    def _dst_rule_expire(self, now, vlan, eth_dst):
        """Expiring a dst rule may indicate that the host is actively sending
        traffic but not receving. If the src rule not yet expires, we reinstall
        host rules."""
        ofmsgs = []
        entry = vlan.cached_host(eth_dst)
        if entry is not None:
            ofmsgs.extend(self.learn_host_on_vlan_ports(
                now, entry.port, vlan, eth_dst, delete_existing=False))
            self.logger.info(
                'refreshing host %s from VLAN %u' % (eth_dst, vlan.vid))
        return ofmsgs


class ValveFloodManager(ValveManagerBase):
    """Implement dataplane based flooding for standalone dataplanes."""

    # Enumerate possible eth_dst flood destinations.
    # First bool says whether to flood this destination if the VLAN
    # has unicast flooding enabled (if unicast flooding is enabled,
    # then we flood all destination eth_dsts).
    FLOOD_DSTS = (
        (True, None, None, None),
        (False, None, valve_packet.BRIDGE_GROUP_ADDRESS, valve_packet.mac_byte_mask(3)),  # 802.x
        (False, None, '01:00:5E:00:00:00', valve_packet.mac_byte_mask(3)),  # IPv4 multicast
        (False, None, '33:33:00:00:00:00', valve_packet.mac_byte_mask(2)),  # IPv6 multicast
        (False, None, valve_of.mac.BROADCAST_STR, valve_packet.mac_byte_mask(6)),  # eth broadcasts
    )
    # Ports with restricted broadcast enabled may only receive these broadcasts.
    RESTRICTED_FLOOD_DISTS = (
        (False, valve_of.ether.ETH_TYPE_ARP,
         valve_of.mac.BROADCAST_STR, valve_packet.mac_byte_mask(6)),  # ARP
        (False, valve_of.ether.ETH_TYPE_IPV6,
         '33:33:FF:00:00:00', valve_packet.mac_byte_mask(3)),  # IPv6 multicast for ND
        (False, valve_of.ether.ETH_TYPE_IPV6,
         valve_packet.IPV6_ALL_ROUTERS_MCAST, valve_packet.mac_byte_mask(6)),  # IPV6 all routers
        (False, valve_of.ether.ETH_TYPE_IPV6,
         valve_packet.IPV6_ALL_NODES_MCAST, valve_packet.mac_byte_mask(6)),  # IPv6 all nodes
    )

    def __init__(self, logger, flood_table, pipeline,  # pylint: disable=too-many-arguments
                 use_group_table, groups, combinatorial_port_flood,
                 canonical_port_order, restricted_bcast_arpnd):
        self.logger = logger
        self.flood_table = flood_table
        self.pipeline = pipeline
        self.use_group_table = use_group_table
        self.groups = groups
        self.combinatorial_port_flood = combinatorial_port_flood
        self.bypass_priority = self._FILTER_PRIORITY
        self.flood_priority = self._MATCH_PRIORITY
        self.classification_offset = 0x100
        self.canonical_port_order = canonical_port_order
        self.restricted_bcast_arpnd = restricted_bcast_arpnd
        if restricted_bcast_arpnd:
            self.flood_dsts = self.FLOOD_DSTS + self.RESTRICTED_FLOOD_DISTS
        else:
            self.flood_dsts = self.FLOOD_DSTS

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

    def floods_to_root(self, _dp_obj):
        """Return True if the given dp floods (only) to root switch"""
        return False

    @functools.lru_cache(maxsize=1024)
    def _mask_flood_priority(self, eth_dst_mask):
        return self.flood_priority + valve_packet.mac_mask_bits(eth_dst_mask)

    @staticmethod
    def _vlan_all_ports(vlan, exclude_unicast):
        """Return list of all ports that should be flooded to on a VLAN."""
        return list(vlan.flood_ports(vlan.get_ports(), exclude_unicast))

    def _build_flood_local_rule_actions(self, vlan, exclude_unicast, in_port,  # pylint: disable=too-many-arguments
                                        exclude_all_external, exclude_restricted_bcast_arpnd):
        """Return a list of flood actions to flood packets from a port."""
        external_ports = self.canonical_port_order(vlan.loop_protect_external_ports_up())
        exclude_ports = vlan.excluded_lag_ports(in_port)
        exclude_ports.update(vlan.exclude_native_if_dot1x())
        if exclude_all_external or (in_port is not None and in_port.loop_protect_external):
            exclude_ports.update(set(external_ports))
        else:
            exclude_ports.update(set(external_ports[1:]))
        if exclude_restricted_bcast_arpnd:
            exclude_ports.update(set(vlan.restricted_bcast_arpnd_ports()))
        return valve_of.flood_port_outputs(
            vlan.tagged_flood_ports(exclude_unicast),
            vlan.untagged_flood_ports(exclude_unicast),
            in_port=in_port,
            exclude_ports=exclude_ports)

    def _build_flood_rule_actions(self, vlan, exclude_unicast, in_port,  # pylint: disable=too-many-arguments
                                  exclude_all_external=False, exclude_restricted_bcast_arpnd=False):
        actions = []
        if vlan.loop_protect_external_ports() and vlan.tagged_flood_ports(exclude_unicast):
            actions.append(self.flood_table.set_external_forwarding_requested())
        actions.extend(self._build_flood_local_rule_actions(
            vlan, exclude_unicast, in_port, exclude_all_external, exclude_restricted_bcast_arpnd))
        return tuple(actions)

    def _build_flood_rule(self, match, command, flood_acts, flood_priority):
        return self.flood_table.flowmod(
            match=match,
            command=command,
            inst=[valve_of.apply_actions(flood_acts)],
            priority=flood_priority)

    @functools.lru_cache(maxsize=1024)
    def _vlan_flood_priority(self, eth_type, eth_dst_mask):
        priority = self._mask_flood_priority(eth_dst_mask)
        if eth_type:
            priority += eth_type
        return priority

    def _build_flood_rule_for_vlan(self, vlan, eth_type, eth_dst, eth_dst_mask,  # pylint: disable=too-many-arguments
                                   exclude_unicast, command):
        flood_priority = self._vlan_flood_priority(eth_type, eth_dst_mask)
        match = self.flood_table.match(
            vlan=vlan, eth_type=eth_type, eth_dst=eth_dst, eth_dst_mask=eth_dst_mask)
        # TODO: optimization - drop all general flood dsts if all ports are restricted.
        exclude_restricted_bcast_arpnd = True
        flood_acts = self._build_flood_rule_actions(
            vlan, exclude_unicast, None,
            exclude_restricted_bcast_arpnd=exclude_restricted_bcast_arpnd)
        return (self._build_flood_rule(match, command, flood_acts, flood_priority), flood_acts)

    def _build_flood_acts_for_port(self, vlan, exclude_unicast, port,  # pylint: disable=too-many-arguments
                                   exclude_all_external=False,
                                   exclude_restricted_bcast_arpnd=False):
        flood_acts = ()
        port_output_ports = []
        port_non_output_acts = []
        if port.dyn_phys_up:
            if exclude_restricted_bcast_arpnd:
                flood_acts = self._build_flood_rule_actions(
                    vlan, exclude_unicast, port, exclude_all_external, port.restricted_bcast_arpnd)
            else:
                flood_acts = self._build_flood_rule_actions(
                    vlan, exclude_unicast, port, exclude_all_external, False)
            (flood_acts,
             port_output_ports,
             port_non_output_acts) = valve_of.output_non_output_actions(flood_acts)
            if not port_output_ports:
                flood_acts = ()
                port_non_output_acts = ()
        return (flood_acts, port_output_ports, port_non_output_acts)

    def _build_flood_match_priority(self, port, vlan, eth_type,  # pylint: disable=too-many-arguments
                                    eth_dst, eth_dst_mask, add_match):
        flood_priority = self._vlan_flood_priority(eth_type, eth_dst_mask) + 1
        if add_match is None:
            add_match = {}
        match = self.flood_table.match(
            vlan=vlan, in_port=port.number,
            eth_type=eth_type, eth_dst=eth_dst, eth_dst_mask=eth_dst_mask,
            **add_match)
        return (flood_priority, match)

    def _build_flood_rule_for_port(self, vlan, eth_type, eth_dst, eth_dst_mask,  # pylint: disable=too-many-arguments
                                   command, port, flood_acts, add_match=None):
        flood_priority, match = self._build_flood_match_priority(
            port, vlan, eth_type, eth_dst, eth_dst_mask, add_match)
        return self._build_flood_rule(match, command, flood_acts, flood_priority)

    def _build_mask_flood_rules(self, vlan, eth_type, eth_dst, eth_dst_mask,  # pylint: disable=too-many-arguments
                                exclude_unicast, exclude_restricted_bcast_arpnd, command):
        ofmsgs = []
        if self.combinatorial_port_flood:
            for port in self._vlan_all_ports(vlan, exclude_unicast):
                flood_acts, _, _ = self._build_flood_acts_for_port(
                    vlan, exclude_unicast, port,
                    exclude_restricted_bcast_arpnd=exclude_restricted_bcast_arpnd)
                if flood_acts:
                    ofmsgs.append(self._build_flood_rule_for_port(
                        vlan, eth_type, eth_dst, eth_dst_mask, command, port, flood_acts))
        else:
            vlan_flood_ofmsg, vlan_flood_acts = self._build_flood_rule_for_vlan(
                vlan, eth_type, eth_dst, eth_dst_mask, exclude_unicast, command)
            if not self.use_group_table:
                ofmsgs.append(vlan_flood_ofmsg)
            (flood_acts,
             vlan_output_ports,
             vlan_non_output_acts) = valve_of.output_non_output_actions(vlan_flood_acts)
            for port in self._vlan_all_ports(vlan, exclude_unicast):
                (flood_acts,
                 port_output_ports,
                 port_non_output_acts) = self._build_flood_acts_for_port(
                     vlan, exclude_unicast, port,
                     exclude_restricted_bcast_arpnd=exclude_restricted_bcast_arpnd)
                if not flood_acts:
                    continue
                if (vlan_output_ports - set([port.number]) == port_output_ports
                        and vlan_non_output_acts == port_non_output_acts):
                    # Delete a potentially existing port specific flow
                    # TODO: optimize, avoid generating delete for port if no existing flow.
                    flood_priority, match = self._build_flood_match_priority(
                        port, vlan, eth_type, eth_dst, eth_dst_mask, add_match=None)
                    ofmsgs.append(self.flood_table.flowdel(
                        match=match, priority=flood_priority))
                else:
                    ofmsgs.append(self._build_flood_rule_for_port(
                        vlan, eth_type, eth_dst, eth_dst_mask, command, port, flood_acts))
        return ofmsgs

    def _build_multiout_flood_rules(self, vlan, command):
        """Build flooding rules for a VLAN without using groups."""
        ofmsgs = []
        for unicast_eth_dst, eth_type, eth_dst, eth_dst_mask in self.flood_dsts:
            if unicast_eth_dst and not vlan.unicast_flood:
                continue
            exclude_restricted_bcast_arpnd = eth_type is None
            ofmsgs.extend(self._build_mask_flood_rules(
                vlan, eth_type, eth_dst, eth_dst_mask,
                unicast_eth_dst, exclude_restricted_bcast_arpnd, command))
        return ofmsgs

    def _build_group_flood_rules(self, vlan, modify, command):
        """Build flooding rules for a VLAN using groups."""
        _, vlan_flood_acts = self._build_flood_rule_for_vlan(
            vlan, None, None, None, False, command)
        group_id = vlan.vid
        group = self.groups.get_entry(
            group_id, valve_of.build_group_flood_buckets(vlan_flood_acts))
        groups_by_unicast_eth = {False: group, True: group}
        ofmsgs = []

        # Only configure unicast flooding group if has different output
        # actions to non unicast flooding.
        _, unicast_eth_vlan_flood_acts = self._build_flood_rule_for_vlan(
            vlan, None, None, None, True, command)
        unicast_eth_vlan_flood_acts, unicast_output_ports, _ = valve_of.output_non_output_actions(
            unicast_eth_vlan_flood_acts)
        vlan_flood_acts, vlan_output_ports, _ = valve_of.output_non_output_actions(vlan_flood_acts)
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

        for unicast_eth_dst, eth_type, eth_dst, eth_dst_mask in self.flood_dsts:
            if unicast_eth_dst and not vlan.unicast_flood:
                continue
            group = groups_by_unicast_eth[unicast_eth_dst]
            match = self.flood_table.match(
                vlan=vlan, eth_type=eth_type, eth_dst=eth_dst, eth_dst_mask=eth_dst_mask)
            flood_priority = self._vlan_flood_priority(eth_type, eth_dst_mask)
            ofmsgs.append(self.flood_table.flowmod(
                match=match,
                command=command,
                inst=[valve_of.apply_actions([valve_of.group_act(group.group_id)])],
                priority=flood_priority))
        return ofmsgs

    def add_vlan(self, vlan):
        return self.build_flood_rules(vlan)

    def del_vlan(self, vlan):
        return [self.flood_table.flowdel(self.flood_table.match(vlan=vlan.vid))]

    def update_vlan(self, vlan):
        return self.build_flood_rules(vlan, modify=True)

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
    def update_stack_topo(event, dp, port):  # pylint: disable=unused-argument,invalid-name
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


class ValveFloodStackManagerBase(ValveFloodManager):
    """Base class for dataplane based flooding on stacked dataplanes."""

    # By default, no reflection used for flooding algorithms.
    _USES_REFLECTION = False

    def __init__(self, logger, flood_table, pipeline, # pylint: disable=too-many-arguments
                 use_group_table, groups,
                 combinatorial_port_flood, canonical_port_order,
                 restricted_bcast_arpnd,
                 stack_ports, has_externals,
                 dp_shortest_path_to_root, shortest_path_port,
                 is_stack_root, is_stack_root_candidate,
                 is_stack_edge, graph):
        super(ValveFloodStackManagerBase, self).__init__(
            logger, flood_table, pipeline,
            use_group_table, groups,
            combinatorial_port_flood,
            canonical_port_order,
            restricted_bcast_arpnd)
        self.stack_ports = stack_ports
        self.canonical_port_order = canonical_port_order
        self.externals = has_externals
        self.shortest_path_port = shortest_path_port
        self.dp_shortest_path_to_root = dp_shortest_path_to_root
        self.is_stack_root = is_stack_root
        self.is_stack_root_candidate = is_stack_root_candidate
        self.is_stack_edge = is_stack_edge
        self.graph = graph
        self._set_ext_port_flag = ()
        self._set_nonext_port_flag = ()
        self.external_root_only = False
        if self.externals:
            self.logger.info('external ports present, using loop protection')
            self._set_ext_port_flag = (self.flood_table.set_external_forwarding_requested(),)
            self._set_nonext_port_flag = (self.flood_table.set_no_external_forwarding_requested(),)
            if not self.is_stack_root() and self.is_stack_root_candidate():
                self.logger.info('external flooding on root only')
                self.external_root_only = True
        self._reset_peer_distances()

    def _build_flood_acts_for_port(self, vlan, exclude_unicast, port,  # pylint: disable=too-many-arguments
                                   exclude_all_external=False,
                                   exclude_restricted_bcast_arpnd=False):
        if self.external_root_only:
            exclude_all_external = True
        return super(ValveFloodStackManagerBase, self)._build_flood_acts_for_port(
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
        ofmsgs = super(ValveFloodStackManagerBase, self)._build_mask_flood_rules(
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


            if self.externals:
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
        else:
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
        return super(ValveFloodStackManagerBase, self).edge_learn_port(
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


class ValveFloodStackManagerNoReflection(ValveFloodStackManagerBase):
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


class ValveFloodStackManagerReflection(ValveFloodStackManagerBase):
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
        # TODO: edge DPs could use a different forwarding algorithm
        # (for example, just default switch to a neighbor).
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
