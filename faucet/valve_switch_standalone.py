"""Manage flooding/learning on standalone datapaths."""

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
import functools
from collections import defaultdict
from faucet import valve_of
from faucet import valve_packet
from faucet.valve_manager_base import ValveManagerBase
from faucet.vlan import NullVLAN
from faucet import valve_table


class ValveSwitchManager(ValveManagerBase):  # pylint: disable=too-many-public-methods
    """Implement dataplane based flooding/learning for standalone dataplanes."""

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

    def __init__(self, logger, ports, vlans,  # pylint: disable=too-many-arguments
                 vlan_table, vlan_acl_table, eth_src_table, eth_dst_table,
                 eth_dst_hairpin_table, flood_table, classification_table,
                 pipeline, use_group_table, groups, combinatorial_port_flood,
                 canonical_port_order, restricted_bcast_arpnd, has_externals,
                 learn_ban_timeout, learn_timeout, learn_jitter, cache_update_guard_time,
                 idle_dst, dp_high_priority, dp_highest_priority, faucet_dp_mac):
        self.logger = logger
        self.ports = ports
        self.vlans = vlans
        self.vlan_table = vlan_table
        self.vlan_acl_table = vlan_acl_table
        self.eth_src_table = eth_src_table
        self.eth_dst_table = eth_dst_table
        self.eth_dst_hairpin_table = eth_dst_hairpin_table
        self.flood_table = flood_table
        self.classification_table = classification_table
        self.pipeline = pipeline
        self.use_group_table = use_group_table
        self.groups = groups
        self.combinatorial_port_flood = combinatorial_port_flood
        self.canonical_port_order = canonical_port_order
        self.restricted_bcast_arpnd = restricted_bcast_arpnd
        self.has_externals = has_externals
        self.learn_ban_timeout = learn_ban_timeout
        self.learn_timeout = learn_timeout
        self.learn_jitter = learn_jitter
        self.cache_update_guard_time = cache_update_guard_time
        self.idle_dst = idle_dst
        self.output_table = self.eth_dst_table
        if self.eth_dst_hairpin_table:
            self.output_table = self.eth_dst_hairpin_table
        if restricted_bcast_arpnd:
            self.flood_dsts = self.FLOOD_DSTS + self.RESTRICTED_FLOOD_DISTS
        else:
            self.flood_dsts = self.FLOOD_DSTS
        self.bypass_priority = self._FILTER_PRIORITY
        self.host_priority = self._MATCH_PRIORITY
        self.flood_priority = self._MATCH_PRIORITY
        self.low_priority = self._LOW_PRIORITY
        self.high_priority = self._HIGH_PRIORITY
        self.classification_offset = 0x100
        self.dp_high_priority = dp_high_priority
        self.dp_highest_priority = dp_highest_priority
        self.faucet_dp_mac = faucet_dp_mac

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
            inst=(valve_of.apply_actions(flood_acts),),
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
                                exclude_unicast, exclude_restricted_bcast_arpnd,
                                command, cold_start):
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
                if (vlan_output_ports - set([port.number]) == port_output_ports and
                        vlan_non_output_acts == port_non_output_acts):
                    # Delete a potentially existing port specific flow
                    # TODO: optimize, avoid generating delete for port if no existing flow.
                    if not cold_start:
                        flood_priority, match = self._build_flood_match_priority(
                            port, vlan, eth_type, eth_dst, eth_dst_mask, add_match=None)
                        ofmsgs.append(self.flood_table.flowdel(
                            match=match, priority=flood_priority))
                else:
                    ofmsgs.append(self._build_flood_rule_for_port(
                        vlan, eth_type, eth_dst, eth_dst_mask, command, port, flood_acts))
        return ofmsgs

    def _build_multiout_flood_rules(self, vlan, command, cold_start):
        """Build flooding rules for a VLAN without using groups."""
        ofmsgs = []
        for unicast_eth_dst, eth_type, eth_dst, eth_dst_mask in self.flood_dsts:
            if unicast_eth_dst and not vlan.unicast_flood:
                continue
            exclude_restricted_bcast_arpnd = eth_type is None
            ofmsgs.extend(self._build_mask_flood_rules(
                vlan, eth_type, eth_dst, eth_dst_mask,
                unicast_eth_dst, exclude_restricted_bcast_arpnd,
                command, cold_start))
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
                inst=(valve_of.apply_actions((valve_of.group_act(group.group_id),)),),
                priority=flood_priority))
        return ofmsgs

    def add_vlan(self, vlan, cold_start):
        ofmsgs = []
        ofmsgs.append(self.eth_src_table.flowcontroller(
            match=self.eth_src_table.match(vlan=vlan),
            priority=self.low_priority,
            inst=(self.eth_src_table.goto(self.output_table),)))
        ofmsgs.extend(self._build_flood_rules(vlan, cold_start))
        return ofmsgs

    def del_vlan(self, vlan):
        table = valve_table.wildcard_table
        return [table.flowdel(match=table.match(vlan=vlan))]

    def update_vlan(self, vlan):
        return self._build_flood_rules(vlan, cold_start=False, modify=True)

    def _find_forwarding_table(self, vlan):
        if vlan.acls_in:
            return self.vlan_acl_table
        return self.classification_table()

    def _port_add_vlan_rules(self, port, vlan, mirror_act, push_vlan=True):
        actions = copy.copy(mirror_act)
        match_vlan = vlan
        if push_vlan:
            actions.extend(valve_of.push_vlan_act(
                self.vlan_table, vlan.vid))
            match_vlan = NullVLAN()
        if self.has_externals:
            if port.loop_protect_external:
                actions.append(self.vlan_table.set_no_external_forwarding_requested())
            else:
                actions.append(self.vlan_table.set_external_forwarding_requested())
        inst = (
            valve_of.apply_actions(actions),
            self.vlan_table.goto(self._find_forwarding_table(vlan)))
        return self.vlan_table.flowmod(
            self.vlan_table.match(in_port=port.number, vlan=match_vlan),
            priority=self.low_priority, inst=inst)

    def _native_vlan(self, port):
        for native_vlan in (port.dyn_dot1x_native_vlan, port.native_vlan):
            if native_vlan is not None:
                return native_vlan
        return None

    def lacp_advertise(self, port):
        ofmsgs = []
        if port.running() and port.lacp_active:
            ofmsgs.extend(self.lacp_req_reply(port.dyn_last_lacp_pkt, port))
        return ofmsgs

    def add_port(self, port):
        ofmsgs = []
        if port.vlans():
            mirror_act = port.mirror_actions()
            tagged_ofmsgs = []
            for vlan in port.tagged_vlans:
                tagged_ofmsgs.append(self._port_add_vlan_rules(
                    port, vlan, mirror_act, push_vlan=False))
            untagged_ofmsgs = []
            native_vlan = self._native_vlan(port)
            if native_vlan is not None:
                untagged_ofmsgs.append(self._port_add_vlan_rules(
                    port, native_vlan, mirror_act))
            # If no untagged VLANs, add explicit drop rule for untagged packets.
            if port.count_untag_vlan_miss and not untagged_ofmsgs:
                untagged_ofmsgs.append(self.vlan_table.flowmod(
                    self.vlan_table.match(in_port=port.number, vlan=NullVLAN()),
                    priority=self.low_priority))
            ofmsgs.extend(tagged_ofmsgs)
            ofmsgs.extend(untagged_ofmsgs)
            if port.lacp:
                ofmsgs.append(self.vlan_table.flowcontroller(
                    self.vlan_table.match(
                        in_port=port.number,
                        eth_type=valve_of.ether.ETH_TYPE_SLOW,
                        eth_dst=valve_packet.SLOW_PROTOCOL_MULTICAST),
                    priority=self.dp_highest_priority,
                    max_len=valve_packet.LACP_SIZE))
                ofmsgs.extend(self.lacp_advertise(port))
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
        for vlan in port.vlans():
            vlan.clear_cache_hosts_on_port(port)
        native_vlan = self._native_vlan(port)
        if native_vlan is not None:
            ofmsgs.append(self.vlan_table.flowdel(
                self.vlan_table.match(in_port=port.number, vlan=port.native_vlan),
                priority=self.low_priority))
        return ofmsgs

    def _build_flood_rules(self, vlan, cold_start, modify=False):
        """Add flows to flood packets to unknown destinations on a VLAN."""
        command = valve_of.ofp.OFPFC_ADD
        if modify:
            command = valve_of.ofp.OFPFC_MODIFY_STRICT
        ofmsgs = self._build_multiout_flood_rules(vlan, command, cold_start)
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

    def _learn_host_timeouts(self, port, eth_src):
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

    def _external_forwarding_requested(self, port):  # pylint: disable=unused-argument
        if self.has_externals:
            return True
        return None

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

        inst = (self.eth_src_table.goto(self.output_table),)
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

        match_dict = {
            'vlan': vlan, 'eth_dst': eth_src, valve_of.EXTERNAL_FORWARDING_FIELD: None}
        if self.has_externals:
            match_dict.update({
                valve_of.EXTERNAL_FORWARDING_FIELD: valve_of.PCP_EXT_PORT_FLAG})

        inst = self.pipeline.output(
            port, vlan, external_forwarding_requested=self._external_forwarding_requested(port))

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

    def _perm_learn_check(self, entry, vlan, now, eth_src, port, ofmsgs,  # pylint: disable=unused-argument
                          cache_port, cache_age,
                          delete_existing, refresh_rules):
        learn_exit = False
        update_cache = True
        if entry is not None and entry.port.permanent_learn:
            if entry.port != port:
                ofmsgs.extend(self.pipeline.filter_packets(
                    {'eth_src': eth_src, 'in_port': port.number}))
            learn_exit = True
            update_cache = False
        return (learn_exit, ofmsgs, cache_port, update_cache, delete_existing, refresh_rules)

    def _learn_cache_check(self, entry, vlan, now, eth_src, port, ofmsgs,  # pylint: disable=unused-argument
                           cache_port, cache_age,
                           delete_existing, refresh_rules):
        learn_exit = False
        update_cache = True
        if cache_port is not None:
            # packet was received on same member of a LAG.
            same_lag = (port.lacp and port.lacp == cache_port.lacp)
            guard_time = self.cache_update_guard_time
            if cache_port == port or same_lag:
                # aggressively re-learn on LAGs
                if same_lag:
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

    def _loop_protect_check(self, entry, vlan, now, eth_src, port, ofmsgs,  # pylint: disable=unused-argument
                            cache_port, cache_age,
                            delete_existing, refresh_rules):
        learn_exit = False
        update_cache = True
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
                learn_exit = True
        return (learn_exit, ofmsgs, cache_port, update_cache, delete_existing, refresh_rules)

    def _learn_check(self, entry, vlan, now, eth_src, port, ofmsgs,  # pylint: disable=unused-argument
                     cache_port, cache_age,
                     delete_existing, refresh_rules):
        learn_exit = True
        update_cache = True
        (src_rule_idle_timeout,
         src_rule_hard_timeout,
         dst_rule_idle_timeout) = self._learn_host_timeouts(port, eth_src)

        ofmsgs.extend(self.learn_host_on_vlan_port_flows(
            port, vlan, eth_src, delete_existing, refresh_rules,
            src_rule_idle_timeout, src_rule_hard_timeout,
            dst_rule_idle_timeout))
        return (learn_exit, ofmsgs, cache_port, update_cache, delete_existing, refresh_rules)

    def learn_host_on_vlan_ports(self, now, port, vlan, eth_src,
                                 delete_existing=True,
                                 last_dp_coldstart_time=None):
        """Learn a host on a port."""
        ofmsgs = []
        cache_port = None
        cache_age = None
        refresh_rules = False
        update_cache = True
        entry = vlan.cached_host(eth_src)

        # Host not cached, and no hosts expired since we cold started
        # Enable faster learning by assuming there's no previous host to delete
        if entry is None:
            if (last_dp_coldstart_time and
                    (vlan.dyn_last_time_hosts_expired is None or
                     vlan.dyn_last_time_hosts_expired < last_dp_coldstart_time)):
                delete_existing = False
        else:
            cache_age = now - entry.cache_time
            cache_port = entry.port

        for learn_func in (
                self._perm_learn_check, self._learn_cache_check,
                self._loop_protect_check, self._learn_check):
            (learn_exit, ofmsgs, cache_port, update_cache,
             delete_existing, refresh_rules) = learn_func(
                 entry, vlan, now, eth_src, port, ofmsgs, cache_port, cache_age,
                 delete_existing, refresh_rules)
            if learn_exit:
                break

        return (ofmsgs, cache_port, update_cache)

    def flow_timeout(self, _now, _table_id, _match):
        """Handle a flow timed out message from dataplane."""
        return []

    def lacp_update_actor_state(self, port, lacp_up, now=None, lacp_pkt=None, cold_start=False):
        """Updates a LAG actor state.

        Args:
            port: LACP port
            lacp_up (bool): Whether LACP is going UP or DOWN
            now (float): Current epoch time
            lacp_pkt (PacketMeta): LACP packet
            cold_start (bool): Whether the port is being cold started
        Returns:
            bool: True if LACP state changed
        """
        prev_actor_state = port.actor_state()
        new_actor_state = port.lacp_actor_update(
            lacp_up, now=now, lacp_pkt=lacp_pkt,
            cold_start=cold_start)
        if prev_actor_state != new_actor_state:
            self.logger.info('LAG %u %s actor state %s (previous state %s)' % (
                port.lacp, port, port.actor_state_name(new_actor_state),
                port.actor_state_name(prev_actor_state)))
        return prev_actor_state != new_actor_state

    def enable_forwarding(self, port):
        ofmsgs = []
        ofmsgs.append(self.vlan_table.flowdel(
            match=self.vlan_table.match(in_port=port.number),
            priority=self.dp_high_priority, strict=True))
        return ofmsgs

    def disable_forwarding(self, port):
        ofmsgs = []
        ofmsgs.append(self.vlan_table.flowdrop(
            match=self.vlan_table.match(in_port=port.number),
            priority=self.dp_high_priority))
        return ofmsgs

    def lacp_req_reply(self, lacp_pkt, port):
        """
        Constructs a LACP req-reply packet.

        Args:
            lacp_pkt (PacketMeta): LACP packet received
            port: LACP port
            other_valves (list): List of other valves

        Returns:
            list packetout OpenFlow msgs.
        """
        if port.lacp_passthrough:
            for peer_num in port.lacp_passthrough:
                lacp_peer = self.ports.get(peer_num, None)
                if not lacp_peer.dyn_lacp_up:
                    self.logger.warning('Suppressing LACP LAG %s on %s, peer %s link is down' %
                                        (port.lacp, port, lacp_peer))
                    return []
        actor_state_activity = 0
        if port.lacp_active:
            actor_state_activity = 1
        actor_state_sync, actor_state_col, actor_state_dist = port.get_lacp_flags()
        if lacp_pkt:
            pkt = valve_packet.lacp_reqreply(
                self.faucet_dp_mac, self.faucet_dp_mac,
                port.lacp, port.lacp_port_id, port.lacp_port_priority,
                actor_state_sync, actor_state_activity,
                actor_state_col, actor_state_dist,
                lacp_pkt.actor_system, lacp_pkt.actor_key, lacp_pkt.actor_port,
                lacp_pkt.actor_system_priority, lacp_pkt.actor_port_priority,
                lacp_pkt.actor_state_defaulted,
                lacp_pkt.actor_state_expired,
                lacp_pkt.actor_state_timeout,
                lacp_pkt.actor_state_collecting,
                lacp_pkt.actor_state_distributing,
                lacp_pkt.actor_state_aggregation,
                lacp_pkt.actor_state_synchronization,
                lacp_pkt.actor_state_activity)
        else:
            pkt = valve_packet.lacp_reqreply(
                self.faucet_dp_mac, self.faucet_dp_mac,
                port.lacp, port.lacp_port_id, port.lacp_port_priority,
                actor_state_synchronization=actor_state_sync,
                actor_state_activity=actor_state_activity,
                actor_state_collecting=actor_state_col,
                actor_state_distributing=actor_state_dist)
        self.logger.debug('Sending LACP %s on %s activity %s' % (pkt, port, actor_state_activity))
        return [valve_of.packetout(port.number, bytes(pkt.data))]

    def get_lacp_dpid_nomination(self, lacp_id, valve, other_valves):  # pylint: disable=unused-argument
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
        return (valve.dp.dp_id, 'standalone')

    def lacp_update_port_selection_state(self, port, valve, other_valves=None, cold_start=False):
        """Update the LACP port selection state.

        Args:
            port (Port): LACP port
            other_valves (list): List of other valves
            cold_start (bool): Whether the port is being cold started
        Returns:
            bool: True if port state changed
        """
        nominated_dpid, _ = self.get_lacp_dpid_nomination(port.lacp, valve, other_valves)
        prev_state = port.lacp_port_state()
        new_state = port.lacp_port_update(valve.dp.dp_id == nominated_dpid, cold_start=cold_start)
        if new_state != prev_state:
            self.logger.info('LAG %u %s %s (previous state %s)' % (
                port.lacp, port, port.port_role_name(new_state),
                port.port_role_name(prev_state)))
        return new_state != prev_state

    def lacp_handler(self, now, pkt_meta, valve, other_valves, lacp_update):
        """
        Handle receiving an LACP packet
        Args:
            now (float): current epoch time
            pkt_meta (PacketMeta): packet for control plane
            valve (Valve): valve instance
            other_valves (list): all other valves
            lacp_update: callable to signal LACP state changes
        Returns
            dict: OpenFlow messages, if any by Valve
        """
        ofmsgs_by_valve = defaultdict(list)
        if (pkt_meta.eth_dst == valve_packet.SLOW_PROTOCOL_MULTICAST and
                pkt_meta.eth_type == valve_of.ether.ETH_TYPE_SLOW and
                pkt_meta.port.lacp):
            # LACP packet so reparse
            pkt_meta.data = pkt_meta.data[:valve_packet.LACP_SIZE]
            pkt_meta.reparse_all()
            lacp_pkt = valve_packet.parse_lacp_pkt(pkt_meta.pkt)
            if lacp_pkt:
                self.logger.debug('receive LACP %s on %s' % (lacp_pkt, pkt_meta.port))
                # Respond to new LACP packet or if we haven't sent anything in a while
                age = None
                if pkt_meta.port.dyn_lacp_last_resp_time:
                    age = now - pkt_meta.port.dyn_lacp_last_resp_time
                lacp_pkt_change = (
                    pkt_meta.port.dyn_last_lacp_pkt is None or
                    str(lacp_pkt) != str(pkt_meta.port.dyn_last_lacp_pkt))
                lacp_resp_interval = pkt_meta.port.lacp_resp_interval
                if lacp_pkt_change or (age is not None and age > lacp_resp_interval):
                    ofmsgs_by_valve[valve].extend(
                        self.lacp_req_reply(lacp_pkt, pkt_meta.port))
                    pkt_meta.port.dyn_lacp_last_resp_time = now
                # Update the LACP information
                actor_up = lacp_pkt.actor_state_synchronization
                ofmsgs_by_valve[valve].extend(lacp_update(
                    pkt_meta.port, actor_up, now=now, lacp_pkt=lacp_pkt, other_valves=other_valves))
                # Determine if LACP ports with the same ID have met different actor systems
                other_lag_ports = [
                    port for port in self.ports.values()
                    if port.lacp == pkt_meta.port.lacp and port.dyn_last_lacp_pkt]
                actor_system = lacp_pkt.actor_system
                for other_lag_port in other_lag_ports:
                    other_actor_system = other_lag_port.dyn_last_lacp_pkt.actor_system
                    if actor_system != other_actor_system:
                        self.logger.error(
                            'LACP actor system mismatch %s: %s, %s %s' % (
                                pkt_meta.port, actor_system,
                                other_lag_port, other_actor_system))
        return ofmsgs_by_valve

    def learn_host_from_pkt(self, valve, now, pkt_meta, other_valves):
        """Learn host from packet."""
        ofmsgs = []
        ofmsgs.extend(valve.learn_host(now, pkt_meta, other_valves))
        ofmsgs.extend(valve.router_rcv_packet(now, pkt_meta))
        return {valve: ofmsgs}


class ValveSwitchFlowRemovedManager(ValveSwitchManager):
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

    def _learn_host_timeouts(self, port, eth_src):
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
