"""Valve IPv4/IPv6 routing implementation."""

# pylint: disable=too-many-lines

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

from collections import defaultdict, deque
import random
import time

import ipaddress

from ryu.lib.packet import arp, icmp, icmpv6, ipv4, ipv6

from faucet import valve_of
from faucet import valve_packet
from faucet.valve_manager_base import ValveManagerBase


class AnonVLAN:
    """The anonymous VLAN for global routing"""

    def __init__(self, vid):
        self.vid = vid


class NextHop:
    """Describes a directly connected (at layer 2) nexthop."""

    __slots__ = [
        'cache_time',
        'eth_src',
        'last_retry_time',
        'next_retry_time',
        'resolve_retries',
        'port',
    ]

    def __init__(self, eth_src, port, now):
        self.eth_src = eth_src
        self.port = port
        self.cache_time = now
        self.resolve_retries = 0
        self.last_retry_time = None
        self.next_retry_time = None
        if not self.eth_src:
            self.next_retry_time = now

    def age(self, now):
        """Return age of this nexthop."""
        return now - self.cache_time

    def dead(self, max_fib_retries):
        """Return True if this nexthop is considered dead."""
        return self.resolve_retries >= max_fib_retries

    def next_retry(self, now, max_resolve_backoff_time):
        """Increment state for next retry."""
        self.resolve_retries += 1
        self.last_retry_time = now
        self.next_retry_time = now + min(
            (2**self.resolve_retries + random.randint(0, self.resolve_retries)),
            max_resolve_backoff_time)

    def resolution_due(self, now, max_age):
        """Return True if this nexthop is due to be re resolved/retried."""
        if self.eth_src is not None and self.age(now) < max_age:
            return False
        if self.next_retry_time is None or self.next_retry_time < now:
            return True
        return False

    def __str__(self):
        return '%s %s' % (self.eth_src, self.port)

    def __repr__(self):
        return self.__str__()


class ValveRouteManager(ValveManagerBase):
    """Base class to implement RIB/FIB."""

    __slots__ = [
        'active',
        'neighbor_timeout',
        'dec_ttl',
        'fib_table',
        'pipeline',
        'multi_out',
        'notify',
        'global_vlan',
        'global_routing',
        'logger',
        'max_host_fib_retry_count',
        'max_hosts_per_resolve_cycle',
        'max_resolve_backoff_time',
        'proactive_learn',
        'route_priority',
        'routers',
        'vip_table',
        'switch_manager',
    ]

    IPV = 0
    ETH_TYPE = None
    ICMP_TYPE = None
    ICMP_SIZE = None
    MAX_PACKET_IN_SIZE = valve_of.MAX_PACKET_IN_BYTES
    CONTROL_ETH_TYPES = ()  # type: ignore
    IP_PKT = None

    def __init__(self, logger, notify, global_vlan, neighbor_timeout,
                 max_hosts_per_resolve_cycle, max_host_fib_retry_count,
                 max_resolve_backoff_time, proactive_learn, dec_ttl, multi_out,
                 fib_table, vip_table, pipeline, routers, stack_manager):
        self.notify = notify
        self.logger = logger
        self.global_vlan = AnonVLAN(global_vlan)
        self.neighbor_timeout = neighbor_timeout
        self.max_hosts_per_resolve_cycle = max_hosts_per_resolve_cycle
        self.max_host_fib_retry_count = max_host_fib_retry_count
        self.max_resolve_backoff_time = max_resolve_backoff_time
        self.proactive_learn = proactive_learn
        self.dec_ttl = dec_ttl
        self.multi_out = multi_out
        self.fib_table = fib_table
        self.vip_table = vip_table
        self.pipeline = pipeline
        self.route_priority = self._LPM_PRIORITY
        self.routers = routers
        self.active = False
        self.global_routing = self._global_routing()
        self.stack_manager = stack_manager
        if self.global_routing:
            self.logger.info('global routing enabled')

    def notify_learn(self, pkt_meta):
        self.notify({'L3_LEARN': {
            'eth_src': pkt_meta.eth_src,
            'l3_src_ip': str(pkt_meta.l3_src),
            'port_no': pkt_meta.port.number,
            'vid': pkt_meta.vlan.vid}})

    def nexthop_dead(self, nexthop_cache_entry):
        """Returns true if the nexthop_cache_entry is considered dead"""
        return nexthop_cache_entry.dead(self.max_host_fib_retry_count)

    @staticmethod
    def _unicast_to_vip(pkt_meta):
        """Return true if packet is from a src in the connected network and dst ip is
            a faucet vip. I.e: Packet is traffic bound for a VIP"""
        return (pkt_meta.eth_dst == pkt_meta.vlan.faucet_mac
                and pkt_meta.vlan.from_connected_to_vip(pkt_meta.l3_src, pkt_meta.l3_dst))

    @staticmethod
    def _gw_resolve_pkt():
        return None

    @staticmethod
    def _gw_respond_pkt():
        return None

    def _flood_stack_links(self, pkt_builder, vlan, multi_out, *args):
        """Return flood packet-out actions to stack ports for gw resolving"""
        ofmsgs = []
        if self.stack_manager:
            ports = []
            if self.stack_manager.stack.is_root():
                ports = list(self.stack_manager.away_ports
                             - self.stack_manager.inactive_away_ports
                             - self.stack_manager.pruned_away_ports)
            else:
                if self.stack_manager.chosen_towards_port is not None:
                    ports = [self.stack_manager.chosen_towards_port]
            if ports:
                running_port_nos = [port.number for port in ports if port.running()]
                pkt = pkt_builder(vlan.vid, *args)
                if running_port_nos:
                    random.shuffle(running_port_nos)
                    if multi_out:
                        ofmsgs.append(valve_of.packetouts(running_port_nos, bytes(pkt.data)))
                    else:
                        ofmsgs.extend(
                            [valve_of.packetout(port_no, bytes(pkt.data)) for
                             port_no in running_port_nos])
        return ofmsgs

    def _resolve_gw_on_vlan(self, vlan, faucet_vip, ip_gw):
        """Return flood packet-out actions for gw resolving"""
        ofmsgs = []
        stack_ofmsgs = self._flood_stack_links(
            self._gw_resolve_pkt(), vlan, self.multi_out,
            vlan.faucet_mac, valve_of.mac.BROADCAST_STR, faucet_vip.ip, ip_gw)
        if stack_ofmsgs:
            ofmsgs.extend(stack_ofmsgs)
        vlan_ofmsgs = vlan.flood_pkt(
            self._gw_resolve_pkt(), self.multi_out,
            vlan.faucet_mac, valve_of.mac.BROADCAST_STR, faucet_vip.ip, ip_gw)
        if vlan_ofmsgs:
            ofmsgs.extend(vlan_ofmsgs)
        return ofmsgs

    def _resolve_gw_on_port(self, vlan, port, faucet_vip, ip_gw, eth_dst):
        """Return packet-out actions for outputting to a specific port"""
        return vlan.pkt_out_port(
            self._gw_resolve_pkt(),
            port, vlan.faucet_mac, eth_dst, faucet_vip.ip, ip_gw)

    def _controller_and_flood(self):
        """Return instructions to forward packet to l2-forwarding"""
        return self.pipeline.accept_to_l2_forwarding(
            actions=(valve_of.output_controller(max_len=self.MAX_PACKET_IN_SIZE),))

    def _resolve_vip_response(self, pkt_meta, solicited_ip, now):
        """Learn host requesting for router, and return packet-out ofmsgs router response"""
        ofmsgs = []
        vlan = pkt_meta.vlan
        if (pkt_meta.vlan.is_faucet_vip(solicited_ip)
                and pkt_meta.vlan.ip_in_vip_subnet(pkt_meta.l3_src)):
            src_ip = pkt_meta.l3_src
            eth_src = pkt_meta.eth_src
            port = pkt_meta.port
            if self._stateful_gw(vlan, src_ip):
                ofmsgs.extend(
                    self._add_host_fib_route(vlan, src_ip, blackhole=False))
                ofmsgs.extend(self._update_nexthop(
                    now, vlan, port, eth_src, src_ip))
                if ofmsgs:
                    self.logger.info(
                        'Resolve response to %s from %s' % (
                            solicited_ip, pkt_meta.log()))
            ofmsgs.append(
                vlan.pkt_out_port(
                    self._gw_respond_pkt(), port,
                    vlan.faucet_mac, eth_src,
                    solicited_ip, src_ip))
        return ofmsgs

    def _gw_advert(self, pkt_meta, target_ip, now):
        """Receive an advert, so update nexthop information"""
        ofmsgs = []
        vlan = pkt_meta.vlan
        if vlan.ip_in_vip_subnet(target_ip):
            if self._stateful_gw(vlan, target_ip):
                ofmsgs.extend(self._update_nexthop(
                    now, vlan, pkt_meta.port, pkt_meta.eth_src, target_ip))
                if ofmsgs:
                    self.logger.info(
                        'Received advert for %s from %s' % (
                            target_ip, pkt_meta.log()))
        return ofmsgs

    def _vlan_routes(self, vlan):
        """Return vlan routes"""
        return vlan.routes_by_ipv(self.IPV)

    def _vlan_nexthop_cache(self, vlan):
        """Return vlan neighbour cache"""
        return vlan.neigh_cache_by_ipv(self.IPV)

    def expire_port_nexthops(self, port):
        """Expire all hosts on a port"""
        ofmsgs = []
        now = time.time()
        for vlan in port.vlans():
            nexthop_cache = self._vlan_nexthop_cache(vlan)
            dead_nexthops = [
                (ip_gw, nexthop_cache_entry) for ip_gw, nexthop_cache_entry in nexthop_cache.items()
                if nexthop_cache_entry and nexthop_cache_entry.port
                and port.number == nexthop_cache_entry.port.number]
            for ip_gw, nexthop_cache_entry in dead_nexthops:
                self.logger.info('marking %s as a dead nexthop' % nexthop_cache_entry.eth_src)
                ofmsgs.extend(self._expire_gateway_flows(ip_gw, nexthop_cache_entry, vlan, now))
        return ofmsgs

    def _vlan_nexthop_cache_entry(self, vlan, ip_gw):
        """Return nexthop cache entry"""
        nexthop_cache = self._vlan_nexthop_cache(vlan)
        return nexthop_cache.get(ip_gw, None)

    def _del_vlan_nexthop_cache_entry(self, vlan, ip_gw):
        nexthop_cache = self._vlan_nexthop_cache(vlan)
        del nexthop_cache[ip_gw]

    def _nexthop_actions(self, eth_dst, vlan):
        """Return flowrule actions for fib entry"""
        actions = []
        if self.routers:
            actions.append(self.fib_table.set_vlan_vid(vlan.vid))
        actions.extend([
            self.fib_table.set_field(eth_src=vlan.faucet_mac),
            self.fib_table.set_field(eth_dst=eth_dst)])
        if self.dec_ttl:
            actions.append(valve_of.dec_ip_ttl())
        return tuple(actions)

    def _route_match(self, vlan, ip_dst):
        """Return vid, dst, eth_type flowrule match for fib entry"""
        return self.fib_table.match(vlan=vlan, eth_type=self.ETH_TYPE, nw_dst=ip_dst)

    def _route_priority(self, ip_dst):
        """Return ip dst priority"""
        prefixlen = ipaddress.ip_network(ip_dst).prefixlen
        return self.route_priority + prefixlen

    def _router_for_vlan(self, vlan):
        """Return vlan router if any"""
        if self.routers:
            for router in self.routers.values():
                if vlan in router.vlans:
                    return router
        return None

    def _routed_vlans(self, vlan):
        """Return vlans that have routers"""
        if self.global_routing:
            return set([self.global_vlan])
        vlans = set([vlan])
        if self.routers:
            for router in self.routers.values():
                if vlan in router.vlans:
                    vlans = vlans.union(router.vlans)
        return vlans

    @staticmethod
    def _stateful_gw(vlan, dst_ip):
        return not dst_ip.is_link_local or vlan.ip_dsts_for_ip_gw(dst_ip)

    def _global_routing(self):
        """Return true if global routing is enabled"""
        return self.global_vlan.vid and self.routers and len(self.routers) == 1

    def _add_faucet_fib_to_vip(self, vlan, priority, faucet_vip, faucet_vip_host):
        """Router flowmods"""
        ofmsgs = []
        learn_connected_priority = self.route_priority + faucet_vip.network.prefixlen
        faucet_mac = vlan.faucet_mac
        actions = None
        if self.global_routing:
            vlan_mac = valve_packet.int_in_mac(faucet_mac, vlan.vid)
            actions = [
                self.fib_table.set_field(eth_dst=vlan_mac),
                self.fib_table.set_vlan_vid(self.global_vlan.vid)
            ]
        ofmsgs.extend(self.pipeline.select_packets(
            self.fib_table,
            {'eth_type': self.ETH_TYPE, 'eth_dst': faucet_mac, 'vlan': vlan},
            actions
        ))
        if self.global_routing:
            vlan = self.global_vlan
        ofmsgs.append(self.fib_table.flowmod(
            self._route_match(vlan, faucet_vip_host),
            priority=priority,
            inst=(self.fib_table.goto(self.vip_table),)))
        if self.proactive_learn and not faucet_vip.ip.is_link_local:
            routed_vlans = self._routed_vlans(vlan)
            for routed_vlan in routed_vlans:
                ofmsgs.append(self.fib_table.flowmod(
                    self._route_match(routed_vlan, faucet_vip),
                    priority=learn_connected_priority,
                    inst=(self.fib_table.goto(self.vip_table),)))
            # Unicast ICMP to us.
            priority -= 1
            ofmsgs.append(self.vip_table.flowcontroller(
                self.vip_table.match(
                    eth_type=self.ETH_TYPE,
                    eth_dst=faucet_mac,
                    nw_proto=self.ICMP_TYPE),
                priority=priority,
                max_len=self.ICMP_SIZE))
            # Learn + flood other ICMP not unicast to us.
            priority -= 1
            ofmsgs.append(self.vip_table.flowmod(
                self.vip_table.match(
                    eth_type=self.ETH_TYPE,
                    nw_proto=self.ICMP_TYPE),
                priority=priority,
                inst=self._controller_and_flood()))
            # Learn from other IP traffic unicast to us.
            priority -= 1
            ofmsgs.append(self.vip_table.flowcontroller(
                self.vip_table.match(
                    eth_type=self.ETH_TYPE,
                    eth_dst=faucet_mac),
                priority=priority,
                max_len=self.MAX_PACKET_IN_SIZE))
            # Learn + flood IP traffic not unicast to us.
            priority -= 1
            ofmsgs.append(self.vip_table.flowmod(
                self.vip_table.match(
                    eth_type=self.ETH_TYPE),
                priority=priority,
                inst=self._controller_and_flood()))
        return ofmsgs

    def _add_faucet_vip_nd(self, vlan, priority, faucet_vip, faucet_vip_host):
        raise NotImplementedError  # pragma: no cover

    def add_vlan(self, vlan, cold_start):
        """Add a VLAN."""
        ofmsgs = []
        # add controller IPs if configured.
        for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
            max_prefixlen = faucet_vip.ip.max_prefixlen
            faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
            priority = self.route_priority + max_prefixlen
            ofmsgs.extend(self._add_faucet_vip_nd(
                vlan, priority, faucet_vip, faucet_vip_host))
            ofmsgs.extend(self._add_faucet_fib_to_vip(
                vlan, priority, faucet_vip, faucet_vip_host))
        return ofmsgs

    def del_vlan(self, vlan):
        """Delete a VLAN."""
        ofmsgs = []
        if vlan.faucet_vips_by_ipv:
            ofmsgs.append(self.fib_table.flowdel(
                match=self.fib_table.match(vlan=vlan)))
        return ofmsgs

    def _add_resolved_route(self, vlan, ip_gw, ip_dst, eth_dst, is_updated):
        """Return flowmods for enabling routing of a resolved nexthop"""
        ofmsgs = []
        if is_updated:
            self.logger.info(
                'Updating next hop for route %s via %s (%s) on VLAN %u' % (
                    ip_dst, ip_gw, eth_dst, vlan.vid))
            ofmsgs.extend(self._del_route_flows(vlan, ip_dst))
        else:
            self.logger.info(
                'Adding new route %s via %s (%s) on VLAN %u' % (
                    ip_dst, ip_gw, eth_dst, vlan.vid))
        inst = self.pipeline.accept_to_l2_forwarding(
            actions=self._nexthop_actions(eth_dst, vlan))
        routed_vlans = self._routed_vlans(vlan)
        for routed_vlan in routed_vlans:
            in_match = self._route_match(routed_vlan, ip_dst)
            ofmsgs.append(self.fib_table.flowmod(
                in_match, priority=self._route_priority(ip_dst), inst=inst))
        return ofmsgs

    def _update_nexthop_cache(self, now, vlan, eth_src, port, ip_gw):
        """Add information to the nexthop cache and return the new object"""
        nexthop = NextHop(eth_src, port, now)
        nexthop_cache = self._vlan_nexthop_cache(vlan)
        nexthop_cache[ip_gw] = nexthop
        return nexthop

    def _update_nexthop(self, now, vlan, port, eth_src, resolved_ip_gw):
        """Update routes where nexthop is newly resolved or changed.

        Args:
            now (float): seconds since epoch.
            vlan (vlan): VLAN containing this RIB/FIB.
            port (port): port for nexthop.
            eth_src (str): MAC address for nexthop.
            resolved_ip_gw (IPAddress): IP address for nexthop
        Returns:
            list: OpenFlow messages, if routes need to be updated.
        """
        ofmsgs = []
        cached_eth_dst = self._cached_nexthop_eth_dst(vlan, resolved_ip_gw)

        if cached_eth_dst != eth_src:
            is_updated = cached_eth_dst is not None
            for ip_dst in vlan.ip_dsts_for_ip_gw(resolved_ip_gw):
                ofmsgs.extend(self._add_resolved_route(
                    vlan, resolved_ip_gw, ip_dst, eth_src, is_updated))

        self._update_nexthop_cache(now, vlan, eth_src, port, resolved_ip_gw)
        return ofmsgs

    def _vlan_unresolved_nexthops(self, vlan, ip_gws, now):
        """Return unresolved or expired IP gateways, never tried/oldest first.

        Args:
           vlan (vlan): VLAN containing this RIB/FIB.
           ip_gws (list): tuple, IP gateway and controller IP in same subnet.
           now (float): seconds since epoch.
        Returns:
           list: prioritized list of gateways.
        """
        vlan_nexthop_cache = self._vlan_nexthop_cache(vlan)
        nexthop_entries = [
            (ip_gw, vlan_nexthop_cache.get(ip_gw, None)) for ip_gw in ip_gws]
        not_fresh_nexthops = [
            (ip_gw, entry) for ip_gw, entry in nexthop_entries
            if entry is None or entry.resolution_due(now, self.neighbor_timeout)]
        unresolved_nexthops_by_retries = defaultdict(list)
        for ip_gw, entry in not_fresh_nexthops:
            if entry is None:
                entry = self._update_nexthop_cache(now, vlan, None, None, ip_gw)
            unresolved_nexthops_by_retries[entry.resolve_retries].append(ip_gw)
        unresolved_nexthops = deque()
        for _retries, nexthops in sorted(unresolved_nexthops_by_retries.items()):
            random.shuffle(nexthops)
            unresolved_nexthops.extend(nexthops)
        return unresolved_nexthops

    def advertise(self, vlan):
        raise NotImplementedError  # pragma: no cover

    def _resolve_gateway_flows(self, ip_gw, nexthop_cache_entry, vlan, now):
        """Return packet-out ofmsgs using ARP/ND to resolve for nexthop"""
        faucet_vip = vlan.vip_map(ip_gw)
        if not faucet_vip:
            self.logger.info('Not resolving %s (not in connected network)' % ip_gw)
            return []
        resolve_flows = []
        last_retry_time = nexthop_cache_entry.last_retry_time
        nexthop_cache_entry.next_retry(now, self.max_resolve_backoff_time)
        if (vlan.targeted_gw_resolution
                and last_retry_time is None and nexthop_cache_entry.port is not None):
            port = nexthop_cache_entry.port
            eth_dst = nexthop_cache_entry.eth_src
            resolve_flows = [self._resolve_gw_on_port(
                vlan, port, faucet_vip, ip_gw, eth_dst)]
        else:
            resolve_flows = self._resolve_gw_on_vlan(vlan, faucet_vip, ip_gw)
        if resolve_flows:
            if last_retry_time is None:
                self.logger.info(
                    'resolving %s (%u flows) on VLAN %u' % (ip_gw, len(resolve_flows), vlan.vid))
            else:
                self.logger.info(
                    'resolving %s retry %u (last attempt was %us ago; %u flows) on VLAN %u' % (
                        ip_gw,
                        nexthop_cache_entry.resolve_retries,
                        now - last_retry_time,
                        len(resolve_flows),
                        vlan.vid))
        return resolve_flows

    def _expire_gateway_flows(self, ip_gw, nexthop_cache_entry, vlan, now):
        """Return ofmsgs deleting the expired nexthop information"""
        expire_flows = []
        self.logger.info(
            'expiring dead route %s (age %us) on %s' % (
                ip_gw, nexthop_cache_entry.age(now), vlan))
        port = nexthop_cache_entry.port
        self._del_vlan_nexthop_cache_entry(vlan, ip_gw)
        expire_flows = self._del_host_fib_route(
            vlan, ipaddress.ip_network(ip_gw.exploded))
        if port is None:
            expire_flows = []
        return expire_flows

    def _resolve_expire_gateway_flows(self, ip_gw, nexthop_cache_entry, vlan, now):
        """If cache entry is dead then delete related flows
        otherwise return packet-out ofmsgs to resolve nexthops"""
        if self.nexthop_dead(nexthop_cache_entry):
            return self._expire_gateway_flows(ip_gw, nexthop_cache_entry, vlan, now)
        return self._resolve_gateway_flows(ip_gw, nexthop_cache_entry, vlan, now)

    def _resolve_gateways_flows(self, resolve_handler, vlan, now,
                                unresolved_nexthops, remaining_attempts):
        """Resolve for nexthops using the resolve_handler
        Return packet-out ofmsgs using V4 ARP/V6 ND to resolve nexthops
        """
        ofmsgs = []
        for ip_gw in unresolved_nexthops:
            if remaining_attempts == 0:
                break
            entry = self._vlan_nexthop_cache_entry(vlan, ip_gw)
            if entry is None:
                continue
            if not entry.resolution_due(now, self.neighbor_timeout):
                continue
            resolve_flows = resolve_handler(ip_gw, entry, vlan, now)
            if resolve_flows:
                ofmsgs.extend(resolve_flows)
                remaining_attempts -= 1
        return ofmsgs

    def resolve_gateways(self, vlan, now, resolve_all=True):
        """Re/resolve gateways.

        Args:
            vlan (vlan): VLAN containing this RIB/FIB.
            now (float): seconds since epoch.
            resolve_all (bool): attempt to resolve all unresolved gateways.
        Returns:
            list: OpenFlow messages.
        """
        unresolved_gateways = []
        if resolve_all:
            unresolved_gateways = self._vlan_unresolved_nexthops(
                vlan, vlan.dyn_route_gws_by_ipv[self.IPV], now)
            vlan.dyn_unresolved_route_ip_gws[self.IPV] = unresolved_gateways
        else:
            if vlan.dyn_unresolved_route_ip_gws[self.IPV]:
                unresolved_gateways = [vlan.dyn_unresolved_route_ip_gws[self.IPV].popleft()]
        return self._resolve_gateways_flows(
            self._resolve_gateway_flows, vlan, now,
            unresolved_gateways, self.max_hosts_per_resolve_cycle)

    def resolve_expire_hosts(self, vlan, now, resolve_all=True):
        """Re/resolve hosts.

        Args:
            vlan (vlan): VLAN containing this RIB/FIB.
            now (float): seconds since epoch.
            resolve_all (bool): attempt to resolve all unresolved gateways.
        Returns:
            list: OpenFlow messages.
        """
        unresolved_gateways = []
        if resolve_all:
            unresolved_gateways = self._vlan_unresolved_nexthops(
                vlan, vlan.dyn_host_gws_by_ipv[self.IPV], now)
            vlan.dyn_unresolved_host_ip_gws[self.IPV] = unresolved_gateways
        else:
            if vlan.dyn_unresolved_host_ip_gws[self.IPV]:
                unresolved_gateways = [vlan.dyn_unresolved_host_ip_gws[self.IPV].popleft()]
        return self._resolve_gateways_flows(
            self._resolve_expire_gateway_flows, vlan, now,
            unresolved_gateways, self.max_hosts_per_resolve_cycle)

    def _cached_nexthop_eth_dst(self, vlan, ip_gw):
        """Return nexthop cache entry eth_dst for the ip_gw"""
        entry = self._vlan_nexthop_cache_entry(vlan, ip_gw)
        if entry is not None and entry.eth_src is not None:
            return entry.eth_src
        return None

    @staticmethod
    def _host_ip_to_host_int(host_ip):
        return ipaddress.ip_interface(ipaddress.ip_network(host_ip))

    def _host_from_faucet_vip(self, faucet_vip):
        return self._host_ip_to_host_int(faucet_vip.ip)

    def _vlan_nexthop_cache_limit(self, vlan):
        raise NotImplementedError  # pragma: no cover

    def _proactive_resolve_neighbor(self, now, pkt_meta):
        """Packet not directly destined for router but we can learn from the packet anyway"""
        vlan = pkt_meta.vlan
        dst_ip = pkt_meta.l3_dst
        ofmsgs = []
        if self.proactive_learn:
            router = self._router_for_vlan(vlan)
            if router is None:
                faucet_vip = vlan.vip_map(dst_ip)
            else:
                vlan, faucet_vip = router.vip_map(dst_ip)
            if (vlan and vlan.ip_in_vip_subnet(dst_ip, faucet_vip)
                    and faucet_vip.ip != dst_ip and self._stateful_gw(vlan, dst_ip)):
                limit = self._vlan_nexthop_cache_limit(vlan)
                if limit is None or len(self._vlan_nexthop_cache(vlan)) < limit:
                    # TODO: avoid relearning L3 source if same L3 source tries
                    # multiple L3 destinations quickly.
                    ofmsgs.extend(self.add_host_fib_route_from_pkt(now, pkt_meta))
                    resolution_in_progress = dst_ip in vlan.dyn_host_gws_by_ipv[self.IPV]
                    ofmsgs.extend(self._add_host_fib_route(vlan, dst_ip, blackhole=True))
                    nexthop_cache_entry = self._update_nexthop_cache(
                        now, vlan, None, None, dst_ip)
                    if not resolution_in_progress:
                        resolve_flows = self._resolve_gateway_flows(
                            dst_ip, nexthop_cache_entry, vlan,
                            nexthop_cache_entry.cache_time)
                        ofmsgs.extend(resolve_flows)
        return ofmsgs

    def router_vlan_for_ip_gw(self, vlan, ip_gw):
        """Return router VLAN for IP gateway (or None).

        Args:
            vlan (vlan): VLAN containing this RIB.
            ip_gw (ipaddress.ip_address): IP address of nexthop.
        Returns:
            VLAN for this gateway or None.
        """
        router = self._router_for_vlan(vlan)
        if router is not None:
            vlan, _ = router.vip_map(ip_gw)
            return vlan
        if vlan.vip_map(ip_gw):
            return vlan
        return None

    def add_route(self, vlan, ip_gw, ip_dst):
        """Add a route to the RIB.

        Args:
            vlan (vlan): VLAN containing this RIB.
            ip_gw (ipaddress.ip_address): IP address of nexthop.
            ip_dst (ipaddress.ip_network): destination IP network.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        vlan = self.router_vlan_for_ip_gw(vlan, ip_gw)
        if vlan is None:
            self.logger.error(
                ('Cannot resolve destination VLAN for gateway %s '
                 '(not in global router?)' % ip_gw))
            return ofmsgs
        if vlan.is_faucet_vip(ip_dst):
            return ofmsgs
        routes = self._vlan_routes(vlan)
        if routes.get(ip_dst, None) == ip_gw:
            return ofmsgs

        vlan.add_route(ip_dst, ip_gw)
        cached_eth_dst = self._cached_nexthop_eth_dst(vlan, ip_gw)
        if cached_eth_dst is not None:
            ofmsgs.extend(self._add_resolved_route(
                vlan=vlan,
                ip_gw=ip_gw,
                ip_dst=ip_dst,
                eth_dst=cached_eth_dst,
                is_updated=False))
        return ofmsgs

    def _add_host_fib_route(self, vlan, host_ip, blackhole=False):
        """Add a host FIB route.

        Args:
            vlan (vlan): VLAN containing this RIB.
            host_ip (ipaddress.ip_address): IP address of host.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        if blackhole:
            priority = self._route_priority(host_ip)
            host_int = self._host_ip_to_host_int(host_ip)
            timeout = (
                self.max_resolve_backoff_time * self.max_host_fib_retry_count
                + random.randint(0, self.max_resolve_backoff_time * 2))
            routed_vlans = self._routed_vlans(vlan)
            for routed_vlan in routed_vlans:
                in_match = self._route_match(routed_vlan, host_int)
                ofmsgs.append(self.fib_table.flowmod(
                    in_match, priority=priority, hard_timeout=timeout))
        host_route = ipaddress.ip_network(host_ip.exploded)
        ofmsgs.extend(self.add_route(vlan, host_ip, host_route))
        return ofmsgs

    def _del_host_fib_route(self, vlan, host_ip):
        """Delete a host FIB route.

        Args:
            vlan (vlan): VLAN containing this RIB.
            host_ip (ipaddress.ip_address): IP address of host.
        Returns:
            list: OpenFlow messages.
        """
        host_route = ipaddress.ip_network(host_ip.exploded)
        return self.del_route(vlan, host_route)

    def _ip_pkt(self, pkt):
        """Return an IP packet from an Ethernet packet.

        Args:
            pkt: ryu.lib.packet from host.
        Returns:
            IP ryu.lib.packet parsed from pkt.
        """
        return pkt.get_protocol(self.IP_PKT)

    def add_host_fib_route_from_pkt(self, now, pkt_meta):
        """Add a host FIB route given packet from host.

        Args:
            now (float): seconds since epoch.
            pkt_meta (PacketMeta): received packet.
        Returns:
            list: OpenFlow messages.
        """
        src_ip = pkt_meta.l3_src
        ofmsgs = []
        if (src_ip and pkt_meta.vlan.ip_in_vip_subnet(src_ip)
                and self._stateful_gw(pkt_meta.vlan, src_ip)):
            ip_pkt = self._ip_pkt(pkt_meta.pkt)
            if ip_pkt:
                ofmsgs.extend(
                    self._add_host_fib_route(pkt_meta.vlan, src_ip, blackhole=False))
                ofmsgs.extend(self._update_nexthop(
                    now, pkt_meta.vlan, pkt_meta.port, pkt_meta.eth_src, src_ip))
        return ofmsgs

    def _del_route_flows(self, vlan, ip_dst):
        """Delete all flows matching the vlan and ip_dst"""
        ofmsgs = []
        routed_vlans = self._routed_vlans(vlan)
        for routed_vlan in routed_vlans:
            route_match = self._route_match(routed_vlan, ip_dst)
            ofmsgs.append(self.fib_table.flowdel(
                route_match, priority=self._route_priority(ip_dst), strict=True))
        return ofmsgs

    def del_route(self, vlan, ip_dst):
        """Delete a route from the RIB.

        Only one route with this exact destination is supported.

        Args:
            vlan (vlan): VLAN containing this RIB.
            ip_dst (ipaddress.ip_network): destination IP network.
        Returns:
            list: OpenFlow messages.
        """
        ofmsgs = []
        if vlan.is_faucet_vip(ip_dst):
            return ofmsgs
        routes = self._vlan_routes(vlan)
        if ip_dst in routes:
            vlan.del_route(ip_dst)
            ofmsgs.extend(self._del_route_flows(vlan, ip_dst))
        return ofmsgs

    def control_plane_handler(self, now, pkt_meta):
        return self._proactive_resolve_neighbor(now, pkt_meta)


class ValveIPv4RouteManager(ValveRouteManager):
    """Implement IPv4 RIB/FIB."""

    IPV = 4
    ETH_TYPE = valve_of.ether.ETH_TYPE_IP
    ICMP_TYPE = valve_of.inet.IPPROTO_ICMP
    ICMP_SIZE = valve_packet.VLAN_ICMP_ECHO_REQ_SIZE
    CONTROL_ETH_TYPES = (valve_of.ether.ETH_TYPE_IP, valve_of.ether.ETH_TYPE_ARP)  # type: ignore
    IP_PKT = ipv4.ipv4

    def advertise(self, _vlan):
        return []

    @staticmethod
    def _gw_resolve_pkt():
        return valve_packet.arp_request

    @staticmethod
    def _gw_respond_pkt():
        return valve_packet.arp_reply

    def _vlan_nexthop_cache_limit(self, vlan):
        return vlan.proactive_arp_limit

    def _add_faucet_vip_nd(self, vlan, priority, faucet_vip, faucet_vip_host):
        ofmsgs = []
        # ARP
        ofmsgs.extend(self.pipeline.select_packets(
            self.vip_table,
            {'eth_type': valve_of.ether.ETH_TYPE_ARP, 'vlan': vlan}
        ))
        # ARP for FAUCET VIP
        ofmsgs.append(self.vip_table.flowcontroller(
            self.vip_table.match(
                eth_type=valve_of.ether.ETH_TYPE_ARP,
                eth_dst=valve_of.mac.BROADCAST_STR,
                nw_dst=faucet_vip_host),
            priority=priority,
            max_len=valve_packet.VLAN_ARP_PKT_SIZE))
        # ARP reply to FAUCET VIP
        ofmsgs.append(self.vip_table.flowcontroller(
            self.vip_table.match(
                eth_type=valve_of.ether.ETH_TYPE_ARP,
                eth_dst=vlan.faucet_mac),
            priority=priority,
            max_len=valve_packet.VLAN_ARP_PKT_SIZE))
        priority -= 1
        # Other ARP
        ofmsgs.append(self.vip_table.flowmod(
            self.vip_table.match(
                eth_type=valve_of.ether.ETH_TYPE_ARP),
            priority=priority,
            inst=self.pipeline.accept_to_l2_forwarding()))
        return ofmsgs

    def _control_plane_arp_handler(self, now, pkt_meta):
        """Handle ARP packets destined for the router"""
        ofmsgs = []
        if not pkt_meta.eth_type == valve_of.ether.ETH_TYPE_ARP:
            return ofmsgs
        arp_pkt = pkt_meta.pkt.get_protocol(arp.arp)
        if arp_pkt is None:
            return ofmsgs
        opcode = arp_pkt.opcode
        if opcode == arp.ARP_REQUEST:
            if pkt_meta.eth_dst in (valve_of.mac.BROADCAST_STR, pkt_meta.vlan.faucet_mac):
                ofmsgs.extend(self._resolve_vip_response(pkt_meta, pkt_meta.l3_dst, now))
        elif opcode == arp.ARP_REPLY:
            if pkt_meta.eth_dst == pkt_meta.vlan.faucet_mac:
                ofmsgs.extend(self._gw_advert(pkt_meta, pkt_meta.l3_src, now))
        self.notify_learn(pkt_meta)
        return ofmsgs

    def _control_plane_icmp_handler(self, now, pkt_meta, ipv4_pkt):
        """Handle ICMP packets destined for the router"""
        ofmsgs = []
        if ipv4_pkt.proto != valve_of.inet.IPPROTO_ICMP:
            return ofmsgs
        if self._unicast_to_vip(pkt_meta):
            pkt_meta.reparse_all()
            icmp_pkt = pkt_meta.pkt.get_protocol(icmp.icmp)
            if icmp_pkt is None:
                return ofmsgs
            if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                ofmsgs.append(
                    pkt_meta.vlan.pkt_out_port(
                        valve_packet.echo_reply, pkt_meta.port,
                        pkt_meta.vlan.faucet_mac, pkt_meta.eth_src,
                        pkt_meta.l3_dst, pkt_meta.l3_src,
                        icmp_pkt.data))
                # ping but no previous ARP request for FAUCET VIP
                # from this host. Missed ARP request or host has
                # static ARP entry for us?
                if self._cached_nexthop_eth_dst(pkt_meta.vlan, pkt_meta.l3_src) is None:
                    ofmsgs.extend(self.add_host_fib_route_from_pkt(now, pkt_meta))
        return ofmsgs

    def control_plane_handler(self, now, pkt_meta):
        """Handle packets destined for router otherwise proactively learn host information"""
        if pkt_meta.packet_complete():
            arp_replies = self._control_plane_arp_handler(now, pkt_meta)
            if arp_replies:
                return arp_replies
            ipv4_pkt = self._ip_pkt(pkt_meta.pkt)
            if ipv4_pkt is None:
                return []
            icmp_replies = self._control_plane_icmp_handler(
                now, pkt_meta, ipv4_pkt)
            if icmp_replies:
                return icmp_replies
        return super().control_plane_handler(now, pkt_meta)


class ValveIPv6RouteManager(ValveRouteManager):
    """Implement IPv6 FIB."""

    IPV = 6
    ETH_TYPE = valve_of.ether.ETH_TYPE_IPV6
    ICMP_TYPE = valve_of.inet.IPPROTO_ICMPV6
    ICMP_SIZE = valve_packet.VLAN_ICMP6_ECHO_REQ_SIZE
    CONTROL_ETH_TYPES = (valve_of.ether.ETH_TYPE_IPV6,)  # type: ignore
    IP_PKT = ipv6.ipv6

    @staticmethod
    def _gw_resolve_pkt():
        return valve_packet.nd_request

    @staticmethod
    def _gw_respond_pkt():
        return valve_packet.nd_advert

    def _vlan_nexthop_cache_limit(self, vlan):
        return vlan.proactive_nd_limit

    def _add_faucet_vip_nd(self, vlan, priority, faucet_vip, faucet_vip_host):
        faucet_vip_host_nd_mcast = valve_packet.ipv6_link_eth_mcast(
            valve_packet.ipv6_solicited_node_from_ucast(faucet_vip.ip))
        ofmsgs = []
        # RA if this is a link local FAUCET VIP
        if faucet_vip.ip.is_link_local:
            match = {
                'eth_type': self.ETH_TYPE,
                'eth_dst': valve_packet.IPV6_ALL_ROUTERS_MCAST,
                'vlan': vlan
            }
            ofmsgs.extend(self.pipeline.select_packets(self.vip_table, match))
            ofmsgs.append(self.vip_table.flowmod(
                self.vip_table.match(
                    eth_type=self.ETH_TYPE,
                    eth_dst=valve_packet.IPV6_ALL_ROUTERS_MCAST,
                    nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                    icmpv6_type=icmpv6.ND_ROUTER_SOLICIT),
                priority=priority,
                inst=self._controller_and_flood()))
        # IPv6 ping unicast to FAUCET
        ofmsgs.append(self.vip_table.flowcontroller(
            self.vip_table.match(
                eth_type=self.ETH_TYPE,
                eth_dst=vlan.faucet_mac,
                nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                icmpv6_type=icmpv6.ICMPV6_ECHO_REQUEST),
            priority=priority,
            max_len=self.ICMP_SIZE))
        # IPv6 NA unicast to FAUCET.
        ofmsgs.append(self.vip_table.flowcontroller(
            self.vip_table.match(
                eth_type=self.ETH_TYPE,
                eth_dst=vlan.faucet_mac,
                nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT),
            priority=priority,
            max_len=self.ICMP_SIZE))
        # IPv6 NS for FAUCET VIP
        match = {
            'eth_type': self.ETH_TYPE,
            'eth_dst': faucet_vip_host_nd_mcast,
            'vlan': vlan
        }
        ofmsgs.extend(self.pipeline.select_packets(self.vip_table, match))
        ofmsgs.append(self.vip_table.flowmod(
            self.vip_table.match(
                eth_type=self.ETH_TYPE,
                eth_dst=faucet_vip_host_nd_mcast,
                nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT),
            priority=priority,
            inst=self._controller_and_flood()))
        return ofmsgs

    def _add_faucet_fib_to_vip(self, vlan, priority, faucet_vip, faucet_vip_host):
        ofmsgs = super()._add_faucet_fib_to_vip(
            vlan, priority, faucet_vip, faucet_vip_host)
        faucet_vip_broadcast = ipaddress.IPv6Interface(faucet_vip.network.broadcast_address)
        if self.global_routing:
            vlan = self.global_vlan
        ofmsgs.append(self.fib_table.flowmod(
            self._route_match(vlan, faucet_vip_broadcast),
            priority=priority,
            inst=(self.fib_table.goto(self.vip_table),)))
        return ofmsgs

    def _nd_solicit_handler(self, now, pkt_meta, _ipv6_pkt, icmpv6_pkt):
        ofmsgs = []
        solicited_ip = ipaddress.ip_address(icmpv6_pkt.data.dst)
        ofmsgs.extend(self._resolve_vip_response(pkt_meta, solicited_ip, now))
        self.notify_learn(pkt_meta)
        return ofmsgs

    def _nd_advert_handler(self, now, pkt_meta, _ipv6_pkt, icmpv6_pkt):
        ofmsgs = []
        target_ip = ipaddress.ip_address(icmpv6_pkt.data.dst)
        ofmsgs.extend(self._gw_advert(pkt_meta, target_ip, now))
        self.notify_learn(pkt_meta)
        return ofmsgs

    def _router_solicit_handler(self, _now, pkt_meta, _ipv6_pkt, _icmpv6_pkt):
        ofmsgs = []
        link_local_vips, other_vips = pkt_meta.vlan.link_and_other_vips(self.IPV)
        for vip in link_local_vips:
            if pkt_meta.l3_src in vip.network:
                ofmsgs.append(
                    pkt_meta.vlan.pkt_out_port(
                        valve_packet.router_advert, pkt_meta.port,
                        pkt_meta.vlan.faucet_mac, pkt_meta.eth_src,
                        vip.ip, pkt_meta.l3_src, other_vips))
                self.logger.info(
                    'Responded to RS solicit from %s (%s)' % (
                        pkt_meta.l3_src, pkt_meta.log()))
                break
        return ofmsgs

    def _echo_request_handler(self, now, pkt_meta, ipv6_pkt, icmpv6_pkt):
        ofmsgs = []
        if self._unicast_to_vip(pkt_meta):
            ofmsgs.append(
                pkt_meta.vlan.pkt_out_port(
                    valve_packet.icmpv6_echo_reply, pkt_meta.port,
                    pkt_meta.vlan.faucet_mac, pkt_meta.eth_src,
                    pkt_meta.l3_dst, pkt_meta.l3_src, ipv6_pkt.hop_limit,
                    icmpv6_pkt.data.id, icmpv6_pkt.data.seq,
                    icmpv6_pkt.data.data))
            # ping but no previous ND request for FAUCET VIP
            # from this host. Missed ND request or host has
            # static ND entry for us?
            if self._cached_nexthop_eth_dst(pkt_meta.vlan, pkt_meta.l3_src) is None:
                ofmsgs.extend(self.add_host_fib_route_from_pkt(now, pkt_meta))
        return ofmsgs

    _icmpv6_handlers = {
        icmpv6.ND_NEIGHBOR_SOLICIT: (_nd_solicit_handler, icmpv6.nd_neighbor, 32),
        icmpv6.ND_NEIGHBOR_ADVERT: (_nd_advert_handler, icmpv6.nd_neighbor, 32),
        icmpv6.ND_ROUTER_SOLICIT: (_router_solicit_handler, None, 32),
        icmpv6.ICMPV6_ECHO_REQUEST: (_echo_request_handler, icmpv6.echo, 96),
    }

    def _control_plane_icmpv6_handler(self, now, pkt_meta, ipv6_pkt):
        """Handle ICMPv6 packets destined for router"""
        ofmsgs = []
        # Must be ICMPv6 and have no extended headers.
        if ipv6_pkt.nxt != valve_of.inet.IPPROTO_ICMPV6:
            return ofmsgs
        if ipv6_pkt.ext_hdrs:
            return ofmsgs
        src_ip = pkt_meta.l3_src
        vlan = pkt_meta.vlan
        if not vlan.ip_in_vip_subnet(src_ip):
            return ofmsgs
        reparse_size = 32
        pkt_meta.reparse_ip(payload=reparse_size)
        icmpv6_pkt = pkt_meta.pkt.get_protocol(icmpv6.icmpv6)
        if icmpv6_pkt is None:
            return ofmsgs
        icmpv6_type = icmpv6_pkt.type_
        if (ipv6_pkt.hop_limit != valve_packet.IPV6_MAX_HOP_LIM
                and icmpv6_type != icmpv6.ICMPV6_ECHO_REQUEST):
            return ofmsgs
        handler, payload_type, type_reparse_size = self._icmpv6_handlers.get(
            icmpv6_type, (None, None, None))
        if handler is not None and (
                payload_type is None
                or isinstance(icmpv6_pkt.data, payload_type)):
            if type_reparse_size != reparse_size:
                pkt_meta.reparse_ip(payload=type_reparse_size)
                icmpv6_pkt = pkt_meta.pkt.get_protocol(icmpv6.icmpv6)
            ofmsgs = handler(self, now, pkt_meta, ipv6_pkt, icmpv6_pkt)
        return ofmsgs

    def control_plane_handler(self, now, pkt_meta):
        """Resolve packets destined for router or proactively learn host information"""
        if pkt_meta.packet_complete():
            ipv6_pkt = self._ip_pkt(pkt_meta.pkt)
            if ipv6_pkt is not None:
                icmp_replies = self._control_plane_icmpv6_handler(
                    now, pkt_meta, ipv6_pkt)
                if icmp_replies:
                    return icmp_replies
        return super().control_plane_handler(now, pkt_meta)

    def advertise(self, vlan):
        ofmsgs = []
        link_local_vips, other_vips = vlan.link_and_other_vips(self.IPV)
        for link_local_vip in link_local_vips:
            # https://tools.ietf.org/html/rfc4861#section-6.1.2
            ofmsgs.extend(vlan.flood_pkt(
                valve_packet.router_advert, self.multi_out,
                vlan.faucet_mac,
                valve_packet.IPV6_ALL_NODES_MCAST,
                link_local_vip.ip, valve_packet.IPV6_ALL_NODES,
                other_vips))
        return ofmsgs
