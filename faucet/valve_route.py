"""Valve IPv4/IPv6 routing implementation."""

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

import time

import ipaddress

from ryu.lib.packet import arp, icmp, icmpv6, ipv4, ipv6

from faucet import valve_of
from faucet import valve_packet
from faucet.valve_util import btos


class NextHop(object):
    """Describes a directly connected (at layer 2) nexthop."""

    def __init__(self, eth_src, now):
        self.eth_src = eth_src
        self.cache_time = now
        self.last_retry_time = None
        self.resolve_retries = 0


class ValveRouteManager(object):
    """Base class to implement RIB/FIB."""

    IPV = None
    ETH_TYPE = None
    ICMP_TYPE = None
    MAX_LEN = 96
    CONTROL_ETH_TYPES = None

    def __init__(self, logger, arp_neighbor_timeout,
                 max_hosts_per_resolve_cycle, max_host_fib_retry_count,
                 max_resolve_backoff_time, proactive_learn, dec_ttl,
                 fib_table, vip_table, eth_src_table, eth_dst_table, flood_table,
                 route_priority, routers, use_group_table, groups):
        self.logger = logger
        self.arp_neighbor_timeout = arp_neighbor_timeout
        self.max_hosts_per_resolve_cycle = max_hosts_per_resolve_cycle
        self.max_host_fib_retry_count = max_host_fib_retry_count
        self.max_resolve_backoff_time = max_resolve_backoff_time
        self.proactive_learn = proactive_learn
        self.dec_ttl = dec_ttl
        self.fib_table = fib_table
        self.vip_table = vip_table
        self.eth_src_table = eth_src_table
        self.eth_dst_table = eth_dst_table
        self.flood_table = flood_table
        self.route_priority = route_priority
        self.routers = routers
        self.use_group_table = use_group_table
        self.groups = groups

    @staticmethod
    def _vlan_vid(vlan, port):
        vid = None
        if vlan.port_is_tagged(port):
            vid = vlan.vid
        return vid

    def _vlan_routes(self, vlan):
        return vlan.routes_by_ipv(self.IPV)

    def _vlan_nexthop_cache(self, vlan):
        return vlan.neigh_cache_by_ipv(self.IPV)

    def _vlan_nexthop_cache_entry(self, vlan, ip_gw):
        nexthop_cache = self._vlan_nexthop_cache(vlan)
        if ip_gw in nexthop_cache:
            return nexthop_cache[ip_gw]
        return None

    def _group_id_from_ip_gw(self, vlan, resolved_ip_gw):
        return self.groups.group_id_from_str(
            ''.join((str(vlan), str(resolved_ip_gw))))

    def _neighbor_resolver_pkt(self, vlan, vid, faucet_vip, ip_gw):
        pass

    def resolve_gw_on_vlan(self, vlan, faucet_vip, ip_gw):
        return vlan.flood_pkt(
            self._neighbor_resolver_pkt, faucet_vip, ip_gw)

    def _nexthop_actions(self, eth_dst, vlan):
        ofmsgs = []
        if self.routers:
            ofmsgs.append(valve_of.set_vlan_vid(vlan.vid))
        ofmsgs.extend([
            valve_of.set_eth_src(vlan.faucet_mac),
            valve_of.set_eth_dst(eth_dst)])
        if self.dec_ttl:
            ofmsgs.append(valve_of.dec_ip_ttl())
        return ofmsgs

    def _route_match(self, vlan, ip_dst):
        return self.fib_table.match(vlan=vlan, eth_type=self.ETH_TYPE, nw_dst=ip_dst)

    def _route_priority(self, ip_dst):
        prefixlen = ipaddress.ip_network(ip_dst).prefixlen
        return self.route_priority + prefixlen

    def _routed_vlans(self, vlan):
        vlans = set([vlan])
        if self.routers:
            for router in list(self.routers.values()):
                if vlan in router.vlans:
                    for other_vlan in router.vlans:
                        vlans.add(other_vlan)
        return vlans

    def _add_faucet_fib_to_vip(self, vlan, priority, faucet_vip, faucet_vip_host):
        learn_connected_priority = self.route_priority + faucet_vip.network.prefixlen
        ofmsgs = []
        ofmsgs.append(self.eth_src_table.flowmod(
            self.eth_src_table.match(eth_type=self.ETH_TYPE, eth_dst=vlan.faucet_mac, vlan=vlan),
            priority=self.route_priority,
            inst=[valve_of.goto_table(self.fib_table)]))
        ofmsgs.append(self.fib_table.flowmod(
            self.fib_table.match(eth_type=self.ETH_TYPE, vlan=vlan, nw_dst=faucet_vip_host),
            priority=priority,
            inst=[valve_of.goto_table(self.vip_table)]))
        if self.proactive_learn:
            for routed_vlan in self._routed_vlans(vlan):
                ofmsgs.append(self.fib_table.flowmod(
                    self.fib_table.match(eth_type=self.ETH_TYPE, vlan=routed_vlan, nw_dst=faucet_vip),
                    priority=learn_connected_priority,
                    inst=[valve_of.goto_table(self.vip_table)]))
            ofmsgs.append(self.vip_table.flowcontroller(
                self.vip_table.match(eth_type=self.ETH_TYPE),
                priority=priority-1,
                max_len=self.MAX_LEN))
        return ofmsgs

    def _add_faucet_vip_nd(self, vlan, priority, faucet_vip, faucet_vip_host):
        return []

    def add_faucet_vip(self, vlan, faucet_vip):
        ofmsgs = []
        max_prefixlen = faucet_vip.ip.max_prefixlen
        faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
        priority = self.route_priority + max_prefixlen
        ofmsgs.extend(self._add_faucet_vip_nd(
            vlan, priority, faucet_vip, faucet_vip_host))
        ofmsgs.extend(self._add_faucet_fib_to_vip(
            vlan, priority, faucet_vip, faucet_vip_host))
        return ofmsgs

    def _add_resolved_route(self, vlan, ip_gw, ip_dst, eth_dst, is_updated):
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
        if self.use_group_table:
            inst = [valve_of.apply_actions([valve_of.group_act(
                group_id=self._group_id_from_ip_gw(vlan, ip_gw))])]
        else:
            inst = [valve_of.apply_actions(self._nexthop_actions(eth_dst, vlan)),
                    valve_of.goto_table(self.eth_dst_table)]
        for routed_vlan in self._routed_vlans(vlan):
            in_match = self._route_match(routed_vlan, ip_dst)
            ofmsgs.append(self.fib_table.flowmod(
                in_match, priority=self._route_priority(ip_dst), inst=inst))
        return ofmsgs

    def _update_nexthop_cache(self, vlan, eth_src, ip_gw):
        now = time.time()
        nexthop = NextHop(eth_src, now)
        nexthop_cache = self._vlan_nexthop_cache(vlan)
        nexthop_cache[ip_gw] = nexthop

    def _nexthop_group_buckets(self, vlan, port, eth_src):
        actions = self._nexthop_actions(eth_src, vlan)
        if not vlan.port_is_tagged(port):
            actions.append(valve_of.pop_vlan())
        actions.append(valve_of.output_port(port.number))
        buckets = [valve_of.bucket(actions=actions)]
        return buckets

    def _update_nexthop_group(self, is_updated, resolved_ip_gw,
                              vlan, port, eth_src):
        group_id = self._group_id_from_ip_gw(vlan, resolved_ip_gw)
        buckets = self._nexthop_group_buckets(vlan, port, eth_src)
        nexthop_group = self.groups.get_entry(
            group_id, buckets)
        ofmsgs = []
        if is_updated:
            ofmsgs.append(nexthop_group.modify())
        else:
            ofmsgs.extend(nexthop_group.add())
        return ofmsgs

    def _update_nexthop(self, vlan, port, eth_src, resolved_ip_gw):
        """Update routes where nexthop is newly resolved or changed.

        Args:
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

            if self.use_group_table:
                ofmsgs.extend(
                    self._update_nexthop_group(
                        is_updated, resolved_ip_gw,
                        vlan, port, eth_src))
            routes = self._vlan_routes(vlan)
            for ip_dst, ip_gw in list(routes.items()):
                if ip_gw == resolved_ip_gw:
                    ofmsgs.extend(self._add_resolved_route(
                        vlan, ip_gw, ip_dst, eth_src, is_updated))

        self._update_nexthop_cache(vlan, eth_src, resolved_ip_gw)
        return ofmsgs

    def _vlan_ip_gws(self, vlan):
        """Return IP gateways in VLAN.

        Args:
            vlan (vlan): VLAN containing this RIB/FIB.
        Returns:
            list: tuple, gateway, controller IP in same subnet.
        """
        routes = self._vlan_routes(vlan)
        ip_gws = []
        for ip_gw in set(routes.values()):
            for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
                if ip_gw in faucet_vip.network:
                    ip_gws.append((ip_gw, faucet_vip))
        return ip_gws

    def _add_unresolved_nexthops(self, vlan, ip_gws):
        """Populates any missing nexthop cache entries.

        Args:
           vlan (vlan): VLAN containing this RIB/FIB.
           ip_gws (list): tuple, IP gateway and controller IP in same subnet.
        """
        for ip_gw, _ in ip_gws:
            if self._vlan_nexthop_cache_entry(vlan, ip_gw) is None:
                self._update_nexthop_cache(vlan, None, ip_gw)

    def _retry_backoff(self, now, resolve_retries, last_retry_time):
        backoff_seconds = min(
            2**resolve_retries, self.max_resolve_backoff_time)
        if now - last_retry_time > backoff_seconds:
            return True
        return False

    def _vlan_unresolved_nexthops(self, vlan, ip_gws, now):
        """Return unresolved or expired IP gateways, never tried/oldest first.

        Args:
           vlan (vlan): VLAN containing this RIB/FIB.
           ip_gws (list): tuple, IP gateway and controller IP in same subnet.
           now (float): seconds since epoch.
        Returns:
           list: tuple, gateway, controller IP in same subnet, last retry time.
        """
        ip_gws_never_tried = []
        ip_gws_with_retry_time = []
        for ip_gw, faucet_vip in ip_gws:
            if self._nexthop_fresh(vlan, ip_gw, now):
                continue
            nexthop_cache_entry = self._vlan_nexthop_cache_entry(vlan, ip_gw)
            last_retry_time = nexthop_cache_entry.last_retry_time
            ip_gw_with_retry_time = (ip_gw, faucet_vip, last_retry_time)
            if last_retry_time is None:
                ip_gws_never_tried.append(ip_gw_with_retry_time)
            else:
                if self._retry_backoff(
                        now, nexthop_cache_entry.resolve_retries, last_retry_time):
                    ip_gws_with_retry_time.append(ip_gw_with_retry_time)
        ip_gws_with_retry_time_sorted = list(
            sorted(ip_gws_with_retry_time, key=lambda x: x[-1]))
        return ip_gws_never_tried + ip_gws_with_retry_time_sorted

    def _is_host_fib_route(self, vlan, host_ip):
        """Return True if IP destination is a host FIB route.

        Args:
            vlan (vlan): VLAN containing this RIB/FIB.
            ip_gw (ipaddress.ip_address): potential host FIB route.
        Returns:
            True if a host FIB route (and not used as a gateway).
        """
        routes = self._vlan_routes(vlan)
        in_fib = False
        for ip_dst, ip_gw in list(routes.items()):
            if ip_gw == host_ip:
                in_fib = True
                if ip_dst.prefixlen < ip_dst.max_prefixlen:
                    return False
        return in_fib

    def advertise(self, vlan):
        return []

    def resolve_gateways(self, vlan, now):
        """Re/resolve all gateways.

        Args:
            vlan (vlan): VLAN containing this RIB/FIB.
            now (float): seconds since epoch.
        Returns:
            list: OpenFlow messages.
        """
        ip_gws = self._vlan_ip_gws(vlan)
        self._add_unresolved_nexthops(vlan, ip_gws)
        all_unresolved_nexthops = self._vlan_unresolved_nexthops(
            vlan, ip_gws, now)
        cycle_unresolved_nexthops = all_unresolved_nexthops[
            :self.max_hosts_per_resolve_cycle]
        deferred_unresolved_nexthops = (len(all_unresolved_nexthops) -
                                        len(cycle_unresolved_nexthops))
        if deferred_unresolved_nexthops:
            self.logger.info(
                'deferring resolution of %u nexthops on VLAN %u' % (
                    deferred_unresolved_nexthops, vlan.vid))
        ofmsgs = []
        for ip_gw, faucet_vip, last_retry_time in cycle_unresolved_nexthops:
            nexthop_cache_entry = self._vlan_nexthop_cache_entry(vlan, ip_gw)
            if (self._is_host_fib_route(vlan, ip_gw) and
                    nexthop_cache_entry.resolve_retries >= self.max_host_fib_retry_count):
                self.logger.info(
                    'expiring dead host FIB route %s (age %us) on VLAN %u' % (
                        ip_gw,
                        now - nexthop_cache_entry.cache_time,
                        vlan.vid))
                ofmsgs.extend(self._del_host_fib_route(
                    vlan, ipaddress.ip_network(ip_gw.exploded)))
            else:
                nexthop_cache_entry.last_retry_time = now
                nexthop_cache_entry.resolve_retries += 1
                resolve_flows = self.resolve_gw_on_vlan(vlan, faucet_vip, ip_gw)
                if last_retry_time is None:
                    self.logger.debug(
                        'resolving %s (%u flows) on VLAN %u' % (
                            ip_gw, len(resolve_flows), vlan.vid))
                else:
                    self.logger.info(
                        'resolving %s retry %u (last attempt was %us ago; %u flows) on VLAN %u' % (
                            ip_gw,
                            nexthop_cache_entry.resolve_retries,
                            now - last_retry_time,
                            len(resolve_flows),
                            vlan.vid))
                ofmsgs.extend(resolve_flows)
        return ofmsgs

    def _cached_nexthop_eth_dst(self, vlan, ip_gw):
        nexthop_cache_entry = self._vlan_nexthop_cache_entry(vlan, ip_gw)
        if (nexthop_cache_entry is not None and
                nexthop_cache_entry.eth_src is not None):
            return nexthop_cache_entry.eth_src
        return None

    @staticmethod
    def _host_ip_to_host_int(host_ip):
        return ipaddress.ip_interface(ipaddress.ip_network(host_ip))

    def _host_from_faucet_vip(self, faucet_vip):
        return self._host_ip_to_host_int(faucet_vip.ip)

    def _vlan_nexthop_cache_limit(self, vlan):
        pass

    def _proactive_resolve_neighbor(self, vlans, dst_ip):
        ofmsgs = []
        if not self.proactive_learn:
            return []
        for vlan in vlans:
            limit = self._vlan_nexthop_cache_limit(vlan)
            faucet_vip = vlan.ip_in_vip_subnet(dst_ip)
            if faucet_vip and not vlan.is_faucet_vip(dst_ip):
                if self._is_host_fib_route(vlan, dst_ip):
                    self.logger.debug(
                        'not proactively learning %s, already trying on VLAN %u' % (
                            dst_ip, vlan.vid))
                    break
                if (limit is not None and
                        len(self._vlan_nexthop_cache(vlan)) >= limit):
                    self.logger.debug(
                        'not proactively learning %s, at limit %u on VLAN %u' % (
                            dst_ip, limit, vlan.vid))
                    break
                priority = self._route_priority(dst_ip)
                dst_int = self._host_ip_to_host_int(dst_ip)
                in_match = self._route_match(vlan, dst_int)
                ofmsgs.append(self.fib_table.flowmod(
                    in_match, priority=priority, hard_timeout=self.arp_neighbor_timeout))
                ofmsgs.extend(
                    self._add_host_fib_route(vlan, dst_ip))
                resolve_flows = self.resolve_gw_on_vlan(
                    vlan, faucet_vip, dst_ip)
                ofmsgs.extend(resolve_flows)
                self.logger.debug(
                    'proactively resolving %s (%u flows) on VLAN %u' % (
                        dst_ip, len(resolve_flows), vlan.vid))
                break
        return ofmsgs

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
        if vlan.is_faucet_vip(ip_dst):
            return ofmsgs
        routes = self._vlan_routes(vlan)
        if ip_dst in routes:
            if routes[ip_dst] == ip_gw:
                return ofmsgs

        routes[ip_dst] = ip_gw
        cached_eth_dst = self._cached_nexthop_eth_dst(vlan, ip_gw)
        if cached_eth_dst is not None:
            ofmsgs.extend(self._add_resolved_route(
                vlan=vlan,
                ip_gw=ip_gw,
                ip_dst=ip_dst,
                eth_dst=cached_eth_dst,
                is_updated=False))
        return ofmsgs

    def _add_host_fib_route(self, vlan, host_ip):
        """Add a host FIB route.

        Args:
            vlan (vlan): VLAN containing this RIB.
            host_ip (ipaddress.ip_address): IP address of host.
        Returns:
            list: OpenFlow messages.
        """
        host_route = ipaddress.ip_network(host_ip.exploded)
        return self.add_route(vlan, host_ip, host_route)

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
        pass

    def _nexthop_fresh(self, vlan, ip_gw, now):
        nexthop_cache_entry = self._vlan_nexthop_cache_entry(vlan, ip_gw)
        if nexthop_cache_entry is not None:
            if nexthop_cache_entry.eth_src is not None:
                cache_time = nexthop_cache_entry.cache_time
                cache_age = now - cache_time
                if cache_age < self.arp_neighbor_timeout:
                    return True
        return False

    def add_host_fib_route_from_pkt(self, pkt_meta):
        """Add a host FIB route given packet from host.

        Args:
            pkt_meta (PacketMeta): received packet.
        Returns:
            list: OpenFlow messages.
        """
        ip_pkt = self._ip_pkt(pkt_meta.pkt)
        ofmsgs = []
        if ip_pkt:
            src_ip = ipaddress.ip_address(btos(ip_pkt.src))
            if src_ip and pkt_meta.vlan.ip_in_vip_subnet(src_ip):
                ofmsgs.extend(
                    self._add_host_fib_route(pkt_meta.vlan, src_ip))
                ofmsgs.extend(self._update_nexthop(
                    pkt_meta.vlan, pkt_meta.port, pkt_meta.eth_src, src_ip))
        return ofmsgs

    def _del_route_flows(self, vlan, ip_dst):
        ofmsgs = []
        for routed_vlan in self._routed_vlans(vlan):
            if ip_dst.prefixlen == 0:
                route_match = self.fib_table.match(
                    vlan=routed_vlan, eth_type=self.ETH_TYPE)
            else:
                route_match = self.fib_table.match(
                    vlan=routed_vlan, eth_type=self.ETH_TYPE, nw_dst=ip_dst)
            ofmsgs.extend(self.fib_table.flowdel(
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
            del routes[ip_dst]
            ofmsgs.extend(self._del_route_flows(vlan, ip_dst))
            # TODO: need to delete nexthop group if groups are in use.
        return ofmsgs

    def control_plane_handler(self, pkt_meta):
        pass


class ValveIPv4RouteManager(ValveRouteManager):
    """Implement IPv4 RIB/FIB."""

    IPV = 4
    ETH_TYPE = valve_of.ether.ETH_TYPE_IP
    ICMP_TYPE = valve_of.inet.IPPROTO_ICMP
    CONTROL_ETH_TYPES = (
        valve_of.ether.ETH_TYPE_IP, valve_of.ether.ETH_TYPE_ARP)


    def _vlan_nexthop_cache_limit(self, vlan):
        return vlan.proactive_arp_limit

    def _neighbor_resolver_pkt(self, vlan, vid, faucet_vip, ip_gw):
        return valve_packet.arp_request(
            vid, vlan.faucet_mac, faucet_vip.ip, ip_gw)

    def _ip_pkt(self, pkt):
        return pkt.get_protocol(ipv4.ipv4)

    def _add_faucet_vip_nd(self, vlan, priority, faucet_vip, faucet_vip_host):
        ofmsgs = []
        ofmsgs.append(self.eth_src_table.flowmod(
            self.eth_src_table.match(
                eth_type=valve_of.ether.ETH_TYPE_ARP,
                vlan=vlan),
            priority=priority,
            inst=[valve_of.goto_table(self.vip_table)]))
        ofmsgs.append(self.vip_table.flowmod(
            self.vip_table.match(
                eth_type=valve_of.ether.ETH_TYPE_ARP),
            priority=priority,
            inst=[valve_of.goto_table(self.eth_dst_table)]))
        priority += 1
        ofmsgs.append(self.vip_table.flowmod(
            self.vip_table.match(
                eth_type=valve_of.ether.ETH_TYPE_ARP,
                eth_dst=valve_of.mac.BROADCAST_STR),
            priority=priority,
            inst=[valve_of.goto_table(self.flood_table)]))
        priority += 1
        ofmsgs.append(self.vip_table.flowcontroller(
            self.vip_table.match(
                eth_type=valve_of.ether.ETH_TYPE_ARP,
                nw_dst=faucet_vip_host),
            priority=priority,
            max_len=self.MAX_LEN))
        return ofmsgs

    def _control_plane_arp_handler(self, pkt_meta):
        ofmsgs = []
        if not pkt_meta.packet_complete():
            return ofmsgs
        pkt_meta.reparse_ip(valve_of.ether.ETH_TYPE_ARP)
        arp_pkt = pkt_meta.pkt.get_protocol(arp.arp)
        if arp_pkt is None:
            return ofmsgs
        src_ip = ipaddress.IPv4Address(btos(arp_pkt.src_ip))
        dst_ip = ipaddress.IPv4Address(btos(arp_pkt.dst_ip))
        vlan = pkt_meta.vlan
        if vlan.from_connected_to_vip(src_ip, dst_ip):
            opcode = arp_pkt.opcode
            port = pkt_meta.port
            eth_src = pkt_meta.eth_src
            vid = self._vlan_vid(vlan, port)
            if opcode == arp.ARP_REQUEST:
                ofmsgs.extend(
                    self._add_host_fib_route(vlan, src_ip))
                ofmsgs.extend(self._update_nexthop(
                    vlan, port, eth_src, src_ip))
                arp_reply = valve_packet.arp_reply(
                    vid, vlan.faucet_mac, eth_src, dst_ip, src_ip)
                ofmsgs.append(
                    valve_of.packetout(port.number, arp_reply.data))
                self.logger.info(
                    'Responded to ARP request for %s from %s (%s) on VLAN %u' % (
                        dst_ip, src_ip, eth_src, vlan.vid))
            elif (opcode == arp.ARP_REPLY and
                  pkt_meta.eth_dst == vlan.faucet_mac):
                ofmsgs.extend(
                    self._update_nexthop(vlan, port, eth_src, src_ip))
                self.logger.info(
                    'ARP response %s (%s) on VLAN %u' % (
                        src_ip, eth_src, vlan.vid))
        return ofmsgs

    def _control_plane_icmp_handler(self, pkt_meta, ipv4_pkt):
        ofmsgs = []
        if not pkt_meta.packet_complete():
            return ofmsgs

        src_ip = ipaddress.IPv4Address(btos(ipv4_pkt.src))
        dst_ip = ipaddress.IPv4Address(btos(ipv4_pkt.dst))
        vlan = pkt_meta.vlan
        if vlan.from_connected_to_vip(src_ip, dst_ip):
            if pkt_meta.eth_dst != vlan.faucet_mac:
                return ofmsgs
            if ipv4_pkt.proto != valve_of.inet.IPPROTO_ICMP:
                return ofmsgs
            pkt_meta.reparse_all()
            icmp_pkt = pkt_meta.pkt.get_protocol(icmp.icmp)
            if icmp_pkt is None:
                return ofmsgs
            if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                port = pkt_meta.port
                vid = self._vlan_vid(vlan, port)
                echo_reply = valve_packet.echo_reply(
                    vid, vlan.faucet_mac, pkt_meta.eth_src,
                    dst_ip, src_ip, icmp_pkt.data)
                ofmsgs.append(
                    valve_of.packetout(port.number, echo_reply.data))
        return ofmsgs

    def control_plane_handler(self, pkt_meta):
        ipv4_pkt = pkt_meta.pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt is None:
            return self._control_plane_arp_handler(pkt_meta)
        else:
            icmp_replies = self._control_plane_icmp_handler(
                pkt_meta, ipv4_pkt)
            if icmp_replies:
                return icmp_replies
            dst_ip = ipaddress.IPv4Address(btos(ipv4_pkt.dst))
            vlan = pkt_meta.vlan
            return self._proactive_resolve_neighbor(
                self._routed_vlans(vlan), dst_ip)
        return []


class ValveIPv6RouteManager(ValveRouteManager):
    """Implement IPv6 FIB."""

    IPV = 6
    ETH_TYPE = valve_of.ether.ETH_TYPE_IPV6
    ICMP_TYPE = valve_of.inet.IPPROTO_ICMPV6
    MAX_LEN = 128
    CONTROL_ETH_TYPES = (valve_of.ether.ETH_TYPE_IPV6,)


    def _vlan_nexthop_cache_limit(self, vlan):
        return vlan.proactive_nd_limit

    def _neighbor_resolver_pkt(self, vlan, vid, faucet_vip, ip_gw):
        return valve_packet.nd_request(
            vid, vlan.faucet_mac, faucet_vip.ip, ip_gw)

    def _ip_pkt(self, pkt):
        return pkt.get_protocol(ipv6.ipv6)

    def _add_faucet_vip_nd(self, vlan, priority, faucet_vip, faucet_vip_host):
        faucet_vip_host_nd_mcast = valve_packet.ipv6_link_eth_mcast(
            valve_packet.ipv6_solicited_node_from_ucast(faucet_vip.ip))
        controller_and_flood = [
            valve_of.apply_actions([valve_of.output_controller()]),
            valve_of.goto_table(self.flood_table)]
        ofmsgs = []
        ofmsgs.append(self.vip_table.flowcontroller(
            self.vip_table.match(
                eth_type=self.ETH_TYPE,
                nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                icmpv6_type=icmpv6.ICMPV6_ECHO_REQUEST),
            priority=priority))
        # IPv6 ND for FAUCET VIP
        ofmsgs.append(self.eth_src_table.flowmod(
            self.eth_src_table.match(
                eth_type=self.ETH_TYPE,
                eth_dst=faucet_vip_host_nd_mcast,
                vlan=vlan),
            priority=priority,
            inst=[valve_of.goto_table(self.vip_table)]))
        ofmsgs.append(self.vip_table.flowmod(
            self.vip_table.match(
                eth_type=self.ETH_TYPE,
                nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT),
            priority=priority,
            inst=controller_and_flood))
        # IPv6 ND for connected hosts.
        ofmsgs.append(self.vip_table.flowcontroller(
            self.vip_table.match(
                eth_type=self.ETH_TYPE,
                eth_dst=vlan.faucet_mac,
                nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT),
            priority=priority))
        if faucet_vip.ip in valve_packet.IPV6_LINK_LOCAL:
            ofmsgs.append(self.eth_src_table.flowmod(
                self.eth_src_table.match(
                    eth_type=self.ETH_TYPE,
                    eth_dst=valve_packet.IPV6_ALL_ROUTERS_MCAST,
                    vlan=vlan),
                priority=priority,
                inst=[valve_of.goto_table(self.vip_table)]))
            ofmsgs.append(self.vip_table.flowmod(
                self.vip_table.match(
                    eth_type=self.ETH_TYPE,
                    nw_proto=valve_of.inet.IPPROTO_ICMPV6,
                    icmpv6_type=icmpv6.ND_ROUTER_SOLICIT),
                priority=priority,
                inst=controller_and_flood))
        return ofmsgs

    def _add_faucet_fib_to_vip(self, vlan, priority, faucet_vip, faucet_vip_host):
        ofmsgs = super(ValveIPv6RouteManager, self)._add_faucet_fib_to_vip(
            vlan, priority, faucet_vip, faucet_vip_host)
        faucet_vip_broadcast = ipaddress.IPv6Interface(faucet_vip.network.broadcast_address)
        ofmsgs.append(self.fib_table.flowmod(
            self.fib_table.match(eth_type=self.ETH_TYPE, vlan=vlan, nw_dst=faucet_vip_broadcast),
            priority=priority,
            inst=[valve_of.goto_table(self.vip_table)]))
        return ofmsgs

    def _control_plane_icmpv6_handler(self, pkt_meta, ipv6_pkt):
        ofmsgs = []
        if not pkt_meta.packet_complete():
            return ofmsgs
        src_ip = ipaddress.IPv6Address(btos(ipv6_pkt.src))
        dst_ip = ipaddress.IPv6Address(btos(ipv6_pkt.dst))
        vlan = pkt_meta.vlan
        if vlan.ip_in_vip_subnet(src_ip):
            # Must be ICMPv6 and have no extended headers.
            if ipv6_pkt.nxt != valve_of.inet.IPPROTO_ICMPV6:
                return ofmsgs
            if ipv6_pkt.ext_hdrs:
                return ofmsgs
            # Explicitly ignore messages to all notes.
            if dst_ip == valve_packet.IPV6_ALL_NODES:
                return ofmsgs
            pkt_meta.reparse_ip(self.ETH_TYPE, payload=32)
            icmpv6_pkt = pkt_meta.pkt.get_protocol(icmpv6.icmpv6)
            if icmpv6_pkt is None:
                return ofmsgs
            icmpv6_type = icmpv6_pkt.type_
            if (ipv6_pkt.hop_limit != valve_packet.IPV6_MAX_HOP_LIM and
                    icmpv6_type != icmpv6.ICMPV6_ECHO_REQUEST):
                return ofmsgs
            port = pkt_meta.port
            vid = self._vlan_vid(vlan, port)
            eth_src = pkt_meta.eth_src
            if icmpv6_type == icmpv6.ND_NEIGHBOR_SOLICIT:
                solicited_ip = btos(icmpv6_pkt.data.dst)
                if vlan.is_faucet_vip(ipaddress.ip_address(solicited_ip)):
                    ofmsgs.extend(
                        self._add_host_fib_route(vlan, src_ip))
                    ofmsgs.extend(self._update_nexthop(
                        vlan, port, eth_src, src_ip))
                    nd_reply = valve_packet.nd_advert(
                        vid, vlan.faucet_mac, eth_src,
                        solicited_ip, src_ip)
                    ofmsgs.append(
                        valve_of.packetout(port.number, nd_reply.data))
                    self.logger.info(
                        'Responded to ND solicit for %s to %s (%s) on VLAN %u' % (
                            solicited_ip, src_ip, eth_src, vlan.vid))
            elif icmpv6_type == icmpv6.ND_NEIGHBOR_ADVERT:
                target_ip = btos(icmpv6_pkt.data.dst)
                if vlan.ip_in_vip_subnet(ipaddress.ip_address(target_ip)):
                    ofmsgs.extend(self._update_nexthop(
                        vlan, port, eth_src, target_ip))
                    self.logger.info(
                        'ND advert %s (%s) on VLAN %u' % (
                            target_ip, eth_src, vlan.vid))
            elif icmpv6_type == icmpv6.ND_ROUTER_SOLICIT:
                link_local_vips, other_vips = self._link_and_other_vips(vlan)
                for vip in link_local_vips:
                    if src_ip in vip.network:
                        ofmsgs.extend(
                            self._add_host_fib_route(vlan, src_ip))
                        ofmsgs.extend(self._update_nexthop(
                            vlan, port, eth_src, src_ip))
                        ra_advert = valve_packet.router_advert(
                            vlan, vid, vlan.faucet_mac, eth_src,
                            vip.ip, src_ip, other_vips)
                        ofmsgs.append(
                            valve_of.packetout(port.number, ra_advert.data))
                        self.logger.info(
                            'Responded to RS solicit from %s (%s) to VIP %s on VLAN %u' % (
                                src_ip, eth_src, vip, vlan.vid))
                        break
            elif icmpv6_type == icmpv6.ICMPV6_ECHO_REQUEST:
                if (vlan.from_connected_to_vip(src_ip, dst_ip) and
                        pkt_meta.eth_dst == vlan.faucet_mac):
                    icmpv6_echo_reply = valve_packet.icmpv6_echo_reply(
                        vid, vlan.faucet_mac, eth_src,
                        dst_ip, src_ip, ipv6_pkt.hop_limit,
                        icmpv6_pkt.data.id, icmpv6_pkt.data.seq,
                        icmpv6_pkt.data.data)
                    ofmsgs.append(
                        valve_of.packetout(port.number, icmpv6_echo_reply.data))
        return ofmsgs

    def control_plane_handler(self, pkt_meta):
        pkt = pkt_meta.pkt
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        if ipv6_pkt is not None:
            icmp_replies = self._control_plane_icmpv6_handler(
                pkt_meta, ipv6_pkt)
            if icmp_replies:
                return icmp_replies
            dst_ip = ipaddress.IPv6Address(btos(ipv6_pkt.dst))
            return self._proactive_resolve_neighbor(
                self._routed_vlans(pkt_meta.vlan), dst_ip)
        return []

    def _link_and_other_vips(self, vlan):
        link_local_vips = []
        other_vips = []
        for faucet_vip in vlan.faucet_vips_by_ipv(self.IPV):
            if faucet_vip.ip in valve_packet.IPV6_LINK_LOCAL:
                link_local_vips.append(faucet_vip)
            else:
                other_vips.append(faucet_vip)
        return link_local_vips, other_vips

    def advertise(self, vlan):
        ofmsgs = []
        link_local_vips, other_vips = self._link_and_other_vips(vlan)
        for link_local_vip in link_local_vips:
            # https://tools.ietf.org/html/rfc4861#section-6.1.2
            ofmsgs.extend(vlan.flood_pkt(
                valve_packet.router_advert, vlan.faucet_mac,
                valve_packet.IPV6_ALL_NODES_MCAST,
                link_local_vip.ip, valve_packet.IPV6_ALL_NODES,
                other_vips))
        return ofmsgs
