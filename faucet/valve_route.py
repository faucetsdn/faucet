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
# distributed under the License is distributed on an "AS IS" BASISo
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time

import ipaddress

from ryu.lib.packet import arp, icmp, icmpv6, ipv4, ipv6
from ryu.ofproto import ether
from ryu.ofproto import inet

import valve_of
import valve_packet
from valve_util import btos


class AnyVlan(object):
    """Wildcard VLAN."""

    vid = valve_of.vid_present(0)


class NextHop(object):
    """Describes a directly connected (at layer 2) nexthop."""

    def __init__(self, eth_src, now):
        self.eth_src = eth_src
        self.cache_time = now
        self.last_retry_time = None
        self.resolve_retries = 0


class ValveRouteManager(object):
    """Base class to implement RIB/FIB."""

    def __init__(self, logger, faucet_mac, arp_neighbor_timeout,
                 max_hosts_per_resolve_cycle, max_host_fib_retry_count,
                 max_resolve_backoff_time,
                 fib_table, eth_src_table, eth_dst_table, flood_table,
                 route_priority,
                 valve_in_match, valve_flowdel, valve_flowmod,
                 valve_flowcontroller, use_group_table, routers):
        self.logger = logger
        self.faucet_mac = faucet_mac
        self.arp_neighbor_timeout = arp_neighbor_timeout
        self.max_hosts_per_resolve_cycle = max_hosts_per_resolve_cycle
        self.max_host_fib_retry_count = max_host_fib_retry_count
        self.max_resolve_backoff_time = max_resolve_backoff_time
        self.fib_table = fib_table
        self.eth_src_table = eth_src_table
        self.eth_dst_table = eth_dst_table
        self.flood_table = flood_table
        self.route_priority = route_priority
        self.valve_in_match = valve_in_match
        self.valve_flowdel = valve_flowdel
        self.valve_flowmod = valve_flowmod
        self.valve_flowcontroller = valve_flowcontroller
        self.use_group_table = use_group_table
        # TODO: if any router config present, we globally route between
        # all VLANs - we want however to be able to restrict routing
        # as required.
        self.routers = routers
        self.ip_gw_to_group_id = {}

    def _vlan_vid(self, vlan, in_port):
        vid = None
        if vlan.port_is_tagged(in_port):
            vid = vlan.vid
        return vid

    def _eth_type(self):
        """Return EtherType for FIB entries."""
        pass

    def _vlan_routes(self, vlan):
        pass

    def _vlan_nexthop_cache(self, vlan):
        pass

    def _vlan_nexthop_cache_entry(self, vlan, ip_gw):
        nexthop_cache = self._vlan_nexthop_cache(vlan)
        if ip_gw in nexthop_cache:
            return nexthop_cache[ip_gw]
        return None

    def _neighbor_resolver_pkt(self, vid, faucet_vip, ip_gw):
        pass

    def _neighbor_resolver(self, ip_gw, faucet_vip, vlan, ports):
        ofmsgs = []
        if ports:
            port_num = ports[0].number
            vid = self._vlan_vid(vlan, port_num)
            resolver_pkt = self._neighbor_resolver_pkt(
                vid, faucet_vip, ip_gw)
            for port in ports:
                ofmsgs.append(valve_of.packetout(
                    port.number, resolver_pkt.data))
        return ofmsgs

    def _nexthop_actions(self, eth_dst, vlan):
        ofmsgs = []
        if self.routers:
            ofmsgs.append(valve_of.set_vlan_vid(vlan.vid))
        ofmsgs.extend([
            valve_of.set_eth_src(self.faucet_mac),
            valve_of.set_eth_dst(eth_dst),
            valve_of.dec_ip_ttl()])
        return ofmsgs

    def _add_resolved_route(self, vlan, ip_gw, ip_dst, eth_dst, is_updated):
        ofmsgs = []
        if self.routers:
            in_match = self.valve_in_match(
                self.fib_table, vlan=AnyVlan(),
                eth_type=self._eth_type(), nw_dst=ip_dst)
        else:
            in_match = self.valve_in_match(
                self.fib_table, vlan=vlan,
                eth_type=self._eth_type(), nw_dst=ip_dst)
        prefixlen = ipaddress.ip_network(ip_dst).prefixlen
        priority = self.route_priority + prefixlen
        if is_updated:
            self.logger.info(
                'Updating next hop for route %s via %s (%s)',
                ip_dst, ip_gw, eth_dst)
            ofmsgs.extend(self.valve_flowdel(
                self.fib_table,
                in_match,
                priority=priority))
        else:
            self.logger.info(
                'Adding new route %s via %s (%s)',
                ip_dst, ip_gw, eth_dst)
        if self.use_group_table:
            inst = [valve_of.apply_actions([valve_of.group_act(
                group_id=self.ip_gw_to_group_id[ip_gw])])]
        else:
            inst = [valve_of.apply_actions(self._nexthop_actions(eth_dst, vlan)),
                    valve_of.goto_table(self.eth_dst_table)]
        ofmsgs.append(self.valve_flowmod(
            self.fib_table,
            in_match,
            priority=priority,
            inst=inst))
        return ofmsgs

    def _group_id_from_ip_gw(self, resolved_ip_gw):
        return (hash(str(resolved_ip_gw)) + valve_of.ROUTE_GROUP_OFFSET) & ((1<<32) -1)

    def _update_nexthop_cache(self, vlan, eth_src, ip_gw):
        now = time.time()
        nexthop = NextHop(eth_src, now)
        nexthop_cache = self._vlan_nexthop_cache(vlan)
        nexthop_cache[ip_gw] = nexthop

    def _nexthop_group_buckets(self, vlan, in_port, eth_src):
        actions = self._nexthop_actions(eth_src, vlan)
        if not vlan.port_is_tagged(in_port):
            actions.append(valve_of.pop_vlan())
        actions.append(valve_of.output_port(in_port))
        buckets = [valve_of.bucket(actions=actions)]
        return buckets

    def _update_nexthop_group(self, is_updated, resolved_ip_gw,
                              vlan, in_port, eth_src):
        group_mod_method = None
        group_id = None
        buckets = self._nexthop_group_buckets(vlan, in_port, eth_src)
        ofmsgs = []
        if is_updated:
            group_mod_method = valve_of.groupmod
            group_id = self.ip_gw_to_group_id[resolved_ip_gw]
        else:
            group_mod_method = valve_of.groupadd
            group_id = self._group_id_from_ip_gw(resolved_ip_gw)
            self.ip_gw_to_group_id[resolved_ip_gw] = group_id
            ofmsgs.append(valve_of.groupdel(group_id=group_id))
        ofmsgs.append(
            group_mod_method(group_id=group_id, buckets=buckets))
        return ofmsgs

    def _update_nexthop(self, vlan, in_port, eth_src, resolved_ip_gw):
        is_updated = False
        routes = self._vlan_routes(vlan)
        cached_eth_dst = self._cached_nexthop_eth_dst(vlan, resolved_ip_gw)
        ofmsgs = []

        if cached_eth_dst is not None and cached_eth_dst != eth_src:
            is_updated = True

        if self.use_group_table:
            ofmsgs.extend(
                self._update_nexthop_group(
                    is_updated, resolved_ip_gw,
                    vlan, in_port, eth_src))
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
            for faucet_vip in vlan.faucet_vips:
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
        for ip_dst, ip_gw in list(routes.items()):
            if ip_gw == host_ip:
                if ip_dst.prefixlen < ip_dst.max_prefixlen:
                    return False
        return True

    def resolve_gateways(self, vlan, now):
        """Re/resolve all gateways.

        Args:
            vlan (vlan): VLAN containing this RIB/FIB.
            now (float): seconds since epoch.
        Returns:
            list: OpenFlow messages.
        """
        untagged_ports = vlan.untagged_flood_ports(False)
        tagged_ports = vlan.tagged_flood_ports(False)
        ip_gws = self._vlan_ip_gws(vlan)
        self._add_unresolved_nexthops(vlan, ip_gws)
        all_unresolved_nexthops = self._vlan_unresolved_nexthops(
            vlan, ip_gws, now)
        cycle_unresolved_nexthops = all_unresolved_nexthops[
            :self.max_hosts_per_resolve_cycle]
        deferred_unresolved_nexthops = (len(all_unresolved_nexthops) -
                                        len(cycle_unresolved_nexthops))
        if deferred_unresolved_nexthops:
            self.logger.info('deferring resolution of %u nexthops',
                             deferred_unresolved_nexthops)
        ofmsgs = []
        for ip_gw, faucet_vip, last_retry_time in cycle_unresolved_nexthops:
            nexthop_cache_entry = self._vlan_nexthop_cache_entry(vlan, ip_gw)
            if (self._is_host_fib_route(vlan, ip_gw) and
                    nexthop_cache_entry.resolve_retries >= self.max_host_fib_retry_count):
                self.logger.info(
                    'expiring dead host FIB route %s (age %us)',
                    ip_gw,
                    now - nexthop_cache_entry.cache_time)
                ofmsgs.extend(self._del_host_fib_route(vlan, ip_gw))
            else:
                nexthop_cache_entry.last_retry_time = now
                nexthop_cache_entry.resolve_retries += 1
                if last_retry_time is None:
                    self.logger.info('resolving %s', ip_gw)
                else:
                    self.logger.info(
                        'resolving %s retry %u (last attempt was %us ago)',
                        ip_gw,
                        nexthop_cache_entry.resolve_retries,
                        now - last_retry_time)
                for ports in untagged_ports, tagged_ports:
                    ofmsgs.extend(self._neighbor_resolver(
                        ip_gw, faucet_vip, vlan, ports))
        return ofmsgs

    def _cached_nexthop_eth_dst(self, vlan, ip_gw):
        nexthop_cache_entry = self._vlan_nexthop_cache_entry(vlan, ip_gw)
        if (nexthop_cache_entry is not None and
                nexthop_cache_entry.eth_src is not None):
            return nexthop_cache_entry.eth_src
        return None

    def _host_from_faucet_vip(self, faucet_vip):
        max_prefixlen = faucet_vip.ip.max_prefixlen
        return ipaddress.ip_interface(
            btos('/'.join((faucet_vip.ip.exploded, str(max_prefixlen)))))

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
        routes = self._vlan_routes(vlan)
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
                now = time.time()
                nexthop_fresh = self._nexthop_fresh(pkt_meta.vlan, src_ip, now)
                self._update_nexthop_cache(
                    pkt_meta.vlan, pkt_meta.eth_src, src_ip)
                if not nexthop_fresh:
                    if self.use_group_table:
                        ofmsgs.extend(
                            self._update_nexthop_group(
                                False,
                                src_ip,
                                pkt_meta.vlan,
                                pkt_meta.port.number,
                                pkt_meta.eth_src))
                    ofmsgs.extend(
                        self._add_host_fib_route(pkt_meta.vlan, src_ip))
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
        routes = self._vlan_routes(vlan)
        if ip_dst in routes:
            del routes[ip_dst]
            route_match = self.valve_in_match(
                self.fib_table, vlan=vlan,
                eth_type=self._eth_type(), nw_dst=ip_dst)
            ofmsgs.extend(self.valve_flowdel(
                self.fib_table, route_match))
            # TODO: need to delete nexthop group if groups are in use.
        return ofmsgs

    def control_plane_handler(self, pkt_meta):
        pass


class ValveIPv4RouteManager(ValveRouteManager):
    """Implement IPv4 RIB/FIB."""

    def _eth_type(self):
        return ether.ETH_TYPE_IP

    def _vlan_routes(self, vlan):
        return vlan.ipv4_routes

    def _vlan_nexthop_cache(self, vlan):
        return vlan.arp_cache

    def _neighbor_resolver_pkt(self, vid, faucet_vip, ip_gw):
        return valve_packet.arp_request(
            self.faucet_mac, vid, faucet_vip.ip, ip_gw)

    def _ip_pkt(self, pkt):
        return pkt.get_protocol(ipv4.ipv4)

    def add_faucet_vip(self, vlan, faucet_vip):
        ofmsgs = []
        max_prefixlen = faucet_vip.ip.max_prefixlen
        faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
        priority = self.route_priority + max_prefixlen
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=ether.ETH_TYPE_ARP,
                nw_dst=faucet_vip_host,
                vlan=vlan),
            priority=priority,
            inst=[valve_of.apply_actions([valve_of.output_controller()])]))
        # Initialize IPv4 FIB
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self._eth_type(),
                eth_dst=self.faucet_mac,
                vlan=vlan),
            priority=self.route_priority,
            inst=[valve_of.goto_table(self.fib_table)]))
        ofmsgs.append(self.valve_flowcontroller(
            self.fib_table,
            self.valve_in_match(
                self.fib_table,
                vlan=vlan,
                eth_type=self._eth_type(),
                nw_proto=inet.IPPROTO_ICMP,
                nw_src=faucet_vip,
                nw_dst=faucet_vip_host),
            priority=priority))
        return ofmsgs

    def _control_plane_arp_handler(self, pkt_meta, arp_pkt):
        src_ip = ipaddress.IPv4Address(btos(arp_pkt.src_ip))
        dst_ip = ipaddress.IPv4Address(btos(arp_pkt.dst_ip))
        vlan = pkt_meta.vlan
        opcode = arp_pkt.opcode
        ofmsgs = []
        if vlan.from_connected_to_vip(src_ip, dst_ip):
            in_port = pkt_meta.port.number
            eth_src = pkt_meta.eth_src
            if opcode == arp.ARP_REQUEST:
                ofmsgs.extend(
                    self._add_host_fib_route(vlan, src_ip))
                vid = self._vlan_vid(vlan, in_port)
                arp_reply = valve_packet.arp_reply(
                    self.faucet_mac, eth_src, vid, dst_ip, src_ip)
                ofmsgs.append(
                    valve_of.packetout(in_port, arp_reply.data))
                self.logger.info(
                    'Responded to ARP request for %s from %s (%s)',
                    dst_ip, src_ip, eth_src)
            elif (opcode == arp.ARP_REPLY and
                  pkt_meta.eth_dst == self.faucet_mac):
                ofmsgs.extend(
                    self._update_nexthop(vlan, in_port, eth_src, src_ip))
                self.logger.info(
                    'ARP response %s (%s)', src_ip, eth_src)
        return ofmsgs

    def _control_plane_icmp_handler(self, pkt_meta, ipv4_pkt, icmp_pkt):
        src_ip = ipaddress.IPv4Address(btos(ipv4_pkt.src))
        dst_ip = ipaddress.IPv4Address(btos(ipv4_pkt.dst))
        vlan = pkt_meta.vlan
        icmpv4_type = icmp_pkt.type
        ofmsgs = []
        if vlan.from_connected_to_vip(src_ip, dst_ip):
            if (icmpv4_type == icmp.ICMP_ECHO_REQUEST and
                    pkt_meta.eth_dst == self.faucet_mac):
                in_port = pkt_meta.port.number
                vid = self._vlan_vid(vlan, in_port)
                echo_reply = valve_packet.echo_reply(
                    self.faucet_mac, pkt_meta.eth_src,
                    vid, dst_ip, src_ip, icmp_pkt.data)
                ofmsgs.append(
                    valve_of.packetout(in_port, echo_reply.data))
        return ofmsgs

    def control_plane_handler(self, pkt_meta):
        arp_pkt = pkt_meta.pkt.get_protocol(arp.arp)
        if arp_pkt is not None:
            return self._control_plane_arp_handler(pkt_meta, arp_pkt)
        ipv4_pkt = pkt_meta.pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt is not None:
            icmp_pkt = pkt_meta.pkt.get_protocol(icmp.icmp)
            if icmp_pkt is not None:
                return self._control_plane_icmp_handler(
                    pkt_meta, ipv4_pkt, icmp_pkt)
        return []


class ValveIPv6RouteManager(ValveRouteManager):
    """Implement IPv6 FIB."""

    def _eth_type(self):
        return ether.ETH_TYPE_IPV6

    def _vlan_routes(self, vlan):
        return vlan.ipv6_routes

    def _vlan_nexthop_cache(self, vlan):
        return vlan.nd_cache

    def _neighbor_resolver_pkt(self, vid, faucet_vip, ip_gw):
        return valve_packet.nd_request(
            self.faucet_mac, vid, faucet_vip.ip, ip_gw)

    def _ip_pkt(self, pkt):
        return pkt.get_protocol(ipv6.ipv6)

    def add_faucet_vip(self, vlan, faucet_vip):
        ofmsgs = []
        max_prefixlen = faucet_vip.ip.max_prefixlen
        faucet_vip_host = self._host_from_faucet_vip(faucet_vip)
        priority = self.route_priority + max_prefixlen
        faucet_vip_host_nd_mcast = valve_packet.ipv6_link_eth_mcast(
            valve_packet.ipv6_solicited_node_from_ucast(faucet_vip.ip))
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self._eth_type(),
                vlan=vlan,
                nw_proto=inet.IPPROTO_ICMPV6,
                eth_dst=faucet_vip_host_nd_mcast,
                icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT),
            priority=priority,
            inst=[
                valve_of.apply_actions([valve_of.output_controller()]),
                valve_of.goto_table(self.flood_table)]))
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self._eth_type(),
                eth_dst=self.faucet_mac,
                vlan=vlan,
                nw_proto=inet.IPPROTO_ICMPV6,
                icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT),
            priority=priority,
            inst=[valve_of.apply_actions([valve_of.output_controller()])]))
        # Initialize IPv6 FIB
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self._eth_type(),
                eth_dst=self.faucet_mac,
                vlan=vlan),
            priority=self.route_priority,
            inst=[valve_of.goto_table(self.fib_table)]))
        ofmsgs.append(self.valve_flowcontroller(
            self.fib_table,
            self.valve_in_match(
                self.fib_table,
                eth_type=self._eth_type(),
                vlan=vlan,
                nw_proto=inet.IPPROTO_ICMPV6,
                nw_dst=faucet_vip_host,
                icmpv6_type=icmpv6.ICMPV6_ECHO_REQUEST),
            priority=priority))
        return ofmsgs

    def _control_plane_icmpv6_handler(self, pkt_meta, ipv6_pkt, icmpv6_pkt):
        vlan = pkt_meta.vlan
        src_ip = ipaddress.IPv6Address(btos(ipv6_pkt.src))
        dst_ip = ipaddress.IPv6Address(btos(ipv6_pkt.dst))
        icmpv6_type = icmpv6_pkt.type_
        ofmsgs = []
        if vlan.ip_in_vip_subnet(src_ip):
            in_port = pkt_meta.port.number
            vid = self._vlan_vid(vlan, in_port)
            eth_src = pkt_meta.eth_src
            if icmpv6_type == icmpv6.ND_NEIGHBOR_SOLICIT:
                solicited_ip = btos(icmpv6_pkt.data.dst)
                if vlan.is_faucet_vip(ipaddress.ip_address(solicited_ip)):
                    ofmsgs.extend(
                        self._add_host_fib_route(vlan, src_ip))
                    nd_reply = valve_packet.nd_reply(
                        self.faucet_mac, eth_src, vid,
                        solicited_ip, src_ip, ipv6_pkt.hop_limit)
                    ofmsgs.append(
                        valve_of.packetout(in_port, nd_reply.data))
                    self.logger.info(
                        'Responded to ND solicit for %s to %s (%s)',
                        solicited_ip, src_ip, eth_src)
            elif icmpv6_type == icmpv6.ND_NEIGHBOR_ADVERT:
                ofmsgs.extend(self._update_nexthop(
                    vlan, in_port, eth_src, src_ip))
                self.logger.info(
                    'ND advert %s (%s)', src_ip, eth_src)
            elif vlan.from_connected_to_vip(src_ip, dst_ip):
                if (icmpv6_type == icmpv6.ICMPV6_ECHO_REQUEST and
                        pkt_meta.eth_dst == self.faucet_mac):
                    icmpv6_echo_reply = valve_packet.icmpv6_echo_reply(
                        self.faucet_mac, eth_src, vid,
                        dst_ip, src_ip, ipv6_pkt.hop_limit,
                        icmpv6_pkt.data.id, icmpv6_pkt.data.seq,
                        icmpv6_pkt.data.data)
                    ofmsgs.append(
                        valve_of.packetout(in_port, icmpv6_echo_reply.data))
        return ofmsgs

    def control_plane_handler(self, pkt_meta):
        pkt = pkt_meta.pkt
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        if ipv6_pkt is not None:
            icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
            if icmpv6_pkt is not None:
                return self._control_plane_icmpv6_handler(
                    pkt_meta, ipv6_pkt, icmpv6_pkt)
        return []
