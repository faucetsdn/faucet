# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
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

import ipaddr

import valve_of
import valve_packet

from ryu.lib.packet import arp, icmp, icmpv6, ipv4, ipv6
from ryu.ofproto import ether
from ryu.ofproto import inet


class LinkNeighbor(object):

    def __init__(self, eth_src, now):
        self.eth_src = eth_src
        self.cache_time = now


class ValveRouteManager(object):

    def __init__(self, logger, faucet_mac, arp_neighbor_timeout,
                 fib_table, eth_src_table, eth_dst_table, route_priority,
                 valve_in_match, valve_flowdel, valve_flowmod,
                 valve_flowcontroller):
        self.logger = logger
        self.faucet_mac = faucet_mac
        self.arp_neighbor_timeout = arp_neighbor_timeout
        self.fib_table = fib_table
        self.eth_src_table = eth_src_table
        self.eth_dst_table = eth_dst_table
        self.route_priority = route_priority
        self.valve_in_match = valve_in_match
        self.valve_flowdel = valve_flowdel
        self.valve_flowmod = valve_flowmod
        self.valve_flowcontroller = valve_flowcontroller

    def vlan_vid(self, vlan, in_port):
        vid = None
        if vlan.port_is_tagged(in_port):
            vid = vlan.vid
        return vid

    def eth_type(self):
        pass

    def vlan_routes(self, vlan):
        pass

    def vlan_neighbor_cache(self, vlan):
        pass

    def neighbor_resolver_pkt(self, vid, controller_ip, ip_gw):
        pass

    def neighbor_resolver(self, ip_gw, controller_ip, vlan, ports):
        ofmsgs = []
        if ports:
            self.logger.info('Resolving %s', ip_gw)
            port_num = ports[0].number
            vid = self.vlan_vid(vlan, port_num)
            resolver_pkt = self.neighbor_resolver_pkt(
                vid, controller_ip, ip_gw)
            for port in ports:
                ofmsgs.append(valve_of.packetout(
                    port.number, resolver_pkt.data))
        return ofmsgs

    def resolve_gateways(self, vlan, now):
        ofmsgs = []
        untagged_ports = vlan.untagged_flood_ports(False)
        tagged_ports = vlan.tagged_flood_ports(False)
        routes = self.vlan_routes(vlan)
        neighbor_cache = self.vlan_neighbor_cache(vlan)
        for ip_gw in set(routes.values()):
            for controller_ip in vlan.controller_ips:
                if ip_gw in controller_ip:
                    cache_age = None
                    if ip_gw in neighbor_cache:
                        cache_time = neighbor_cache[ip_gw].cache_time
                        cache_age = now - cache_time
                    if (cache_age is None or
                            cache_age > self.arp_neighbor_timeout):
                        for ports in untagged_ports, tagged_ports:
                            ofmsgs.extend(self.neighbor_resolver(
                                ip_gw, controller_ip, vlan, ports))
        return ofmsgs

    def add_resolved_route(self, vlan, ip_gw, ip_dst, eth_dst, is_updated=None):
        ofmsgs = []
        if is_updated is not None:
            in_match = self.valve_in_match(
                self.fib_table, vlan=vlan,
                eth_type=self.eth_type(), nw_dst=ip_dst)
            prefixlen = ipaddr.IPNetwork(ip_dst).prefixlen
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

            ofmsgs.append(self.valve_flowmod(
                self.fib_table,
                in_match,
                priority=priority,
                inst=[valve_of.apply_actions(
                    [valve_of.set_eth_src(self.faucet_mac),
                     valve_of.set_eth_dst(eth_dst),
                     valve_of.dec_ip_ttl()])] +
                [valve_of.goto_table(self.eth_dst_table)]))
        now = time.time()
        link_neighbor = LinkNeighbor(eth_dst, now)
        neighbor_cache = self.vlan_neighbor_cache(vlan)
        neighbor_cache[ip_gw] = link_neighbor
        return ofmsgs

    def add_route(self, vlan, ip_gw, ip_dst):
        ofmsgs = []
        routes = self.vlan_routes(vlan)
        neighbor_cache = self.vlan_neighbor_cache(vlan)
        routes[ip_dst] = ip_gw
        if ip_gw in neighbor_cache:
            eth_dst = neighbor_cache[ip_gw].eth_src
            ofmsgs.extend(self.add_resolved_route(
                vlan=vlan,
                ip_gw=ip_gw,
                ip_dst=ip_dst,
                eth_dst=eth_dst,
                is_updated=False))
        return ofmsgs

    def del_route(self, vlan, ip_dst):
        ofmsgs = []
        routes = self.vlan_routes(vlan)
        if ip_dst in routes:
            del routes[ip_dst]
            route_match = self.valve_in_match(
                self.fib_table, vlan=vlan,
                eth_type=self.eth_type(), nw_dst=ip_dst)
            ofmsgs.extend(self.valve_flowdel(
                self.fib_table, route_match))
        return ofmsgs

    def update_nexthop(self, vlan, eth_src, resolved_ip_gw):
        ofmsgs = []
        is_updated = None
        routes = self.vlan_routes(vlan)
        neighbor_cache = self.vlan_neighbor_cache(vlan)
        if resolved_ip_gw in neighbor_cache:
            cached_eth_dst = neighbor_cache[resolved_ip_gw].eth_src
            if cached_eth_dst != eth_src:
                is_updated = True
        else:
            is_updated = False
        for ip_dst, ip_gw in routes.iteritems():
            if ip_gw == resolved_ip_gw:
                ofmsgs.extend(self.add_resolved_route(
                    vlan, ip_gw, ip_dst, eth_src, is_updated))
        return ofmsgs

    def control_plane_handler(self, in_port, vlan, eth_src, eth_dst, pkt):
        pass


class ValveIPv4RouteManager(ValveRouteManager):

    def eth_type(self):
        return ether.ETH_TYPE_IP

    def vlan_routes(self, vlan):
        return vlan.ipv4_routes

    def vlan_neighbor_cache(self, vlan):
        return vlan.arp_cache

    def neighbor_resolver_pkt(self, vid, controller_ip, ip_gw):
        return valve_packet.arp_request(
            self.faucet_mac, vid, controller_ip.ip, ip_gw)

    def add_controller_ip(self, vlan, controller_ip, controller_ip_host):
        ofmsgs = []
        max_prefixlen = controller_ip_host.prefixlen
        priority = self.route_priority + max_prefixlen
        ofmsgs.append(self.valve_flowcontroller(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=ether.ETH_TYPE_ARP,
                nw_dst=controller_ip_host,
                vlan=vlan),
            priority=priority))
        # Initialize IPv4 FIB
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self.eth_type(),
                eth_dst=self.faucet_mac,
                vlan=vlan),
            priority=self.route_priority,
            inst=[valve_of.goto_table(self.fib_table)]))
        ofmsgs.append(self.valve_flowcontroller(
            self.fib_table,
            self.valve_in_match(
                self.fib_table,
                vlan=vlan,
                eth_type=self.eth_type(),
                nw_proto=inet.IPPROTO_ICMP,
                nw_src=controller_ip,
                nw_dst=controller_ip_host),
            priority=priority))
        return ofmsgs

    def control_plane_arp_handler(self, in_port, vlan, eth_src, eth_dst, arp_pkt):
        ofmsgs = []
        opcode = arp_pkt.opcode
        src_ip = ipaddr.IPv4Address(arp_pkt.src_ip)
        dst_ip = ipaddr.IPv4Address(arp_pkt.dst_ip)

        if (opcode == arp.ARP_REQUEST and
                vlan.ip_in_controller_subnet(src_ip) and
                vlan.ip_in_controller_subnet(dst_ip)):
            vid = self.vlan_vid(vlan, in_port)
            arp_reply = valve_packet.arp_reply(
                self.faucet_mac, eth_src, vid, dst_ip, src_ip)
            ofmsgs.append(valve_of.packetout(in_port, arp_reply.data))
            self.logger.info(
                'Responded to ARP request for %s from %s', src_ip, dst_ip)
        elif (opcode == arp.ARP_REPLY and
              eth_dst == self.faucet_mac and
              vlan.ip_in_controller_subnet(src_ip) and
              vlan.ip_in_controller_subnet(dst_ip)):
            self.logger.info('ARP response %s for %s', eth_src, src_ip)
            ofmsgs.extend(self.update_nexthop(vlan, eth_src, src_ip))
        return ofmsgs

    def control_plane_icmp_handler(self, in_port, vlan, eth_src,
                                   ipv4_pkt, icmp_pkt):
        ofmsgs = []
        src_ip = ipaddr.IPv4Address(ipv4_pkt.src)
        dst_ip = ipaddr.IPv4Address(ipv4_pkt.dst)
        if (icmp_pkt is not None and
                vlan.ip_in_controller_subnet(src_ip) and
                vlan.ip_in_controller_subnet(dst_ip)):
            vid = self.vlan_vid(vlan, in_port)
            echo_reply = valve_packet.echo_reply(
                self.faucet_mac, eth_src, vid, dst_ip, src_ip, icmp_pkt.data)
            ofmsgs.append(valve_of.packetout(in_port, echo_reply.data))
        return ofmsgs

    def control_plane_handler(self, in_port, vlan, eth_src, eth_dst, pkt):
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is not None:
            return self.control_plane_arp_handler(
                in_port, vlan, eth_src, eth_dst, arp_pkt)

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt is not None:
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt is not None:
                return self.control_plane_icmp_handler(
                    in_port, vlan, eth_src, ipv4_pkt, icmp_pkt)

        return []


class ValveIPv6RouteManager(ValveRouteManager):

    def eth_type(self):
        return ether.ETH_TYPE_IPV6

    def vlan_routes(self, vlan):
        return vlan.ipv6_routes

    def vlan_neighbor_cache(self, vlan):
        return vlan.nd_cache

    def neighbor_resolver_pkt(self, vid, controller_ip, ip_gw):
        return valve_packet.nd_request(
            self.faucet_mac, vid, controller_ip.ip, ip_gw)

    def add_controller_ip(self, vlan, controller_ip, controller_ip_host):
        ofmsgs = []
        max_prefixlen = controller_ip_host.prefixlen
        priority = self.route_priority + max_prefixlen
        ofmsgs.append(self.valve_flowcontroller(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self.eth_type(),
                vlan=vlan,
                nw_proto=inet.IPPROTO_ICMPV6,
                ipv6_nd_target=controller_ip_host,
                icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT),
            priority=priority))
        ofmsgs.append(self.valve_flowcontroller(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self.eth_type(),
                eth_dst=self.faucet_mac,
                vlan=vlan,
                nw_proto=inet.IPPROTO_ICMPV6,
                icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT),
            priority=priority))
        # Initialize IPv6 FIB
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table,
                eth_type=self.eth_type(),
                eth_dst=self.faucet_mac,
                vlan=vlan),
            priority=self.route_priority,
            inst=[valve_of.goto_table(self.fib_table)]))
        ofmsgs.append(self.valve_flowcontroller(
            self.fib_table,
            self.valve_in_match(
                self.fib_table,
                eth_type=self.eth_type(),
                vlan=vlan,
                nw_proto=inet.IPPROTO_ICMPV6,
                nw_dst=controller_ip_host,
                icmpv6_type=icmpv6.ICMPV6_ECHO_REQUEST),
            priority=priority))
        return ofmsgs

    def control_plane_icmpv6_handler(self, in_port, vlan, eth_src,
                                     ipv6_pkt, icmpv6_pkt):
        vid = self.vlan_vid(vlan, in_port)
        src_ip = ipaddr.IPv6Address(ipv6_pkt.src)
        dst_ip = ipaddr.IPv6Address(ipv6_pkt.dst)
        icmpv6_type = icmpv6_pkt.type_
        ofmsgs = []
        if (icmpv6_type == icmpv6.ND_NEIGHBOR_SOLICIT and
                vlan.ip_in_controller_subnet(src_ip)):
            nd_reply = valve_packet.nd_reply(
                self.faucet_mac, eth_src, vid,
                icmpv6_pkt.data.dst, src_ip, ipv6_pkt.hop_limit)
            ofmsgs.extend([valve_of.packetout(in_port, nd_reply.data)])
        elif (icmpv6_type == icmpv6.ND_NEIGHBOR_ADVERT and
              vlan.ip_in_controller_subnet(src_ip)):
            resolved_ip_gw = ipaddr.IPv6Address(icmpv6_pkt.data.dst)
            self.logger.info('ND response %s for %s', eth_src, resolved_ip_gw)
            ofmsgs.extend(self.update_nexthop(vlan, eth_src, resolved_ip_gw))
        elif icmpv6_type == icmpv6.ICMPV6_ECHO_REQUEST:
            icmpv6_echo_reply = valve_packet.icmpv6_echo_reply(
                self.faucet_mac, eth_src, vid,
                dst_ip, src_ip, ipv6_pkt.hop_limit,
                icmpv6_pkt.data.id, icmpv6_pkt.data.seq, icmpv6_pkt.data.data)
            ofmsgs.extend([valve_of.packetout(in_port, icmpv6_echo_reply.data)])
        return ofmsgs

    def control_plane_handler(self, in_port, vlan, eth_src, eth_dst, pkt):
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        if ipv6_pkt is not None:
            icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
            if icmpv6_pkt is not None:
                return self.control_plane_icmpv6_handler(
                    in_port, vlan, eth_src, ipv6_pkt, icmpv6_pkt)
        return []
