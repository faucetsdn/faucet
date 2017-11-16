"""Utility functions for parsing and building Ethernet packet/contents."""

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

import ipaddress

import dpkt
from ryu.lib.packet import arp, bpdu, ethernet, icmp, icmpv6, ipv4, ipv6, slow, stream_parser, packet, vlan

from faucet.valve_util import btos
from faucet import valve_of


SLOW_PROTOCOL_MULTICAST = slow.SLOW_PROTOCOL_MULTICAST
ETH_VLAN_HEADER_SIZE = 14 + 4
BRIDGE_GROUP_ADDRESS = bpdu.BRIDGE_GROUP_ADDRESS
CISCO_SPANNING_GROUP_ADDRESS = '01:00:0c:cc:cc:cd'
IPV6_ALL_NODES_MCAST = '33:33:00:00:00:01'
IPV6_ALL_ROUTERS_MCAST = '33:33:00:00:00:02'
IPV6_LINK_LOCAL = ipaddress.IPv6Network(btos('fe80::/10'))
IPV6_ALL_NODES = ipaddress.IPv6Address(btos('ff02::1'))
IPV6_MAX_HOP_LIM = 255



def mac_byte_mask(mask_bytes=0):
    """Return a MAC address mask with n bytes masked out."""
    assert mask_bytes <= 6
    return ':'.join(['ff'] * mask_bytes + (['00'] * (6 - mask_bytes)))


def parse_eth_pkt(pkt):
    """Return parsed Ethernet packet.

    Args:
        pkt (ryu.lib.packet.packet): packet received from dataplane.
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet.
    """
    return pkt.get_protocol(ethernet.ethernet)


def parse_vlan_pkt(pkt):
    """Return parsed VLAN header.

    Args:
        pkt (ryu.lib.packet.packet): packet received from dataplane.
    Returns:
        ryu.lib.packet.vlan: VLAN header.
    """
    return pkt.get_protocol(vlan.vlan)


def parse_lacp_pkt(pkt):
    """Return parsed LACP packet.

    Args:
        pkt (ryu.lib.packet.packet): packet received from dataplane.
    Returns:
        ryu.lib.packet.lacp: LACP packet.
    """
    return pkt.get_protocol(slow.lacp)


def parse_packet_in_pkt(data, max_len):
    """Parse a packet received via packet in from the dataplane.

    Args:
        data (bytearray): packet data from dataplane.
        max_len (int): max number of packet data bytes to parse.
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet.
        int: VLAN VID.
        int: Ethernet type of packet (inside VLAN)
    """
    pkt = None
    eth_pkt = None
    vlan_vid = None
    eth_type = None

    if max_len:
        data = data[:max_len]

    try:
        pkt = packet.Packet(data)
        eth_pkt = parse_eth_pkt(pkt)
        eth_type = eth_pkt.ethertype
        # Packet ins, can only come when a VLAN header has already been pushed
        # (ie. when we have progressed past the VLAN table). This gaurantees
        # a VLAN header will always be present, so we know which VLAN the packet
        # belongs to.
        if eth_type == valve_of.ether.ETH_TYPE_8021Q:
            vlan_pkt = parse_vlan_pkt(pkt)
            if vlan_pkt:
                vlan_vid = vlan_pkt.vid
                eth_type = vlan_pkt.ethertype
    except (AssertionError, stream_parser.StreamParser.TooSmallException):
        pass

    return (pkt, eth_pkt, vlan_vid, eth_type)


def mac_addr_is_unicast(mac_addr):
    """Returns True if mac_addr is a unicast Ethernet address.

    Args:
        mac_addr (str): MAC address.
    Returns:
        bool: True if a unicast Ethernet address.
    """
    msb = mac_addr.split(':')[0]
    return msb[-1] in '02468aAcCeE'


def build_pkt_header(vid, eth_src, eth_dst, dl_type):
    """Return an Ethernet packet header.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): destination Ethernet MAC address.
        dl_type (int): EtherType.
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet with header.
    """
    pkt_header = packet.Packet()
    if vid is None:
        eth_header = ethernet.ethernet(
            eth_dst, eth_src, dl_type)
        pkt_header.add_protocol(eth_header)
    else:
        eth_header = ethernet.ethernet(
            eth_dst, eth_src, valve_of.ether.ETH_TYPE_8021Q)
        pkt_header.add_protocol(eth_header)
        vlan_header = vlan.vlan(vid=vid, ethertype=dl_type)
        pkt_header.add_protocol(vlan_header)
    return pkt_header


def lacp_reqreply(eth_src,
                  actor_system, actor_key, actor_port,
                  partner_system, partner_key, partner_port,
                  partner_system_priority, partner_port_priority,
                  partner_state_defaulted,
                  partner_state_expired,
                  partner_state_timeout,
                  partner_state_collecting,
                  partner_state_distributing,
                  partner_state_aggregation,
                  partner_state_synchronization,
                  partner_state_activity):
    """Return a LACP frame.

    Args:
        eth_src (str): source Ethernet MAC address.
        actor_system (str): actor system ID (MAC address)
        actor_key (int): actor's LACP key assigned to this port.
        actor_port (int): actor port number.
        partner_system (str): partner system ID (MAC address)
        partner_key (int): partner's LACP key assigned to this port.
        partner_port (int): partner port number.
        partner_system_priority (int): partner's system priority.
        partner_port_priority (int): partner's port priority.
        partner_state_defaulted (int): 1 if partner reverted to defaults.
        partner_state_expired (int): 1 if partner thinks LACP expired.
        partner_state_timeout (int): 1 if partner has short timeout.
        partner_state_collecting (int): 1 if partner receiving on this link.
        partner_state_distributing (int): 1 if partner transmitting on this link.
        partner_state_aggregation (int): 1 if partner can aggregate this link.
        partner_state_synchronization (int): 1 if partner will use this link.
        partner_state_activity (int): 1 if partner actively sends LACP.
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet with header.
    """
    pkt = build_pkt_header(
        None, eth_src, slow.SLOW_PROTOCOL_MULTICAST, valve_of.ether.ETH_TYPE_SLOW)
    lacp_pkt = slow.lacp(
        version=1,
        actor_system=actor_system,
        actor_port=actor_port,
        partner_system=partner_system,
        partner_port=partner_port,
        actor_key=actor_key,
        partner_key=partner_key,
        actor_system_priority=65535,
        partner_system_priority=partner_system_priority,
        actor_port_priority=255,
        partner_port_priority=partner_port_priority,
        actor_state_defaulted=0,
        partner_state_defaulted=partner_state_defaulted,
        actor_state_expired=0,
        partner_state_expired=partner_state_expired,
        actor_state_timeout=1,
        partner_state_timeout=partner_state_timeout,
        actor_state_collecting=1,
        partner_state_collecting=partner_state_collecting,
        actor_state_distributing=1,
        partner_state_distributing=partner_state_distributing,
        actor_state_aggregation=1,
        partner_state_aggregation=partner_state_aggregation,
        actor_state_synchronization=1,
        partner_state_synchronization=partner_state_synchronization,
        actor_state_activity=0,
        partner_state_activity=partner_state_activity)
    pkt.add_protocol(lacp_pkt)
    pkt.serialize()
    return pkt


def arp_request(vid, eth_src, src_ip, dst_ip):
    """Return an ARP request packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): Ethernet source address.
        src_ip (ipaddress.IPv4Address): source IPv4 address.
        dst_ip (ipaddress.IPv4Address): requested IPv4 address.
    Returns:
        ryu.lib.packet.arp: serialized ARP request packet.
    """
    pkt = build_pkt_header(
        vid, eth_src, valve_of.mac.BROADCAST_STR, valve_of.ether.ETH_TYPE_ARP)
    arp_pkt = arp.arp(
        opcode=arp.ARP_REQUEST, src_mac=eth_src,
        src_ip=str(src_ip), dst_mac=valve_of.mac.DONTCARE_STR, dst_ip=str(dst_ip))
    pkt.add_protocol(arp_pkt)
    pkt.serialize()
    return pkt


def arp_reply(vid, eth_src, eth_dst, src_ip, dst_ip):
    """Return an ARP reply packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): Ethernet source address.
        eth_dst (str): destination Ethernet MAC address.
        src_ip (ipaddress.IPv4Address): source IPv4 address.
        dst_ip (ipaddress.IPv4Address): destination IPv4 address.
    Returns:
        ryu.lib.packet.arp: serialized ARP reply packet.
    """
    pkt = build_pkt_header(vid, eth_src, eth_dst, valve_of.ether.ETH_TYPE_ARP)
    arp_pkt = arp.arp(
        opcode=arp.ARP_REPLY, src_mac=eth_src,
        src_ip=src_ip, dst_mac=eth_dst, dst_ip=dst_ip)
    pkt.add_protocol(arp_pkt)
    pkt.serialize()
    return pkt


def echo_reply(vid, eth_src, eth_dst, src_ip, dst_ip, data):
    """Return an ICMP echo reply packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): Ethernet source address.
        eth_dst (str): destination Ethernet MAC address.
        src_ip (ipaddress.IPv4Address): source IPv4 address.
        dst_ip (ipaddress.IPv4Address): destination IPv4 address.
    Returns:
        ryu.lib.packet.icmp: serialized ICMP echo reply packet.
    """
    pkt = build_pkt_header(vid, eth_src, eth_dst, valve_of.ether.ETH_TYPE_IP)
    ipv4_pkt = ipv4.ipv4(
        dst=dst_ip, src=src_ip, proto=valve_of.inet.IPPROTO_ICMP)
    pkt.add_protocol(ipv4_pkt)
    icmp_pkt = icmp.icmp(
        type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE,
        data=data)
    pkt.add_protocol(icmp_pkt)
    pkt.serialize()
    return pkt


def ipv6_link_eth_mcast(dst_ip):
    """Return an Ethernet multicast address from an IPv6 address.

    See RFC 2464 section 7.

    Args:
        dst_ip (ipaddress.IPv6Address): IPv6 address.
    Returns:
        str: Ethernet multicast address.
    """
    mcast_mac_bytes = b'\x33\x33\xff' + dst_ip.packed[-3:]
    mcast_mac_octets = []
    for i in mcast_mac_bytes:
        if isinstance(i, int):
            mcast_mac_octets.append(i)
        else:
            mcast_mac_octets.append(ord(i))
    mcast_mac = ':'.join(['%02X' % x for x in mcast_mac_octets])
    return mcast_mac


def ipv6_solicited_node_from_ucast(ucast):
    """Return IPv6 solicited node multicast address from IPv6 unicast address.

    See RFC 3513 section 2.7.1.

    Args:
       ucast (ipaddress.IPv6Address): IPv6 unicast address.
    Returns:
       ipaddress.IPv6Address: IPv6 solicited node multicast address.
    """
    link_mcast_prefix = ipaddress.ip_interface(btos('ff02::1:ff00:0/104'))
    mcast_bytes = link_mcast_prefix.packed[:13] + ucast.packed[-3:]
    link_mcast = ipaddress.IPv6Address(mcast_bytes)
    return link_mcast


def nd_request(vid, eth_src, src_ip, dst_ip):
    """Return IPv6 neighbor discovery request packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        dst_ip (ipaddress.IPv6Address): requested IPv6 address.
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 neighbor discovery packet.
    """
    nd_mac = ipv6_link_eth_mcast(dst_ip)
    ip_gw_mcast = ipv6_solicited_node_from_ucast(dst_ip)
    pkt = build_pkt_header(vid, eth_src, nd_mac, valve_of.ether.ETH_TYPE_IPV6)
    ipv6_pkt = ipv6.ipv6(
        src=str(src_ip), dst=ip_gw_mcast, nxt=valve_of.inet.IPPROTO_ICMPV6)
    pkt.add_protocol(ipv6_pkt)
    icmpv6_pkt = icmpv6.icmpv6(
        type_=icmpv6.ND_NEIGHBOR_SOLICIT,
        data=icmpv6.nd_neighbor(
            dst=dst_ip,
            option=icmpv6.nd_option_sla(hw_src=eth_src)))
    pkt.add_protocol(icmpv6_pkt)
    pkt.serialize()
    return pkt


def nd_advert(vid, eth_src, eth_dst, src_ip, dst_ip):
    """Return IPv6 neighbor avertisement packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): destination Ethernet MAC address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        dst_ip (ipaddress.IPv6Address): destination IPv6 address.
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 neighbor discovery packet.
    """
    pkt = build_pkt_header(
        vid, eth_src, eth_dst, valve_of.ether.ETH_TYPE_IPV6)
    ipv6_icmp6 = ipv6.ipv6(
        src=src_ip,
        dst=dst_ip,
        nxt=valve_of.inet.IPPROTO_ICMPV6,
        hop_limit=IPV6_MAX_HOP_LIM)
    pkt.add_protocol(ipv6_icmp6)
    icmpv6_nd_advert = icmpv6.icmpv6(
        type_=icmpv6.ND_NEIGHBOR_ADVERT,
        data=icmpv6.nd_neighbor(
            dst=src_ip,
            option=icmpv6.nd_option_tla(hw_src=eth_src), res=7))
    pkt.add_protocol(icmpv6_nd_advert)
    pkt.serialize()
    return pkt


def icmpv6_echo_reply(vid, eth_src, eth_dst, src_ip, dst_ip, hop_limit,
                      id_, seq, data):
    """Return IPv6 ICMP echo reply packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): destination Ethernet MAC address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        dst_ip (ipaddress.IPv6Address): destination IPv6 address.
        hop_limit (int): IPv6 hop limit.
        id_ (int): identifier for echo reply.
        seq (int): sequence number for echo reply.
        data (str): payload for echo reply.
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 ICMP echo reply packet.
    """
    pkt = build_pkt_header(
        vid, eth_src, eth_dst, valve_of.ether.ETH_TYPE_IPV6)
    ipv6_reply = ipv6.ipv6(
        src=src_ip,
        dst=dst_ip,
        nxt=valve_of.inet.IPPROTO_ICMPV6,
        hop_limit=hop_limit)
    pkt.add_protocol(ipv6_reply)
    icmpv6_reply = icmpv6.icmpv6(
        type_=icmpv6.ICMPV6_ECHO_REPLY,
        data=icmpv6.echo(id_=id_, seq=seq, data=data))
    pkt.add_protocol(icmpv6_reply)
    pkt.serialize()
    return pkt


def router_advert(_vlan, vid, eth_src, eth_dst, src_ip, dst_ip,
                  vips, pi_flags=0x6):
    """Return IPv6 ICMP echo reply packet.

    Args:
        _vlan (VLAN): VLAN instance.
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): dest Ethernet MAC address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        vips (list): prefixes (ipaddress.IPv6Address) to advertise.
        pi_flags (int): flags to set in prefix information field (default set A and L)
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 ICMP RA packet.
    """
    pkt = build_pkt_header(
        vid, eth_src, eth_dst, valve_of.ether.ETH_TYPE_IPV6)
    ipv6_pkt = ipv6.ipv6(
        src=src_ip,
        dst=dst_ip,
        nxt=valve_of.inet.IPPROTO_ICMPV6,
        hop_limit=IPV6_MAX_HOP_LIM)
    pkt.add_protocol(ipv6_pkt)
    options = []
    for vip in vips:
        options.append(
            icmpv6.nd_option_pi(
                prefix=vip.network.network_address,
                pl=vip.network.prefixlen,
                res1=pi_flags,
                val_l=86400,
                pre_l=14400,
            ))
    options.append(icmpv6.nd_option_sla(hw_src=eth_src))
    # https://tools.ietf.org/html/rfc4861#section-4.6.2
    icmpv6_ra_pkt = icmpv6.icmpv6(
        type_=icmpv6.ND_ROUTER_ADVERT,
        data=icmpv6.nd_router_advert(
            rou_l=1800,
            ch_l=IPV6_MAX_HOP_LIM,
            options=options))
    pkt.add_protocol(icmpv6_ra_pkt)
    pkt.serialize()
    return pkt


def ip_header_size(eth_type):
    """Return size of a packet header with specified ether type."""
    ip_header = build_pkt_header(
        1, valve_of.mac.BROADCAST_STR, valve_of.mac.BROADCAST_STR, eth_type)
    ip_header.serialize()
    return len(ip_header.data)


class PacketMeta(object):
    """Original, and parsed Ethernet packet metadata."""

    def __init__(self, data, orig_len, pkt, eth_pkt, port, valve_vlan, eth_src, eth_dst, eth_type):
        self.data = data
        self.orig_len = orig_len
        self.pkt = pkt
        self.eth_pkt = eth_pkt
        self.port = port
        self.vlan = valve_vlan
        self.eth_src = eth_src
        self.eth_dst = eth_dst
        self.eth_type = eth_type

    def reparse(self, max_len):
        """Reparse packet using data up to the specified maximum length."""
        pkt, eth_pkt, vlan_vid, eth_type = parse_packet_in_pkt(
            self.data, max_len)
        if pkt is None or vlan_vid is None or eth_type is None:
            return
        self.pkt = pkt
        self.eth_pkt = eth_pkt

    def reparse_all(self):
        """Reparse packet with all available data."""
        self.reparse(0)

    def isfragment(self):
        """Return True if a fragment."""
        dpkt_ip = dpkt.ethernet.Ethernet(self.data)
        if isinstance(dpkt_ip.data, dpkt.ip.IP):
            if bool(dpkt_ip.data.off & dpkt.ip.IP_MF) or dpkt_ip.data.off & dpkt.ip.IP_OFFMASK:
                return True
        return False

    def reparse_ip(self, eth_type, payload=0):
        """Reparse packet with specified IP header type and optionally payload."""
        # Ryu blows up on fragments
        if self.isfragment():
            return
        self.reparse(ip_header_size(eth_type) + payload)

    def packet_complete(self):
        """True if we have the complete packet."""
        return len(self.data) == self.orig_len
