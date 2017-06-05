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
# distributed under the License is distributed on an "AS IS" BASISo
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ipaddress

from ryu.lib import mac
from ryu.lib.packet import arp, ethernet, icmp, icmpv6, ipv4, ipv6, stream_parser, packet, vlan
from ryu.ofproto import ether
from ryu.ofproto import inet

from valve_util import btos


IPV6_ALL_NODES_MCAST = '33:33:00:00:00:01'
IPV6_ALL_ROUTERS_MCAST = '33:33:00:00:00:02'
IPV6_LINK_LOCAL = ipaddress.IPv6Network(btos('fe80::/10'))
IPV6_ALL_NODES = ipaddress.IPv6Address(btos('ff02::1'))


def mac_addr_is_unicast(mac_addr):
    """Returns True if mac_addr is a unicast Ethernet address.

    Args:
        mac_addr (str): MAC address.
    Returns:
        bool: True if a unicast Ethernet address.
    """
    msb = mac_addr.split(':')[0]
    return msb[-1] in '02468aAcCeE'


def parse_pkt(pkt):
    """Return parsed Ethernet packet.

    Args:
        pkt (ryu.lib.packet.packet): packet received from dataplane.
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet.
    """
    return pkt.get_protocol(ethernet.ethernet)


def parse_packet_in_pkt(msg):
    pkt = None
    vlan_vid = None

    try:
        pkt = packet.Packet(msg.data)
    except stream_parser.StreamParser.TooSmallException:
        return (pkt, vlan_vid)

    eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
    eth_type = eth_pkt.ethertype
    # Packet ins, can only come when a VLAN header has already been pushed
    # (ie. when we have progressed past the VLAN table). This gaurantees
    # a VLAN header will always be present, so we know which VLAN the packet
    # belongs to.
    if eth_type == ether.ETH_TYPE_8021Q:
        # tagged packet
        vlan_proto = pkt.get_protocols(vlan.vlan)[0]
        vlan_vid = vlan_proto.vid
    return (pkt, vlan_vid)


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
            eth_dst, eth_src, ether.ETH_TYPE_8021Q)
        pkt_header.add_protocol(eth_header)
        vlan_header = vlan.vlan(vid=vid, ethertype=dl_type)
        pkt_header.add_protocol(vlan_header)
    return pkt_header


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
    pkt = build_pkt_header(vid, eth_src, mac.BROADCAST_STR, ether.ETH_TYPE_ARP)
    arp_pkt = arp.arp(
        opcode=arp.ARP_REQUEST, src_mac=eth_src,
        src_ip=str(src_ip), dst_mac=mac.DONTCARE_STR, dst_ip=str(dst_ip))
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
    pkt = build_pkt_header(vid, eth_src, eth_dst, ether.ETH_TYPE_ARP)
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
    pkt = build_pkt_header(vid, eth_src, eth_dst, ether.ETH_TYPE_IP)
    ipv4_pkt = ipv4.ipv4(
        dst=dst_ip, src=src_ip, proto=inet.IPPROTO_ICMP)
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
    pkt = build_pkt_header(vid, eth_src, nd_mac, ether.ETH_TYPE_IPV6)
    ipv6_pkt = ipv6.ipv6(
        src=str(src_ip), dst=ip_gw_mcast, nxt=inet.IPPROTO_ICMPV6)
    pkt.add_protocol(ipv6_pkt)
    icmpv6_pkt = icmpv6.icmpv6(
        type_=icmpv6.ND_NEIGHBOR_SOLICIT,
        data=icmpv6.nd_neighbor(
            dst=dst_ip,
            option=icmpv6.nd_option_sla(hw_src=eth_src)))
    pkt.add_protocol(icmpv6_pkt)
    pkt.serialize()
    return pkt


def nd_advert(vid, eth_src, eth_dst, src_ip, dst_ip, hop_limit):
    """Return IPv6 neighbor avertisement packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): destination Ethernet MAC address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        dst_ip (ipaddress.IPv6Address): destination IPv6 address.
        hop_limit (int): IPv6 hop limit.
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 neighbor discovery packet.
    """
    pkt = build_pkt_header(
        vid, eth_src, eth_dst, ether.ETH_TYPE_IPV6)
    ipv6_icmp6 = ipv6.ipv6(
        src=src_ip,
        dst=dst_ip,
        nxt=inet.IPPROTO_ICMPV6,
        hop_limit=hop_limit)
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
        vid, eth_src, eth_dst, ether.ETH_TYPE_IPV6)
    ipv6_reply = ipv6.ipv6(
        src=src_ip,
        dst=dst_ip,
        nxt=inet.IPPROTO_ICMPV6,
        hop_limit=hop_limit)
    pkt.add_protocol(ipv6_reply)
    icmpv6_reply = icmpv6.icmpv6(
        type_=icmpv6.ICMPV6_ECHO_REPLY,
        data=icmpv6.echo(id_=id_, seq=seq, data=data))
    pkt.add_protocol(icmpv6_reply)
    pkt.serialize()
    return pkt


def router_advert(vid, eth_src, eth_dst, src_ip, dst_ip,
                  vips, hop_limit=255, pi_flags=0x6):
    """Return IPv6 ICMP echo reply packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): dest Ethernet MAC address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        vips (list): prefixes (ipaddress.IPv6Address) to advertise.
        hop_limit (int): IPv6 hop limit.
        pi_flags (int): flags to set in prefix information field (default set A and L)
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 ICMP RA packet.
    """
    pkt = build_pkt_header(
        vid, eth_src, eth_dst, ether.ETH_TYPE_IPV6)
    ipv6_pkt = ipv6.ipv6(
        src=src_ip,
        dst=dst_ip,
        nxt=inet.IPPROTO_ICMPV6,
        hop_limit=hop_limit)
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
            ch_l=hop_limit,
            options=options))
    pkt.add_protocol(icmpv6_ra_pkt)
    pkt.serialize()
    return pkt
