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

import ipaddr

from ryu.lib import mac
from ryu.lib.packet import arp, ethernet, icmp, icmpv6, ipv4, ipv6, packet, vlan
from ryu.ofproto import ether
from ryu.ofproto import inet

def parse_pkt(pkt):
    return pkt.get_protocol(ethernet.ethernet)

def build_pkt_header(eth_src, eth_dst, vid, dl_type):
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

def arp_request(eth_src, vid, src_ip, dst_ip):
    pkt = build_pkt_header(eth_src, mac.BROADCAST_STR, vid, ether.ETH_TYPE_ARP)
    arp_pkt = arp.arp(
        opcode=arp.ARP_REQUEST, src_mac=eth_src,
        src_ip=str(src_ip), dst_mac=mac.DONTCARE_STR, dst_ip=str(dst_ip))
    pkt.add_protocol(arp_pkt)
    pkt.serialize()
    return pkt

def arp_reply(eth_src, eth_dst, vid, src_ip, dst_ip):
    pkt = build_pkt_header(eth_src, eth_dst, vid, ether.ETH_TYPE_ARP)
    arp_pkt = arp.arp(
        opcode=arp.ARP_REPLY, src_mac=eth_src,
        src_ip=src_ip, dst_mac=eth_dst, dst_ip=dst_ip)
    pkt.add_protocol(arp_pkt)
    pkt.serialize()
    return pkt

def echo_reply(eth_src, eth_dst, vid, src_ip, dst_ip, data):
    pkt = build_pkt_header(eth_src, eth_dst, vid, ether.ETH_TYPE_IP)
    ipv4_pkt = ipv4.ipv4(
        dst=dst_ip, src=src_ip, proto=inet.IPPROTO_ICMP)
    pkt.add_protocol(ipv4_pkt)
    icmp_pkt = icmp.icmp(
        type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE,
        data=data)
    pkt.add_protocol(icmp_pkt)
    pkt.serialize()
    return pkt

def ipv6_link_eth_mcast(ucast):
    nd_mac_bytes = ipaddr.Bytes('\x33\x33') + ucast.packed[-4:]
    nd_mac = ':'.join(['%02X' % ord(x) for x in nd_mac_bytes])
    return nd_mac

def ipv6_link_mcast_from_ucast(ucast):
    link_mcast_prefix = ipaddr.IPv6Network('ff02::1:ff00:0/104')
    mcast_bytes = ipaddr.Bytes(
        link_mcast_prefix.packed[:13] + ucast.packed[-3:])
    link_mcast = ipaddr.IPv6Address(mcast_bytes)
    return link_mcast

def nd_request(eth_src, vid, src_ip, dst_ip):
    nd_mac = ipv6_link_eth_mcast(dst_ip)
    ip_gw_mcast = ipv6_link_mcast_from_ucast(dst_ip)
    pkt = build_pkt_header(eth_src, nd_mac, vid, ether.ETH_TYPE_IPV6)
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

def nd_reply(eth_src, eth_dst, vid, src_ip, dst_ip, hop_limit):
    pkt = build_pkt_header(
        eth_src, eth_dst, vid, ether.ETH_TYPE_IPV6)
    ipv6_reply = ipv6.ipv6(
        src=src_ip,
        dst=dst_ip,
        nxt=inet.IPPROTO_ICMPV6,
        hop_limit=hop_limit)
    pkt.add_protocol(ipv6_reply)
    icmpv6_reply = icmpv6.icmpv6(
        type_=icmpv6.ND_NEIGHBOR_ADVERT,
        data=icmpv6.nd_neighbor(
            dst=src_ip,
            option=icmpv6.nd_option_tla(hw_src=eth_src), res=7))
    pkt.add_protocol(icmpv6_reply)
    pkt.serialize()
    return pkt

def icmpv6_echo_reply(eth_src, eth_dst, vid, src_ip, dst_ip, hop_limit,
                      id_, seq, data):
    pkt = build_pkt_header(
        eth_src, eth_dst, vid, ether.ETH_TYPE_IPV6)
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
