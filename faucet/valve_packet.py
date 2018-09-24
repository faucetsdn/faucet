"""Utility functions for parsing and building Ethernet packet/contents."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
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
import socket
import struct

from ryu.lib import addrconv
from ryu.lib.mac import BROADCAST, is_multicast, haddr_to_bin
from ryu.lib.packet import (
    arp, bpdu, ethernet,
    icmp, icmpv6, ipv4, ipv6,
    lldp, slow, packet, vlan)
from ryu.lib.packet.stream_parser import StreamParser

from faucet import valve_util
from faucet import valve_of

FAUCET_MAC = '0e:00:00:00:00:01' # Default FAUCET MAC address

ETH_HEADER_SIZE = 14
ETH_VLAN_HEADER_SIZE = ETH_HEADER_SIZE + 4 # https://en.wikipedia.org/wiki/IEEE_802.1Q#Frame_format
IPV4_HEADER_SIZE = 20 # https://en.wikipedia.org/wiki/IPv4#Header
ICMP_ECHO_REQ_SIZE = 8 + 64 # https://en.wikipedia.org/wiki/Ping_(networking_utility)#ICMP_packet
IPV6_HEADER_SIZE = 40 # https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header
ARP_REQ_PKT_SIZE = 28
ARP_PKT_SIZE = 46 # https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
VLAN_ARP_REQ_PKT_SIZE = ETH_VLAN_HEADER_SIZE + ARP_REQ_PKT_SIZE
VLAN_ARP_PKT_SIZE = ETH_VLAN_HEADER_SIZE + ARP_PKT_SIZE
VLAN_ICMP_ECHO_REQ_SIZE = ETH_VLAN_HEADER_SIZE + IPV4_HEADER_SIZE + ICMP_ECHO_REQ_SIZE

ETH_EAPOL = 0x888e
SLOW_PROTOCOL_MULTICAST = slow.SLOW_PROTOCOL_MULTICAST
BRIDGE_GROUP_ADDRESS = bpdu.BRIDGE_GROUP_ADDRESS
BRIDGE_GROUP_MASK = 'ff:ff:ff:ff:ff:f0'
LLDP_MAC_NEAREST_BRIDGE = lldp.LLDP_MAC_NEAREST_BRIDGE
CISCO_SPANNING_GROUP_ADDRESS = '01:00:0c:cc:cc:cd'
IPV6_ALL_NODES_MCAST = '33:33:00:00:00:01'
IPV6_ALL_ROUTERS_MCAST = '33:33:00:00:00:02'
IPV6_ALL_NODES = ipaddress.IPv6Address('ff02::1')
IPV6_MAX_HOP_LIM = 255
IPV6_RA_HOP_LIM = 64

LLDP_FAUCET_DP_ID = 1
LLDP_FAUCET_STACK_STATE = 2

LACP_SIZE = 124


def int_from_mac(mac):
    int_hi, int_lo = [int(i, 16) for i in mac.split(':')[-2:]]
    return (int_hi << 8) + int_lo


def int_in_mac(mac, to_int):
    int_mac = mac.split(':')[:4] + [
        '%x' % (to_int >> 8), '%x' % (to_int & 0xff)]
    return ':'.join(int_mac)


def ipv4_parseable(ip_header_data):
    """Return True if an IPv4 packet we could parse."""
    # TODO: python library parsers are fragile
    # Perform sanity checking on the header to limit exposure of the parser
    ipv4_header = struct.unpack('!BBHHHBBH4s4s', ip_header_data[:IPV4_HEADER_SIZE])
    header_size = (ipv4_header[0] & 0xf) * 32 / 8
    if header_size < IPV4_HEADER_SIZE:
        return False
    flags = ipv4_header[4] >> 12
    # MF bit set
    if flags & 0x2:
        return False
    # fragment - discard
    ip_off = ipv4_header[4] & 0xfff
    if ip_off:
        return False
    # not a protocol conservatively known to parse
    protocol = ipv4_header[6]
    if protocol not in (socket.IPPROTO_ICMP, socket.IPPROTO_UDP, socket.IPPROTO_TCP):
        return False
    return True


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


def parse_lacp_pkt(pkt):
    """Return parsed LACP packet.

    Args:
        pkt (ryu.lib.packet.packet): packet received from dataplane.
    Returns:
        ryu.lib.packet.lacp: LACP packet.
    """
    return pkt.get_protocol(slow.lacp)


def parse_lldp(pkt):
    """Return parsed LLDP packet.

    Args:
        pkt (ryu.lib.packet.packet): packet received from dataplane.
    Returns:
        ryu.lib.packet.lldp: LLDP packet.
    """
    return pkt.get_protocol(lldp.lldp)


def parse_packet_in_pkt(data, max_len, eth_pkt=None, vlan_pkt=None):
    """Parse a packet received via packet in from the dataplane.

    Args:
        data (bytearray): packet data from dataplane.
        max_len (int): max number of packet data bytes to parse.
    Returns:
        ryu.lib.packet.packet: raw packet
        ryu.lib.packet.ethernet: parsed Ethernet packet.
        int: Ethernet type of packet (inside VLAN)
        int: VLAN VID (or None if no VLAN)
    """
    pkt = None
    eth_type = None
    vlan_vid = None

    if max_len:
        data = data[:max_len]

    try:
        # Packet may or may not have a VLAN tag - whether it is user
        # traffic, or control like LACP/LLDP.
        if vlan_pkt is None:
            if eth_pkt is None:
                pkt = packet.Packet(data[:ETH_HEADER_SIZE])
                eth_pkt = parse_eth_pkt(pkt)
            eth_type = eth_pkt.ethertype
            if eth_type == valve_of.ether.ETH_TYPE_8021Q:
                pkt, vlan_pkt = packet.Packet(data[:ETH_VLAN_HEADER_SIZE])
        if vlan_pkt:
            vlan_vid = vlan_pkt.vid
            eth_type = vlan_pkt.ethertype
        if len(data) > ETH_VLAN_HEADER_SIZE:
            pkt = packet.Packet(data)
    except (AttributeError, AssertionError, StreamParser.TooSmallException):
        pass

    return (pkt, eth_pkt, eth_type, vlan_pkt, vlan_vid)


def mac_addr_is_unicast(mac_addr):
    """Returns True if mac_addr is a unicast Ethernet address.

    Args:
        mac_addr (str): MAC address.
    Returns:
        bool: True if a unicast Ethernet address.
    """
    mac_bin = haddr_to_bin(mac_addr)
    if mac_bin == BROADCAST:
        return False
    return not is_multicast(mac_bin)


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


def lldp_beacon(eth_src, chassis_id, port_id, ttl, org_tlvs=None,
                system_name=None, port_descr=None):
    """Return an LLDP frame suitable for a host/access port.

    Args:
        eth_src (str): source Ethernet MAC address.
        chassis_id (str): Chassis ID.
        port_id (int): port ID,
        TTL (int): TTL for payload.
        org_tlvs (list): list of tuples of (OUI, subtype, info).
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet with header.
    """
    pkt = build_pkt_header(
        None, eth_src, lldp.LLDP_MAC_NEAREST_BRIDGE, valve_of.ether.ETH_TYPE_LLDP)
    tlvs = [
        lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_MAC_ADDRESS,
            chassis_id=addrconv.mac.text_to_bin(chassis_id)),
        lldp.PortID(
            subtype=lldp.PortID.SUB_INTERFACE_NAME,
            port_id=str(port_id).encode('utf-8')),
        lldp.TTL(
            ttl=ttl)
    ]
    for tlv, info_name, info in (
            (lldp.SystemName, 'system_name', system_name),
            (lldp.PortDescription, 'port_description', port_descr)):
        if info is not None:
            info_args = {info_name: info.encode('UTF-8')}
            tlvs.append(tlv(**info_args))
    if org_tlvs is not None:
        for tlv_oui, tlv_subtype, tlv_info in org_tlvs:
            tlvs.append(
                lldp.OrganizationallySpecific(
                    oui=tlv_oui,
                    subtype=tlv_subtype,
                    info=tlv_info))
    tlvs.append(lldp.End())
    lldp_pkt = lldp.lldp(tlvs)
    pkt.add_protocol(lldp_pkt)
    pkt.serialize()
    return pkt


def faucet_oui(mac):
    """Return first 3 bytes of MAC address (given as str)."""
    return addrconv.mac.text_to_bin(mac)[:3]


def faucet_lldp_tlvs(dp):
    """Return LLDP TLVs for a datapath."""
    tlvs = []
    tlvs.append(
        (faucet_oui(dp.faucet_dp_mac), LLDP_FAUCET_DP_ID, str(dp.dp_id).encode('utf-8')))
    return tlvs


def faucet_lldp_stack_state_tlvs(dp, port):
    """Return a LLDP TLV for state of a stack port."""
    tlvs = []
    if not port.stack:
        return []
    tlvs.append(
        (
            faucet_oui(dp.faucet_dp_mac),
            LLDP_FAUCET_STACK_STATE,
            str(port.dyn_stack_current_state).encode('utf-8')))
    return tlvs


def tlvs_by_type(tlvs, tlv_type):
    """Return list of TLVs with matching type."""
    return [tlv for tlv in tlvs if tlv.tlv_type == tlv_type]


def tlvs_by_subtype(tlvs, subtype):
    """Return list of TLVs with matching type."""
    return [tlv for tlv in tlvs if tlv.subtype == subtype]


def tlv_cast(tlvs, tlv_attr, cast_func):
    """Return cast'd attribute of first TLV or None."""
    tlv_val = None
    if tlvs:
        try:
            tlv_val = cast_func(getattr(tlvs[0], tlv_attr))
        except (AttributeError, ValueError, TypeError):
            pass
    return tlv_val


def faucet_tlvs(lldp_pkt, faucet_dp_mac):
    """Return list of TLVs with FAUCET OUI."""
    return [tlv for tlv in tlvs_by_type(
        lldp_pkt.tlvs, lldp.LLDP_TLV_ORGANIZATIONALLY_SPECIFIC)
            if tlv.oui == faucet_oui(faucet_dp_mac)]


def parse_faucet_lldp(lldp_pkt, faucet_dp_mac):
    """Parse and return FAUCET TLVs from LLDP packet."""
    remote_dp_id = None
    remote_dp_name = None
    remote_port_id = None
    remote_port_state = None

    tlvs = faucet_tlvs(lldp_pkt, faucet_dp_mac)
    if tlvs:
        dp_id_tlvs = tlvs_by_subtype(tlvs, LLDP_FAUCET_DP_ID)
        dp_name_tlvs = tlvs_by_type(lldp_pkt.tlvs, lldp.LLDP_TLV_SYSTEM_NAME)
        port_id_tlvs = tlvs_by_type(lldp_pkt.tlvs, lldp.LLDP_TLV_PORT_ID)
        port_state_tlvs = tlvs_by_subtype(tlvs, LLDP_FAUCET_STACK_STATE)
        remote_dp_id = tlv_cast(dp_id_tlvs, 'info', int)
        remote_port_id = tlv_cast(port_id_tlvs, 'port_id', int)
        remote_port_state = tlv_cast(port_state_tlvs, 'info', int)
        remote_dp_name = tlv_cast(dp_name_tlvs, 'system_name', valve_util.utf8_decode)
    return (remote_dp_id, remote_dp_name, remote_port_id, remote_port_state)


def lacp_reqreply(eth_src,
                  actor_system, actor_key, actor_port,
                  actor_state_synchronization=0,
                  actor_state_activity=0,
                  partner_system='00:00:00:00:00:00',
                  partner_key=0,
                  partner_port=0,
                  partner_system_priority=0,
                  partner_port_priority=0,
                  partner_state_defaulted=0,
                  partner_state_expired=0,
                  partner_state_timeout=0,
                  partner_state_collecting=0,
                  partner_state_distributing=0,
                  partner_state_aggregation=0,
                  partner_state_synchronization=0,
                  partner_state_activity=0):
    """Return a LACP frame.

    Args:
        eth_src (str): source Ethernet MAC address.
        actor_system (str): actor system ID (MAC address)
        actor_key (int): actor's LACP key assigned to this port.
        actor_port (int): actor port number.
        actor_state_synchronization (int): 1 if we will use this link.
        actor_state_activity (int): 1 if actively sending LACP.
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
        actor_state_synchronization=actor_state_synchronization,
        partner_state_synchronization=partner_state_synchronization,
        actor_state_activity=actor_state_activity,
        partner_state_activity=partner_state_activity)
    pkt.add_protocol(lacp_pkt)
    pkt.serialize()
    return pkt


def arp_request(vid, eth_src, eth_dst, src_ip, dst_ip):
    """Return an ARP request packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): Ethernet source address.
        eth_dst (str): Ethernet destination address.
        src_ip (ipaddress.IPv4Address): source IPv4 address.
        dst_ip (ipaddress.IPv4Address): requested IPv4 address.
    Returns:
        ryu.lib.packet.arp: serialized ARP request packet.
    """
    pkt = build_pkt_header(
        vid, eth_src, eth_dst, valve_of.ether.ETH_TYPE_ARP)
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
    mcast_mac = ':'.join(['%02X' % x for x in mcast_mac_bytes])
    return mcast_mac


def ipv6_solicited_node_from_ucast(ucast):
    """Return IPv6 solicited node multicast address from IPv6 unicast address.

    See RFC 3513 section 2.7.1.

    Args:
       ucast (ipaddress.IPv6Address): IPv6 unicast address.
    Returns:
       ipaddress.IPv6Address: IPv6 solicited node multicast address.
    """
    link_mcast_prefix = ipaddress.ip_interface('ff02::1:ff00:0/104')
    mcast_bytes = link_mcast_prefix.packed[:13] + ucast.packed[-3:]
    link_mcast = ipaddress.IPv6Address(mcast_bytes)
    return link_mcast


def nd_request(vid, eth_src, eth_dst, src_ip, dst_ip):
    """Return IPv6 neighbor discovery request packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): Ethernet destination address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        dst_ip (ipaddress.IPv6Address): requested IPv6 address.
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 neighbor discovery packet.
    """
    if mac_addr_is_unicast(eth_dst):
        nd_mac = eth_dst
        nd_ip = dst_ip
    else:
        nd_mac = ipv6_link_eth_mcast(dst_ip)
        nd_ip = ipv6_solicited_node_from_ucast(dst_ip)
    pkt = build_pkt_header(vid, eth_src, nd_mac, valve_of.ether.ETH_TYPE_IPV6)
    ipv6_pkt = ipv6.ipv6(
        src=str(src_ip), dst=nd_ip, nxt=valve_of.inet.IPPROTO_ICMPV6)
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
    r"""Return IPv6 ICMP echo reply packet.

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


def router_advert(vid, eth_src, eth_dst, src_ip, dst_ip,
                  vips, pi_flags=0x6):
    """Return IPv6 ICMP Router Advert.

    Args:
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
            ch_l=IPV6_RA_HOP_LIM,
            options=options))
    pkt.add_protocol(icmpv6_ra_pkt)
    pkt.serialize()
    return pkt


class PacketMeta:
    """Original, and parsed Ethernet packet metadata."""

    __slots__ = [
        'data',
        'orig_len',
        'pkt',
        'eth_pkt',
        'vlan_pkt',
        'port',
        'vlan',
        'eth_src',
        'eth_dst',
        'eth_type',
        'l3_pkt',
        'l3_src',
        'l3_dst',
    ]

    ETH_TYPES_PARSERS = {
        valve_of.ether.ETH_TYPE_IP: (4, ipv4_parseable, ipv4.ipv4),
        valve_of.ether.ETH_TYPE_ARP: (None, None, arp.arp),
        valve_of.ether.ETH_TYPE_IPV6: (6, None, ipv6.ipv6),
    }

    MIN_ETH_TYPE_PKT_SIZE = {
        valve_of.ether.ETH_TYPE_ARP: VLAN_ARP_REQ_PKT_SIZE,
        valve_of.ether.ETH_TYPE_IP: ETH_VLAN_HEADER_SIZE + IPV4_HEADER_SIZE,
        valve_of.ether.ETH_TYPE_IPV6: ETH_VLAN_HEADER_SIZE + IPV6_HEADER_SIZE,
    }

    MAX_ETH_TYPE_PKT_SIZE = {
        valve_of.ether.ETH_TYPE_ARP: VLAN_ARP_PKT_SIZE,
        valve_of.ether.ETH_TYPE_IP: VLAN_ICMP_ECHO_REQ_SIZE,
    }

    def __init__(self, data, orig_len, pkt, eth_pkt, vlan_pkt, port, valve_vlan,
                 eth_src, eth_dst, eth_type):
        self.data = data
        self.orig_len = orig_len
        self.pkt = pkt
        self.eth_pkt = eth_pkt
        self.vlan_pkt = vlan_pkt
        self.port = port
        self.vlan = valve_vlan
        self.eth_src = eth_src
        self.eth_dst = eth_dst
        self.eth_type = eth_type
        self.l3_pkt = None
        self.l3_src = None
        self.l3_dst = None

    def log(self):
        vlan_msg = ''
        if self.vlan:
            vlan_msg = 'VLAN %u' % self.vlan.vid
        return '%s (L2 type 0x%4.4x, L3 src %s, L3 dst %s) %s %s' % (
            self.eth_src, self.eth_type, self.l3_src, self.l3_dst,
            self.port, vlan_msg)

    def reparse(self, max_len):
        """Reparse packet using data up to the specified maximum length."""
        pkt, eth_pkt, eth_type, vlan_pkt, _ = parse_packet_in_pkt(
            self.data, max_len, eth_pkt=self.eth_pkt, vlan_pkt=self.vlan_pkt)
        if pkt is None or eth_type is None:
            return
        right_size = self.MAX_ETH_TYPE_PKT_SIZE.get(eth_type, len(self.data))
        if len(self.data) > right_size:
            self.data = self.data[:right_size]
        self.pkt = pkt
        self.eth_pkt = eth_pkt
        self.vlan_pkt = vlan_pkt

    def reparse_all(self):
        """Reparse packet with all available data."""
        self.reparse(0)

    def ip_ver(self):
        """Return IP version number."""
        if len(self.data) > ETH_VLAN_HEADER_SIZE:
            ip_header = self.data[ETH_VLAN_HEADER_SIZE:]
            return ip_header[0] >> 4
        return None

    def reparse_ip(self, payload=0):
        """Reparse packet with specified IP header type and optionally payload."""
        if self.eth_type in self.ETH_TYPES_PARSERS:
            header_size = self.MIN_ETH_TYPE_PKT_SIZE[self.eth_type]
            ip_ver, ip_parseable, pkt_parser = self.ETH_TYPES_PARSERS[self.eth_type]
            if ip_ver is not None:
                if ip_ver != self.ip_ver():
                    return
                if self.vlan is not None and self.vlan.minimum_ip_size_check:
                    if len(self.data) < header_size:
                        return
                ip_header_data = self.data[ETH_VLAN_HEADER_SIZE:]
                if ip_parseable is not None and not ip_parseable(ip_header_data):
                    return
            parse_limit = header_size + payload
            self.reparse(parse_limit)
            self.l3_pkt = self.pkt.get_protocol(pkt_parser)
            if self.l3_pkt:
                if hasattr(self.l3_pkt, 'src'):
                    self.l3_src = self.l3_pkt.src
                    self.l3_dst = self.l3_pkt.dst
                elif hasattr(self.l3_pkt, 'src_ip'):
                    self.l3_src = self.l3_pkt.src_ip
                    self.l3_dst = self.l3_pkt.dst_ip
                self.l3_src = ipaddress.ip_address(self.l3_src)
                self.l3_dst = ipaddress.ip_address(self.l3_dst)

    def packet_complete(self):
        """True if we have the complete packet."""
        return len(self.data) == self.orig_len
