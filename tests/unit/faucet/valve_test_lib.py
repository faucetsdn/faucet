#!/usr/bin/env python

"""Library for test_valve.py."""

# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.lib.packet import (
    arp, ethernet, icmp, icmpv6, ipv4, ipv6, lldp, slow, packet, vlan)
from ryu.ofproto import ether, inet
from faucet import valve_packet


def build_pkt(pkt):
    """Build and return a packet and eth type from a dict."""

    def serialize(layers):
        """Concatenate packet layers and serialize."""
        result = packet.Packet()
        for layer in reversed(layers):
            result.add_protocol(layer)
        result.serialize()
        return result

    layers = []
    assert 'eth_dst' in pkt and 'eth_src' in pkt
    ethertype = None
    if 'arp_source_ip' in pkt and 'arp_target_ip' in pkt:
        ethertype = ether.ETH_TYPE_ARP
        arp_code = pkt.get('arp_code', arp.ARP_REQUEST)
        layers.append(arp.arp(
            src_ip=pkt['arp_source_ip'],
            dst_ip=pkt['arp_target_ip'],
            opcode=arp_code))
    elif 'ipv6_src' in pkt and 'ipv6_dst' in pkt:
        ethertype = ether.ETH_TYPE_IPV6
        if 'router_solicit_ip' in pkt:
            layers.append(icmpv6.icmpv6(
                type_=icmpv6.ND_ROUTER_SOLICIT))
        elif 'neighbor_advert_ip' in pkt:
            layers.append(icmpv6.icmpv6(
                type_=icmpv6.ND_NEIGHBOR_ADVERT,
                data=icmpv6.nd_neighbor(
                    dst=pkt['neighbor_advert_ip'],
                    option=icmpv6.nd_option_sla(hw_src=pkt['eth_src']))))
        elif 'neighbor_solicit_ip' in pkt:
            layers.append(icmpv6.icmpv6(
                type_=icmpv6.ND_NEIGHBOR_SOLICIT,
                data=icmpv6.nd_neighbor(
                    dst=pkt['neighbor_solicit_ip'],
                    option=icmpv6.nd_option_sla(hw_src=pkt['eth_src']))))
        elif 'echo_request_data' in pkt:
            layers.append(icmpv6.icmpv6(
                type_=icmpv6.ICMPV6_ECHO_REQUEST,
                data=icmpv6.echo(id_=1, seq=1, data=pkt['echo_request_data'])))
        layers.append(ipv6.ipv6(
            src=pkt['ipv6_src'],
            dst=pkt['ipv6_dst'],
            nxt=inet.IPPROTO_ICMPV6))
    elif 'ipv4_src' in pkt and 'ipv4_dst' in pkt:
        ethertype = ether.ETH_TYPE_IP
        proto = inet.IPPROTO_IP
        if 'echo_request_data' in pkt:
            echo = icmp.echo(id_=1, seq=1, data=pkt['echo_request_data'])
            layers.append(icmp.icmp(type_=icmp.ICMP_ECHO_REQUEST, data=echo))
            proto = inet.IPPROTO_ICMP
        net = ipv4.ipv4(src=pkt['ipv4_src'], dst=pkt['ipv4_dst'], proto=proto)
        layers.append(net)
    elif 'actor_system' in pkt and 'partner_system' in pkt:
        ethertype = ether.ETH_TYPE_SLOW
        layers.append(slow.lacp(
            version=1,
            actor_system=pkt['actor_system'],
            actor_port=1,
            partner_system=pkt['partner_system'],
            partner_port=1,
            actor_key=1,
            partner_key=1,
            actor_system_priority=65535,
            partner_system_priority=1,
            actor_port_priority=255,
            partner_port_priority=255,
            actor_state_defaulted=0,
            partner_state_defaulted=0,
            actor_state_expired=0,
            partner_state_expired=0,
            actor_state_timeout=1,
            partner_state_timeout=1,
            actor_state_collecting=1,
            partner_state_collecting=1,
            actor_state_distributing=1,
            partner_state_distributing=1,
            actor_state_aggregation=1,
            partner_state_aggregation=1,
            actor_state_synchronization=pkt['actor_state_synchronization'],
            partner_state_synchronization=1,
            actor_state_activity=0,
            partner_state_activity=0))
    elif 'chassis_id' in pkt and 'port_id' in pkt:
        ethertype = ether.ETH_TYPE_LLDP
        return valve_packet.lldp_beacon(
            pkt['eth_src'], pkt['chassis_id'], str(pkt['port_id']), 1,
            org_tlvs=pkt.get('org_tlvs', None),
            system_name=pkt.get('system_name', None))
    assert ethertype is not None, pkt
    if 'vid' in pkt:
        tpid = ether.ETH_TYPE_8021Q
        layers.append(vlan.vlan(vid=pkt['vid'], ethertype=ethertype))
    else:
        tpid = ethertype
    eth = ethernet.ethernet(
        dst=pkt['eth_dst'],
        src=pkt['eth_src'],
        ethertype=tpid)
    layers.append(eth)
    result = serialize(layers)
    return result
