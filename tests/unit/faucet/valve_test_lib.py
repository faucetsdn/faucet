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


FAUCET_MAC = '0e:00:00:00:00:01'


# TODO: fix fake OF table implementation for in_port filtering
# (ie. do not output to in_port)
BASE_DP1_CONFIG = """
        dp_id: 1
        hardware: 'GenericTFM'
        egress_pipeline: True
        ignore_learn_ins: 100
        ofchannel_log: '/dev/null'
        packetin_pps: 99
        lldp_beacon:
            send_interval: 1
            max_per_interval: 1
"""

DP1_CONFIG = """
        combinatorial_port_flood: True
""" + BASE_DP1_CONFIG

IDLE_DP1_CONFIG = """
        use_idle_timeout: True
""" + DP1_CONFIG

GROUP_DP1_CONFIG = """
        group_table: True
""" + BASE_DP1_CONFIG

DOT1X_CONFIG = """
        dot1x:
            nfv_intf: lo
            nfv_sw_port: 2
            radius_ip: 127.0.0.1
            radius_port: 1234
            radius_secret: SECRET
""" + BASE_DP1_CONFIG

DOT1X_ACL_CONFIG = """
        dot1x:
            nfv_intf: lo
            nfv_sw_port: 2
            radius_ip: 127.0.0.1
            radius_port: 1234
            radius_secret: SECRET
            auth_acl: auth_acl
            noauth_acl: noauth_acl
""" + BASE_DP1_CONFIG

CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lldp_beacon:
                    enable: True
                    system_name: "faucet"
                    port_descr: "first_port"
                loop_protect: True
                receive_lldp: True
                max_hosts: 1
                hairpin: True
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
                loop_protect: True
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                tagged_vlans: [v300]

    s2:
        hardware: 'GenericTFM'
        dp_id: 0xdeadbeef
        interfaces:
            p1:
                number: 1
                native_vlan: v100
    s3:
        hardware: 'GenericTFM'
        combinatorial_port_flood: True
        dp_id: 0x3
        stack:
            priority: 1
        interfaces:
            p1:
                number: 1
                native_vlan: v300
            p2:
                number: 2
                native_vlan: v300
            p3:
                number: 3
                native_vlan: v300
            p4:
                number: 4
                native_vlan: v300
            5:
                description: p5
                stack:
                    dp: s4
                    port: 5
    s4:
        hardware: 'GenericTFM'
        dp_id: 0x4
        interfaces:
            p1:
                number: 1
                native_vlan: v300
            p2:
                number: 2
                native_vlan: v300
            p3:
                number: 3
                native_vlan: v300
            p4:
                number: 4
                native_vlan: v300
            5:
                description: p5
                number: 5
                stack:
                    dp: s3
                    port: 5
routers:
    router1:
        vlans: [v100, v200]
vlans:
    v100:
        vid: 0x100
        targeted_gw_resolution: True
        faucet_vips: ['10.0.0.254/24']
        routes:
            - route:
                ip_dst: 10.99.99.0/24
                ip_gw: 10.0.0.1
            - route:
                ip_dst: 10.99.98.0/24
                ip_gw: 10.0.0.99
    v200:
        vid: 0x200
        faucet_vips: ['fc00::1:254/112', 'fe80::1:254/64']
        routes:
            - route:
                ip_dst: 'fc00::10:0/112'
                ip_gw: 'fc00::1:1'
            - route:
                ip_dst: 'fc00::20:0/112'
                ip_gw: 'fc00::1:99'
    v300:
        vid: 0x300
    v400:
        vid: 0x400
""" % DP1_CONFIG


STACK_CONFIG = """
dps:
    s1:
%s
        stack:
            priority: 1
        interfaces:
            1:
                description: p1
                stack:
                    dp: s2
                    port: 1
            2:
                description: p2
                stack:
                    dp: s2
                    port: 2
            3:
                description: p3
                native_vlan: v100
    s2:
        hardware: 'GenericTFM'
        dp_id: 0x2
        stack:
            priority: 2
        interfaces:
            1:
                description: p1
                stack:
                    dp: s1
                    port: 1
            2:
                description: p2
                stack:
                    dp: s1
                    port: 2
            3:
                description: p3
                stack:
                    dp: s3
                    port: 2
            4:
                description: p4
                native_vlan: v100
    s3:
        dp_id: 0x3
        hardware: 'GenericTFM'
        interfaces:
            1:
                description: p1
                native_vlan: v100
            2:
                description: p2
                stack:
                    dp: s2
                    port: 3
vlans:
    v100:
        vid: 100
    """ % DP1_CONFIG
