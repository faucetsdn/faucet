#!/usr/bin/env python

"""Unit tests run as PYTHONPATH=.. python3 ./test_valve.py."""

# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
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

from collections import namedtuple
import ipaddress
import logging
import os
import unittest
import tempfile
import shutil
import socket

from ryu.lib import mac
from ryu.lib.packet import arp, ethernet, icmp, icmpv6, ipv4, ipv6, packet, vlan
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

from prometheus_client import CollectorRegistry

from faucet import faucet_bgp
from faucet import faucet_experimental_event
from faucet import faucet_metrics
from faucet import valve
from faucet import valves_manager
from faucet import valve_of
from faucet import valve_packet
from faucet import valve_util

from fakeoftable import FakeOFTable


FAUCET_MAC = '0e:00:00:00:00:01'


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
        arp_code = arp.ARP_REQUEST
        if pkt['eth_dst'] == FAUCET_MAC:
            arp_code = arp.ARP_REPLY
        layers.append(arp.arp(
            src_ip=pkt['arp_source_ip'], dst_ip=pkt['arp_target_ip'], opcode=arp_code))
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


class ValveTestBase(unittest.TestCase):
    """Base class for all Valve unit tests."""

    CONFIG = """
dps:
    s1:
        ignore_learn_ins: 0
        dp_id: 1
        ofchannel_log: "/dev/null"
        hardware: 'GenericTFM'
        pipeline_config_dir: '%s/../etc/faucet'
        lldp_beacon:
            send_interval: 1
            max_per_interval: 1
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lldp_beacon:
                    enable: True
                    system_name: "faucet"
                    port_descr: "first_port"
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
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
        hardware: 'Open vSwitch'
        dp_id: 0xdeadbeef
        interfaces:
            p1:
                number: 1
                native_vlan: v100
    s3:
        hardware: 'Open vSwitch'
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
                stack:
                    dp: s4
                    port: 5
    s4:
        hardware: 'Open vSwitch'
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
""" % os.path.dirname(os.path.realpath(__file__))

    DP = 's1'
    DP_ID = 1
    NUM_PORTS = 5
    NUM_TABLES = 9
    P1_V100_MAC = '00:00:00:01:00:01'
    P2_V200_MAC = '00:00:00:02:00:02'
    P3_V200_MAC = '00:00:00:02:00:03'
    UNKNOWN_MAC = '00:00:00:04:00:04'
    V100 = 0x100|ofp.OFPVID_PRESENT
    V200 = 0x200|ofp.OFPVID_PRESENT
    V300 = 0x300|ofp.OFPVID_PRESENT
    LOGNAME = 'faucet'
    last_flows_to_dp = {}
    valve = None
    valves_manager = None
    metrics = None
    bgp = None
    table = None
    logger = None
    tmpdir = None
    faucet_event_sock = None
    registry = None
    sock = None
    notifier = None
    config_file = None

    def setup_valve(self, config):
        """Set up test DP with config."""
        self.tmpdir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.tmpdir, 'valve_unit.yaml')
        self.faucet_event_sock = os.path.join(self.tmpdir, 'event.sock')
        self.table = FakeOFTable(self.NUM_TABLES)
        logfile = os.path.join(self.tmpdir, 'faucet.log')
        self.logger = valve_util.get_logger(self.LOGNAME, logfile, logging.DEBUG, 0)
        self.registry = CollectorRegistry()
        # TODO: verify Prometheus variables
        self.metrics = faucet_metrics.FaucetMetrics(reg=self.registry) # pylint: disable=unexpected-keyword-arg
        # TODO: verify events
        self.notifier = faucet_experimental_event.FaucetExperimentalEventNotifier(
            self.faucet_event_sock, self.metrics, self.logger)
        self.bgp = faucet_bgp.FaucetBgp(self.logger, self.metrics, self.send_flows_to_dp_by_id)
        self.valves_manager = valves_manager.ValvesManager(
            self.LOGNAME, self.logger, self.metrics, self.notifier, self.bgp, self.send_flows_to_dp_by_id)
        self.notifier.start()
        self.update_config(config)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.faucet_event_sock)
        self.connect_dp()

    def teardown_valve(self):
        """Tear down test DP."""
        for handler in self.logger.handlers:
            handler.close()
        self.logger.handlers = []
        self.sock.close()
        shutil.rmtree(self.tmpdir)

    def send_flows_to_dp_by_id(self, dp_id, flows):
        """Callback for ValvesManager to simulate sending flows to DP."""
        self.last_flows_to_dp[dp_id] = flows

    def update_config(self, config):
        """Update FAUCET config with config as text."""
        self.assertFalse(self.valves_manager.config_watcher.files_changed())
        existing_config = os.path.exists(self.config_file)
        with open(self.config_file, 'w') as config_file:
            config_file.write(config)
        if existing_config:
            self.assertTrue(self.valves_manager.config_watcher.files_changed())
        self.last_flows_to_dp = {}
        self.valves_manager.request_reload_configs(self.config_file)
        self.valve = self.valves_manager.valves[self.DP_ID]
        if self.DP_ID in self.last_flows_to_dp:
            reload_ofmsgs = self.last_flows_to_dp[self.DP_ID]
            self.table.apply_ofmsgs(reload_ofmsgs)

    def connect_dp(self):
        """Call DP connect and set all ports to up."""
        discovered_ports = []
        for port_no in range(1, self.NUM_PORTS + 1):
            ofpport = parser.OFPPort(
                port_no=port_no,
                hw_addr=None,
                name=str(port_no),
                config=0,
                state=0,
                curr=0,
                advertised=0,
                supported=0,
                peer=0,
                curr_speed=1e6,
                max_speed=1e6)
            discovered_ports.append(ofpport)
        self.table.apply_ofmsgs(self.valve.datapath_connect(discovered_ports))
        for port in discovered_ports:
            self.set_port_up(port.port_no)

    def set_port_down(self, port_no):
        """Set port status of port to down."""
        self.table.apply_ofmsgs(self.valve.port_status_handler(
            port_no, ofp.OFPPR_DELETE, 0))

    def set_port_up(self, port_no):
        """Set port status of port to up."""
        self.table.apply_ofmsgs(self.valve.port_status_handler(
            port_no, ofp.OFPPR_ADD, 1))

    def flap_port(self, port_no):
        """Flap op status on a port."""
        self.set_port_down(port_no)
        self.set_port_up(port_no)

    @staticmethod
    def packet_outs_from_flows(flows):
        """Return flows that are packetout actions."""
        return [flow for flow in flows if isinstance(flow, valve_of.parser.OFPPacketOut)]

    def learn_hosts(self):
        """Learn some hosts."""
        self.rcv_packet(1, 0x100, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'ipv4_src': '10.0.0.1',
            'ipv4_dst': '10.0.0.2'})
        self.rcv_packet(2, 0x200, {
            'eth_src': self.P2_V200_MAC,
            'eth_dst': self.P3_V200_MAC,
            'ipv4_src': '10.0.0.2',
            'ipv4_dst': '10.0.0.3',
            'vid': 0x200})
        self.rcv_packet(3, 0x200, {
            'eth_src': self.P3_V200_MAC,
            'eth_dst': self.P2_V200_MAC,
            'ipv4_src': '10.0.0.3',
            'ipv4_dst': '10.0.0.4',
            'vid': 0x200})

    def verify_flooding(self, matches):
        """Verify flooding for a packet, depending on the DP implementation."""
        for match in matches:
            in_port = match['in_port']

            if ('vlan_vid' in match and
                    match['vlan_vid'] & ofp.OFPVID_PRESENT is not 0):
                valve_vlan = self.valve.dp.vlans[match['vlan_vid'] & ~ofp.OFPVID_PRESENT]
            else:
                valve_vlan = self.valve.dp.get_native_vlan(in_port)

            all_ports = set([port for port in self.valve.dp.ports.values() if port.running()])
            remaining_ports = all_ports - set([port for port in valve_vlan.get_ports() if port.running])

            # Packet must be flooded to all ports on the VLAN.
            for port in valve_vlan.get_ports():
                if valve_vlan.port_is_tagged(port):
                    vid = valve_vlan.vid|ofp.OFPVID_PRESENT
                else:
                    vid = 0
                if port.number == in_port:
                    self.assertFalse(
                        self.table.is_output(match, port=port.number, vid=vid),
                        msg=('Packet %s with unknown eth_dst flooded back to input port'
                             ' on VLAN %u to port %u' % (
                                 match, valve_vlan.vid, port.number)))
                else:
                    self.assertTrue(
                        self.table.is_output(match, port=port.number, vid=vid),
                        msg=('Packet %s with unknown eth_dst not flooded'
                             ' on VLAN %u to port %u' % (
                                 match, valve_vlan.vid, port.number)))

            # Packet must not be flooded to ports not on the VLAN.
            for port in remaining_ports:
                if port.stack:
                    self.assertTrue(
                        self.table.is_output(match, port=port.number),
                        msg=('Packet with unknown eth_dst not flooded to stack port %s' % port))
                elif not port.mirror:
                    self.assertFalse(
                        self.table.is_output(match, port=port.number),
                        msg=('Packet with unknown eth_dst flooded to non-VLAN, non-stack, non-mirror %s' % port))

    def rcv_packet(self, port, vid, match):
        """Simulate control plane receiving a packet on a port/VID."""
        pkt = build_pkt(match)
        vlan_pkt = pkt
        # TODO: packet submitted to packet in always has VID
        # Fake OF switch implementation should do this by applying actions.
        if vid not in match:
            vlan_match = match
            vlan_match['vid'] = vid
            vlan_pkt = build_pkt(match)
        msg = namedtuple(
            'null_msg',
            ('match', 'in_port', 'data', 'total_len', 'cookie', 'reason'))
        msg.reason = valve_of.ofp.OFPR_ACTION
        msg.data = vlan_pkt.data
        msg.total_len = len(msg.data)
        msg.match = {'in_port': port}
        msg.cookie = self.valve.dp.cookie
        pkt_meta = self.valve.parse_pkt_meta(msg)
        self.valves_manager.valve_packet_in(self.valve, pkt_meta) # pylint: disable=no-member
        rcv_packet_ofmsgs = self.last_flows_to_dp[self.DP_ID]
        self.table.apply_ofmsgs(rcv_packet_ofmsgs)
        resolve_ofmsgs = self.valve.resolve_gateways()
        self.table.apply_ofmsgs(resolve_ofmsgs)
        self.valve.advertise()
        self.valve.state_expire()
        self.valves_manager.update_metrics()
        return rcv_packet_ofmsgs


class ValveTestCase(ValveTestBase):
    """Test basic switching/L2/L3 functions."""

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def tearDown(self):
        self.teardown_valve()

    def test_disconnect(self):
        """Test disconnection of DP from controller."""
        # TODO: verify DP state change.
        self.valve.datapath_disconnect()

    def test_oferror(self):
        """Test OFError handler."""
        datapath = None
        msg = valve_of.parser.OFPFlowMod(datapath=datapath)
        msg.xid = 123
        self.valve.recent_ofmsgs.append(msg)
        test_error = valve_of.parser.OFPErrorMsg(datapath=datapath, msg=msg)
        self.valve.oferror(test_error)

    def test_switch_features(self):
        """Test switch features handler."""
        self.assertTrue(isinstance(self.valve, valve.TfmValve))
        features_flows = self.valve.switch_features(None)
        tfm_flows = [flow for flow in features_flows if isinstance(flow, valve_of.parser.OFPTableFeaturesStatsRequest)]
        # TODO: verify TFM content.
        self.assertTrue(tfm_flows)

    def test_arp_for_controller(self):
        """ARP request for controller VIP."""
        arp_replies = self.rcv_packet(1, 0x100, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': mac.BROADCAST_STR,
            'arp_source_ip': '10.0.0.1',
            'arp_target_ip': '10.0.0.254'})
        # TODO: check ARP reply is valid
        self.assertTrue(self.packet_outs_from_flows(arp_replies))

    def test_arp_reply_from_host(self):
        """ARP reply for host."""
        arp_replies = self.rcv_packet(1, 0x100, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': FAUCET_MAC,
            'arp_source_ip': '10.0.0.1',
            'arp_target_ip': '10.0.0.254'})
        # TODO: check ARP reply is valid
        self.assertTrue(arp_replies)
        self.assertFalse(self.packet_outs_from_flows(arp_replies))

    def test_nd_for_controller(self):
        """IPv6 ND for controller VIP."""
        dst_ip = ipaddress.IPv6Address('fc00::1:254')
        nd_mac = valve_packet.ipv6_link_eth_mcast(dst_ip)
        ip_gw_mcast = valve_packet.ipv6_solicited_node_from_ucast(dst_ip)
        nd_replies = self.rcv_packet(2, 0x200, {
            'eth_src': self.P2_V200_MAC,
            'eth_dst': nd_mac,
            'vid': 0x200,
            'ipv6_src': 'fc00::1:1',
            'ipv6_dst': str(ip_gw_mcast),
            'neighbor_solicit_ip': str(dst_ip)})
        # TODO: check ND reply is valid
        self.assertTrue(self.packet_outs_from_flows(nd_replies))

    def test_nd_from_host(self):
        """IPv6 NA from host."""
        na_replies = self.rcv_packet(2, 0x200, {
            'eth_src': self.P2_V200_MAC,
            'eth_dst': FAUCET_MAC,
            'vid': 0x200,
            'ipv6_src': 'fc00::1:1',
            'ipv6_dst': 'fc00::1:254',
            'neighbor_advert_ip': 'fc00::1:1'})
        # TODO: check NA response flows are valid
        self.assertTrue(na_replies)
        self.assertFalse(self.packet_outs_from_flows(na_replies))

    def test_ra_for_controller(self):
        """IPv6 RA for controller."""
        router_solicit_ip = 'ff02::2'
        ra_replies = self.rcv_packet(2, 0x200, {
            'eth_src': self.P2_V200_MAC,
            'eth_dst': '33:33:00:00:00:02',
            'vid': 0x200,
            'ipv6_src': 'fe80::1:1',
            'ipv6_dst': router_solicit_ip,
            'router_solicit_ip': router_solicit_ip})
        # TODO: check RA is valid
        self.assertTrue(self.packet_outs_from_flows(ra_replies))

    def test_icmp_ping_controller(self):
        """IPv4 ping controller VIP."""
        echo_replies = self.rcv_packet(1, 0x100, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': FAUCET_MAC,
            'vid': 0x100,
            'ipv4_src': '10.0.0.1',
            'ipv4_dst': '10.0.0.254',
            'echo_request_data': bytes('A'*8, encoding='UTF-8')})
        # TODO: check ping response
        self.assertTrue(self.packet_outs_from_flows(echo_replies))

    def test_add_del_route(self):
        """IPv4 add/del of a route."""
        arp_replies = self.rcv_packet(1, 0x100, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': mac.BROADCAST_STR,
            'arp_source_ip': '10.0.0.1',
            'arp_target_ip': '10.0.0.254'})
        # TODO: check arp reply is valid
        self.assertTrue(self.packet_outs_from_flows(arp_replies))
        valve_vlan = self.valve.dp.vlans[0x100]
        ip_dst = ipaddress.IPv4Network('10.100.100.0/24')
        ip_gw = ipaddress.IPv4Address('10.0.0.1')
        route_add_replies = self.valve.add_route(
            valve_vlan, ip_gw, ip_dst)
        # TODO: check add flows.
        self.assertTrue(route_add_replies)
        route_del_replies = self.valve.del_route(
            valve_vlan, ip_dst)
        # TODO: check del flows.
        self.assertTrue(route_del_replies)

    def test_host_ipv4_fib_route(self):
        """Test learning a FIB rule for an IPv4 host."""
        fib_route_replies = self.rcv_packet(1, 0x100, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'vid': 0x100,
            'ipv4_src': '10.0.0.2',
            'ipv4_dst': '10.0.0.4',
            'echo_request_data': bytes('A'*8, encoding='UTF-8')})
        # TODO: verify learning rule contents
        # We want to know this host was learned we did not get packet outs.
        self.assertTrue(fib_route_replies)
        self.assertFalse(self.packet_outs_from_flows(fib_route_replies))

    def test_host_ipv6_fib_route(self):
        """Test learning a FIB rule for an IPv6 host."""
        fib_route_replies = self.rcv_packet(2, 0x200, {
            'eth_src': self.P2_V200_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'vid': 0x200,
            'ipv6_src': 'fc00::1:2',
            'ipv6_dst': 'fc00::1:4',
            'echo_request_data': bytes('A'*8, encoding='UTF-8')})
        # TODO: verify learning rule contents
        # We want to know this host was learned we did not get packet outs.
        self.assertTrue(fib_route_replies)
        self.assertFalse(self.packet_outs_from_flows(fib_route_replies))

    def test_icmp_ping_unknown_neighbor(self):
        """IPv4 ping unknown host on same subnet, causing proactive learning."""
        echo_replies = self.rcv_packet(1, 0x100, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': FAUCET_MAC,
            'vid': 0x100,
            'ipv4_src': '10.0.0.1',
            'ipv4_dst': '10.0.0.99',
            'echo_request_data': bytes('A'*8, encoding='UTF-8')})
        # TODO: check proactive neighbor resolution
        self.assertTrue(self.packet_outs_from_flows(echo_replies))

    def test_icmpv6_ping_controller(self):
        """IPv6 ping controller VIP."""
        echo_replies = self.rcv_packet(2, 0x200, {
            'eth_src': self.P2_V200_MAC,
            'eth_dst': FAUCET_MAC,
            'vid': 0x200,
            'ipv6_src': 'fc00::1:1',
            'ipv6_dst': 'fc00::1:254',
            'echo_request_data': bytes('A'*8, encoding='UTF-8')})
        # TODO: check ping response
        self.assertTrue(self.packet_outs_from_flows(echo_replies))

    def test_invalid_vlan(self):
        """Test that packets with incorrect vlan tagging get dropped."""

        matches = [
            {'in_port': 1, 'vlan_vid': 18|ofp.OFPVID_PRESENT},
            {'in_port': 1, 'vlan_vid': self.V100},
            {'in_port': 3, 'vlan_vid': 0}]
        for match in matches:
            self.assertFalse(
                self.table.is_output(match),
                msg="Packets with incorrect vlan tags are output")

    def test_unknown_eth_src(self):
        """Test that packets from unknown macs are sent to controller.

        Untagged packets should have VLAN tags pushed before they are sent to
        the controller.
        """
        matches = [
            {'in_port': 1, 'vlan_vid': 0},
            {'in_port': 1, 'vlan_vid': 0, 'eth_src' : self.UNKNOWN_MAC},
            {
                'in_port': 1,
                'vlan_vid': 0,
                'eth_src' : self.P2_V200_MAC
                },
            {'in_port': 2, 'vlan_vid': 0, 'eth_dst' : self.UNKNOWN_MAC},
            {'in_port': 2, 'vlan_vid': 0},
            {
                'in_port': 2,
                'vlan_vid': self.V100,
                'eth_src' : self.P2_V200_MAC
                },
            {
                'in_port': 2,
                'vlan_vid': self.V100,
                'eth_src' : self.UNKNOWN_MAC,
                'eth_dst' : self.P1_V100_MAC
                },
            ]
        for match in matches:
            if match['vlan_vid'] != 0:
                vid = match['vlan_vid']
            else:
                vid = self.valve.dp.get_native_vlan(match['in_port']).vid
                vid = vid|ofp.OFPVID_PRESENT
            self.assertTrue(
                self.table.is_output(match, ofp.OFPP_CONTROLLER, vid=vid),
                msg="Packet with unknown ethernet src not sent to controller: "
                "{0}".format(match))

    def test_unknown_eth_dst_rule(self):
        """Test that packets with unkown eth dst addrs get flooded correctly.

        They must be output to each port on the associated vlan, with the
        correct vlan tagging. And they must not be forwarded to a port not
        on the associated vlan
        """
        self.learn_hosts()
        matches = [
            {
                'in_port': 3,
                'vlan_vid': self.V100,
            },
            {
                'in_port': 2,
                'vlan_vid': 0,
                'eth_dst': self.P1_V100_MAC
            },
            {
                'in_port': 1,
                'vlan_vid': 0,
                'eth_src': self.P1_V100_MAC
            },
            {
                'in_port': 3,
                'vlan_vid': self.V200,
                'eth_src': self.P2_V200_MAC,
            }
        ]
        self.verify_flooding(matches)

    def test_known_eth_src_rule(self):
        """Test that packets with known eth src addrs are not sent to controller."""
        self.learn_hosts()
        matches = [
            {
                'in_port': 1,
                'vlan_vid': 0,
                'eth_src': self.P1_V100_MAC
                },
            {
                'in_port': 2,
                'vlan_vid': self.V200,
                'eth_src': self.P2_V200_MAC
                },
            {
                'in_port': 3,
                'vlan_vid': self.V200,
                'eth_src': self.P3_V200_MAC,
                'eth_dst': self.P2_V200_MAC
                }
            ]
        for match in matches:
            self.assertFalse(
                self.table.is_output(match, port=ofp.OFPP_CONTROLLER),
                msg="Packet ({0}) output to controller when eth_src address"
                    " is known".format(match))

    def test_known_eth_src_deletion(self):
        """Verify that when a mac changes port the old rules get deleted.

        If a mac address is seen on one port, then seen on a different port on
        the same vlan the rules associated with that mac address on previous
        port need to be deleted. IE packets with that mac address arriving on
        the old port should be output to the controller."""

        self.rcv_packet(3, 0x200, {
            'eth_src': self.P2_V200_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'vlan_vid': 0x200,
            'ipv4_src': '10.0.0.3',
            'ipv4_dst': '10.0.0.3'})
        match = {'in_port': 2, 'vlan_vid': 0, 'eth_src': self.P2_V200_MAC}
        self.assertTrue(
            self.table.is_output(match, port=ofp.OFPP_CONTROLLER),
            msg='eth src rule not deleted when mac seen on another port')

    def test_known_eth_dst_rule(self):
        """Test that packets with known eth dst addrs are output correctly.

        Output to the correct port with the correct vlan tagging."""
        self.learn_hosts()
        match_results = [
            ({
                'in_port': 2,
                'vlan_vid': self.V100,
                'eth_dst': self.P1_V100_MAC
                }, {
                    'out_port': 1,
                    'vlan_vid': 0
                }),
            ({
                'in_port': 3,
                'vlan_vid': self.V200,
                'eth_dst': self.P2_V200_MAC,
                'eth_src': self.P3_V200_MAC
                }, {
                    'out_port': 2,
                    'vlan_vid': 0,
                })
            ]
        for match, result in match_results:
            self.assertTrue(
                self.table.is_output(
                    match, result['out_port'], vid=result['vlan_vid']),
                msg='packet not output to port correctly when eth dst is known')
            incorrect_ports = set(range(1, self.NUM_PORTS + 1))
            incorrect_ports.remove(result['out_port'])
            for port in incorrect_ports:
                self.assertFalse(
                    self.table.is_output(match, port=port),
                    msg=('packet %s output to incorrect port %u when eth_dst '
                         'is known' % (match, port)))

    def test_mac_learning_vlan_separation(self):
        """Test that when a mac is seen on a second vlan the original vlan
        rules are unaffected."""
        self.learn_hosts()
        self.rcv_packet(2, 0x200, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'vlan_vid': 0x200,
            'ipv4_src': '10.0.0.2',
            'ipv4_dst': '10.0.0.3'})

        # check eth_src rule
        match1 = {'in_port': 1, 'vlan_vid': 0, 'eth_src': self.P1_V100_MAC}
        self.assertFalse(
            self.table.is_output(match1, ofp.OFPP_CONTROLLER),
            msg=('mac address being seen on a vlan affects eth_src rule on '
                 'other vlan'))

        # check eth_dst rule
        match2 = {'in_port': 3, 'vlan_vid': self.V100, 'eth_dst': self.P1_V100_MAC}
        self.assertTrue(
            self.table.is_output(match2, port=1, vid=0),
            msg=('mac address being seen on a vlan affects eth_dst rule on '
                 'other vlan'))
        for port in (2, 4):
            self.assertFalse(
                self.table.is_output(match2, port=port),
                msg=('mac address being seen on a vlan affects eth_dst rule on '
                     'other vlan'))

    def test_known_eth_dst_rule_deletion(self):
        """Test that eth_dst rules are deleted when the mac is learned on
        another port.

        This should only occur when the mac is seen on the same vlan."""
        self.rcv_packet(2, 0x100, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'ipv4_src': '10.0.0.2',
            'ipv4_dst': '10.0.0.3'})
        match = {'in_port': 3, 'vlan_vid': self.V100, 'eth_dst': self.P1_V100_MAC}
        self.assertTrue(
            self.table.is_output(match, port=2, vid=self.V100),
            msg='Packet not output correctly after mac is learnt on new port')
        self.assertFalse(
            self.table.is_output(match, port=1),
            msg='Packet output on old port after mac is learnt on new port')

    def test_port_delete_eth_dst_removal(self):
        """Test that when a port is disabled packets are correctly output. """
        match = {'in_port': 2, 'vlan_vid': self.V100, 'eth_dst': self.P1_V100_MAC}

        valve_vlan = self.valve.dp.vlans[match['vlan_vid'] & ~ofp.OFPVID_PRESENT]
        ofmsgs = self.valve.port_delete(port_num=1)
        self.table.apply_ofmsgs(ofmsgs)

        # Check packets are output to each port on vlan
        for port in valve_vlan.get_ports():
            if port.number != match['in_port'] and port.running():
                if valve_vlan.port_is_tagged(port):
                    vid = valve_vlan.vid|ofp.OFPVID_PRESENT
                else:
                    vid = 0
                self.assertTrue(
                    self.table.is_output(match, port=port.number, vid=vid),
                    msg=('packet %s with eth dst learnt on deleted port not output '
                         'correctly on vlan %u to port %u' % (
                             match, valve_vlan.vid, port.number)))

    def test_port_down_eth_src_removal(self):
        """Test that when a port goes down and comes back up learnt mac
        addresses are deleted."""

        match = {'in_port': 1, 'vlan_vid': 0, 'eth_src': self.P1_V100_MAC}
        self.flap_port(1)
        self.assertTrue(
            self.table.is_output(match, port=ofp.OFPP_CONTROLLER),
            msg='Packet not output to controller after port bounce')

    def test_port_add_input(self):
        """Test that when a port is enabled packets are input correctly."""

        match = {'in_port': 1, 'vlan_vid': 0}
        self.table.apply_ofmsgs(
            self.valve.port_delete(port_num=1))
        self.assertFalse(
            self.table.is_output(match, port=2, vid=self.V100),
            msg='Packet output after port delete')

        self.table.apply_ofmsgs(
            self.valve.port_add(port_num=1))
        self.assertTrue(
            self.table.is_output(match, port=2, vid=self.V100),
            msg='Packet not output after port add')

    def test_port_acl_deny(self):
        """Test that port ACL denies forwarding."""
        acl_config = """
version: 2
dps:
    s1:
        ignore_learn_ins: 0
        hardware: 'Open vSwitch'
        dp_id: 1
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
                acl_in: drop_non_ospf_ipv4
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                native_vlan: v300
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
    v300:
        vid: 0x300
acls:
    drop_non_ospf_ipv4:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            actions:
                allow: 1
        - rule:
            dl_type: 0x800
            actions:
                allow: 0
"""

        drop_match = {
            'in_port': 2,
            'vlan_vid': 0,
            'eth_type': 0x800,
            'ipv4_dst': '192.0.2.1'}
        accept_match = {
            'in_port': 2,
            'vlan_vid': 0,
            'eth_type': 0x800,
            'ipv4_dst': '224.0.0.5'}
        # base case
        for match in (drop_match, accept_match):
            self.assertTrue(
                self.table.is_output(match, port=3, vid=self.V200),
                msg='Packet not output before adding ACL')

        self.update_config(acl_config)
        self.assertFalse(
            self.table.is_output(drop_match),
            msg='packet not blocked by ACL')
        self.assertTrue(
            self.table.is_output(accept_match, port=3, vid=self.V200),
            msg='packet not allowed by ACL')

    def test_lldp_beacon(self):
        """Test LLDP beacon service."""
        # TODO: verify LLDP packet content.
        self.assertTrue(self.valve.send_lldp_beacons())

    def test_unknown_port(self):
        """Test port status change for unknown port handled."""
        self.set_port_up(99)

    def test_move_port(self):
        self.rcv_packet(2, 0x200, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'vlan_vid': 0x200,
            'ipv4_src': '10.0.0.2',
            'ipv4_dst': '10.0.0.3'})
        self.rcv_packet(4, 0x200, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'vlan_vid': 0x200,
            'ipv4_src': '10.0.0.2',
            'ipv4_dst': '10.0.0.3'})


class ValveChangePortCase(ValveTestBase):

    CONFIG = """
dps:
    s1:
        dp_id: 1
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
                permanent_learn: True
"""

    LESS_CONFIG = """
dps:
    s1:
        dp_id: 1
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
                permanent_learn: False
"""

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def tearDown(self):
        self.teardown_valve()

    def test_delete_port(self):
        self.rcv_packet(2, 0x200, {
            'eth_src': self.P2_V200_MAC,
            'eth_dst': self.P3_V200_MAC,
            'ipv4_src': '10.0.0.2',
            'ipv4_dst': '10.0.0.3',
            'vid': 0x200})
        self.update_config(self.LESS_CONFIG)


class ValveACLTestCase(ValveTestBase):
    """Test ACL drop/allow and reloading."""

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def tearDown(self):
        self.teardown_valve()

    def test_vlan_acl_deny(self):
        """Test VLAN ACL denies a packet."""
        acl_config = """
dps:
    s1:
        ignore_learn_ins: 0
        hardware: 'Open vSwitch'
        dp_id: 1
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                native_vlan: v300
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
        acl_in: drop_non_ospf_ipv4
    v300:
        vid: 0x300
acls:
    drop_non_ospf_ipv4:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            actions:
                allow: 1
        - rule:
            dl_type: 0x800
            actions:
                allow: 0
"""

        drop_match = {
            'in_port': 2,
            'vlan_vid': 0,
            'eth_type': 0x800,
            'ipv4_dst': '192.0.2.1'}
        accept_match = {
            'in_port': 2,
            'vlan_vid': 0,
            'eth_type': 0x800,
            'ipv4_dst': '224.0.0.5'}
        # base case
        for match in (drop_match, accept_match):
            self.assertTrue(
                self.table.is_output(match, port=3, vid=self.V200),
                msg='Packet not output before adding ACL')

        self.update_config(acl_config)
        self.flap_port(2)
        self.assertFalse(
            self.table.is_output(drop_match),
            msg='Packet not blocked by ACL')
        self.assertTrue(
            self.table.is_output(accept_match, port=3, vid=self.V200),
            msg='Packet not allowed by ACL')


class ValveReloadConfigTestCase(ValveTestCase):
    """Repeats the tests after a config reload."""

    OLD_CONFIG = """
version: 2
dps:
    s1:
        ignore_learn_ins: 0
        hardware: 'Open vSwitch'
        dp_id: 1
        interfaces:
            p1:
                number: 1
                tagged_vlans: [v100, v200]
            p2:
                number: 2
                native_vlan: v100
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                native_vlan: v300
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
    v300:
        vid: 0x300
"""

    def setUp(self):
        self.setup_valve(self.OLD_CONFIG)
        self.flap_port(1)
        self.update_config(self.CONFIG)

    def tearDown(self):
        self.teardown_valve()


class ValveStackTestCase(ValveTestBase):
    """Test stacking/forwarding."""

    DP = 's3'
    DP_ID = 0x3

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def tearDown(self):
        self.teardown_valve()

    def test_stack_flood(self):
        """Test packet flooding when stacking."""
        matches = [
            {
                'in_port': 1,
                'vlan_vid': 0,
                'eth_src': self.P1_V100_MAC
            }]
        self.verify_flooding(matches)


class ValveMirrorTestCase(ValveTestCase):
    """Test ACL and interface mirroring."""
    # TODO: check mirror packets are present/correct

    CONFIG = """
acls:
    mirror_ospf:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            actions:
                mirror: p5
                allow: 1
        - rule:
            actions:
                allow: 1
dps:
    s1:
        ignore_learn_ins: 0
        dp_id: 1
        hardware: 'GenericTFM'
        pipeline_config_dir: '%s/../etc/faucet'
        lldp_beacon:
            send_interval: 1
            max_per_interval: 1
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lldp_beacon:
                    enable: True
                    system_name: "faucet"
                    port_descr: "first_port"
                acls_in: [mirror_ospf]
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                output_only: True
                mirror: 4
vlans:
    v100:
        vid: 0x100
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
""" % os.path.dirname(os.path.realpath(__file__))



if __name__ == "__main__":
    unittest.main()
