#!/usr/bin/env python

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
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

import hashlib
import logging
import sys
import os
import ipaddress

testdir = os.path.dirname(__file__)
srcdir = '../'
sys.path.insert(0, os.path.abspath(os.path.join(testdir, srcdir)))

import unittest
from faucet.config_parser import dp_parser, watcher_parser

class DistConfigTestCase(unittest.TestCase):
    def setUp(self):
        logname = 'test_config'

        logger = logging.getLogger('%s.config' % logname)
        logger_handler = logging.StreamHandler(stream=sys.stderr)
        log_fmt = '%(asctime)s %(name)-6s %(levelname)-8s %(message)s'
        logger_handler.setFormatter(
            logging.Formatter(log_fmt, '%b %d %H:%M:%S'))
        logger.addHandler(logger_handler)
        logger.propagate = 0
        logger.setLevel(logging.CRITICAL)

        self.v2_config_hashes, v2_dps = dp_parser('config/testconfigv2.yaml', logname)
        self.v2_dps_by_id = {}
        for dp in v2_dps:
            self.v2_dps_by_id[dp.dp_id] = dp
        self.v2_dp = self.v2_dps_by_id[0xcafef00d]
        self.v2_watchers = watcher_parser(
            'config/testgaugeconfig.yaml', logname)

    def test_hashes(self):
        testconfigv2_yaml = os.path.realpath('config/testconfigv2.yaml')
        testconfigv2_dps_yaml = os.path.realpath('config/testconfigv2-dps.yaml')
        testconfigv2_vlans_yaml = os.path.realpath('config/testconfigv2-vlans.yaml')
        testconfigv2_acls_yaml = os.path.realpath('config/testconfigv2-acls.yaml')
        testconfigv2_includeloop_yaml = os.path.realpath('config/testconfigv2-includeloop.yaml')

        with open(testconfigv2_yaml, 'r') as f:
            self.assertEquals(self.v2_config_hashes[testconfigv2_yaml], hashlib.sha256(f.read()).hexdigest())
        with open(testconfigv2_dps_yaml, 'r') as f:
            self.assertEquals(self.v2_config_hashes[testconfigv2_dps_yaml], hashlib.sha256(f.read()).hexdigest())
        with open(testconfigv2_vlans_yaml, 'r') as f:
            self.assertEquals(self.v2_config_hashes[testconfigv2_vlans_yaml], hashlib.sha256(f.read()).hexdigest())
        with open(testconfigv2_acls_yaml, 'r') as f:
            self.assertEquals(self.v2_config_hashes[testconfigv2_acls_yaml], hashlib.sha256(f.read()).hexdigest())
        # Not loaded due to the include loop.
        self.assertIsNone(self.v2_config_hashes[testconfigv2_includeloop_yaml])

    def test_dps(self):
        for dp in (self.v2_dp,):
            # confirm that DPIDs match
            self.assertEqual(dp.dp_id, 0xcafef00d)

    def test_stacking(self):
        switch1 = self.v2_dps_by_id[0xcafef00d]
        switch2 = self.v2_dps_by_id[0xdeadbeef]
        self.assertEqual(switch1.stack['priority'], 1)
        self.assertEqual(
            switch1.ports[7].stack['dp'], switch2)
        self.assertEqual(
            switch1.ports[7].stack['port'], switch2.ports[1])
        self.assertEqual(
            switch2.ports[1].stack['dp'], switch1)
        self.assertEqual(
            switch2.ports[1].stack['port'], switch1.ports[7])
        self.assertEqual(
            switch1.stack['root_dp'], switch1)
        self.assertEqual(
            switch2.stack['root_dp'], switch1)
        self.assertEqual(
            ['switch1', 'switch2'], switch1.shortest_path(switch2.name))
        self.assertEqual(
            [], switch1.shortest_path_to_root())
        self.assertEqual(
            ['switch2', 'switch1'], switch2.shortest_path_to_root())
        self.assertEqual(
            switch1.ports[7], switch1.shortest_path_port('switch2'))
        edges = [edge for edge in switch1.stack['graph'].adjacency_iter()]
        self.assertEqual(
            2, len(edges))
        edge_from_switch_a, edge_from_switch_z = edges
        _, edge_data_a = edge_from_switch_a
        _, edge_data_b = edge_from_switch_z
        self.assertEqual(
            edge_data_a.values(), edge_data_b.values())

    def test_port_numbers(self):
        self.assertEqual(set(self.v2_dp.ports.keys()), set([1, 2, 3, 4, 5, 6, 7]))

    def test_ports_vlans(self):
        for dp in (self.v2_dp,):
            # load ports for easy reading
            portcafef00d_1 = dp.ports[1]
            portcafef00d_2 = dp.ports[2]
            portcafef00d_3 = dp.ports[3]
            portcafef00d_4 = dp.ports[4]
            portcafef00d_5 = dp.ports[5]
            vlan_40 = dp.vlans[40]
            vlan_41 = dp.vlans[41]
            # check that the ports are in the right vlans
            self.assertIn(portcafef00d_1, vlan_40.tagged)
            self.assertIn(portcafef00d_1, vlan_41.tagged)
            self.assertIn(portcafef00d_2, vlan_40.untagged)
            self.assertIn(portcafef00d_3, vlan_40.untagged)
            self.assertIn(portcafef00d_3, vlan_41.tagged)
            self.assertIn(portcafef00d_4, vlan_41.untagged)
            self.assertIn(portcafef00d_5, vlan_41.untagged)
            # check that the ports are not in vlans they should not be
            self.assertNotIn(portcafef00d_1, vlan_40.untagged)
            self.assertNotIn(portcafef00d_1, vlan_41.untagged)
            self.assertNotIn(portcafef00d_2, vlan_40.tagged)
            self.assertNotIn(portcafef00d_2, vlan_41.untagged)
            self.assertNotIn(portcafef00d_2, vlan_41.tagged)
            self.assertNotIn(portcafef00d_3, vlan_40.tagged)
            self.assertNotIn(portcafef00d_3, vlan_41.untagged)
            self.assertNotIn(portcafef00d_4, vlan_40.untagged)
            self.assertNotIn(portcafef00d_4, vlan_40.tagged)
            self.assertNotIn(portcafef00d_4, vlan_41.tagged)
            self.assertNotIn(portcafef00d_5, vlan_40.untagged)
            self.assertNotIn(portcafef00d_5, vlan_40.tagged)
            self.assertNotIn(portcafef00d_5, vlan_41.tagged)
            # check get_native_vlan
            self.assertEquals(dp.get_native_vlan(1), None)
            self.assertEquals(dp.get_native_vlan(2), vlan_40)
            self.assertEquals(dp.get_native_vlan(3), vlan_40)
            self.assertEquals(dp.get_native_vlan(4), vlan_41)
            self.assertEquals(dp.get_native_vlan(5), vlan_41)
            self.assertEquals(dp.get_native_vlan(6), None)

    def test_only_one_untagged_vlan_per_port(self):
        for dp in (self.v2_dp,):
            untaggedports = set()
            for vlan in dp.vlans.values():
                for port in vlan.untagged:
                    self.assertNotIn(port.number, untaggedports)
                    untaggedports.add(port.number)

    def test_permanent_learn(self):
        for dp in (self.v2_dp,):
            for port in dp.ports.itervalues():
                if port.number != 5:
                    self.assertFalse(port.permanent_learn)
                else:
                    self.assertTrue(port.permanent_learn)

    def test_max_hosts(self):
        for dp in (self.v2_dp,):
            self.assertEqual(20, dp.vlans[40].max_hosts)
            self.assertEqual(255, dp.vlans[41].max_hosts)

    def test_mirror(self):
        for dp in (self.v2_dp,):
            self.assertEqual(dp.ports[6].mirror, 1)

    def test_unicast_flood(self):
        for dp in (self.v2_dp,):
            self.assertFalse(dp.vlans[40].unicast_flood)
            self.assertTrue(dp.vlans[41].unicast_flood)

    def test_routing(self):
        for dp in (self.v2_dp,):
            vlan = dp.vlans[41]
            self.assertIn(
                ipaddress.ip_interface(u'10.0.0.253/24'),
                vlan.faucet_vips
                )
            self.assertEquals(vlan.bgp_port, 9179)
            self.assertEquals(vlan.bgp_as, 1)
            self.assertEquals(vlan.bgp_routerid, '1.1.1.1')
            self.assertIn('127.0.0.1', vlan.bgp_neighbor_addresses)
            self.assertEquals(vlan.bgp_neighbor_as, 2)
            self.assertIn(
                ipaddress.ip_network(u'10.0.1.0/24'),
                vlan.routes_by_ipv(4)
                )
            self.assertIn(
                ipaddress.ip_network(u'10.0.2.0/24'),
                vlan.routes_by_ipv(4)
                )
            self.assertIn(
                ipaddress.ip_network(u'10.0.3.0/24'),
                vlan.routes_by_ipv(4)
                )

    def test_port_acl(self):
        for dp in (self.v2_dp,):
            self.assertIn(1, dp.port_acl_in)
            self.assertIn(dp.ports[1].acl_in, dp.acls)
            self.assertEquals(
                dp.acls[dp.ports[1].acl_in].rules[0]['nw_dst'],
                '172.0.0.0/8')

    def test_vlan_acl(self):
        for dp in (self.v2_dp,):
            self.assertIn(41, dp.vlan_acl_in)
            self.assertIn(dp.vlans[41].acl_in, dp.acls)
            self.assertEquals(
                dp.acls[dp.vlans[41].acl_in].rules[0]['nw_dst'],
                '172.0.0.0/8')

    def test_gauge_port_stats(self):
        for watcher in self.v2_watchers:
            if watcher.type == 'port_stats':
                wv2 = watcher
        self.assertEqual(wv2.db_type, 'influx')
        self.assertEqual(wv2.interval, 40)
        self.assertEqual(wv2.influx_db, 'faucet')
        self.assertEqual(wv2.influx_host, 'localhost')
        self.assertEqual(wv2.influx_port, 8086)
        self.assertEqual(wv2.influx_user, 'kit')
        self.assertEqual(wv2.influx_pwd, 'password')
        self.assertEqual(wv2.influx_timeout, 10)

    def test_gauge_port_state(self):
        for watcher in self.v2_watchers:
            if watcher.type == 'port_state':
                wv2 = watcher
        self.assertEqual(wv2.db_type, 'influx')
        self.assertEqual(wv2.influx_db, 'faucet')
        self.assertEqual(wv2.influx_host, 'localhost')
        self.assertEqual(wv2.influx_port, 8086)
        self.assertEqual(wv2.influx_user, 'kit')
        self.assertEqual(wv2.influx_pwd, 'password')
        self.assertEqual(wv2.influx_timeout, 10)

    def test_gauge_flow_table(self):
        for watcher in self.v2_watchers:
            if watcher.type != 'flow_table':
                continue
            self.assertEqual(watcher.db_type, 'text')
            self.assertEqual(watcher.interval, 40)
            self.assertEqual(watcher.file, 'flow_table.JSON')

if __name__ == "__main__":
    unittest.main()
