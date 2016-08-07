#!/usr/bin/python

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
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

import sys
import os
import ipaddr

testdir = os.path.dirname(__file__)
srcdir = '../src/ryu_faucet/org/onfsdn/faucet'
sys.path.insert(0, os.path.abspath(os.path.join(testdir, srcdir)))

import unittest
from config_parser import dp_parser, watcher_parser

class DistConfigTestCase(unittest.TestCase):
    def setUp(self):
        self.v1_dp = dp_parser('config/testconfig.yaml', 'test_config')[0]
        self.v2_dp = dp_parser('config/testconfigv2.yaml', 'test_config')[0]
        self.v1_watchers = watcher_parser(
            'config/testgaugeconfig.conf', 'test_config')
        self.v2_watchers = watcher_parser(
            'config/testgaugeconfig.yaml', 'test_config')

    def test_dps(self):
        for dp in (self.v1_dp, self.v2_dp):
            # confirm that DPIDs match
            self.assertEqual(dp.dp_id, 0xcafef00d)

    def test_port_numbers(self):
        for dp in (self.v1_dp, self.v2_dp):
            # check the port numbers line up
            self.assertEqual(set(dp.ports.keys()), set([1, 2, 3, 4, 5, 6]))

    def test_ports_vlans(self):
        for dp in (self.v1_dp, self.v2_dp):
            # load ports for easy reading
            portcafef00d_1 = dp.ports[1]
            portcafef00d_2 = dp.ports[2]
            portcafef00d_3 = dp.ports[3]
            portcafef00d_4 = dp.ports[4]
            portcafef00d_5 = dp.ports[5]
            # check that the ports are in the right vlans
            self.assertIn(portcafef00d_1, dp.vlans[40].tagged)
            self.assertIn(portcafef00d_1, dp.vlans[41].tagged)
            self.assertIn(portcafef00d_2, dp.vlans[40].untagged)
            self.assertIn(portcafef00d_3, dp.vlans[40].untagged)
            self.assertIn(portcafef00d_3, dp.vlans[41].tagged)
            self.assertIn(portcafef00d_4, dp.vlans[41].untagged)
            self.assertIn(portcafef00d_5, dp.vlans[41].untagged)
            # check that the ports are not in vlans they should not be
            self.assertNotIn(portcafef00d_1, dp.vlans[40].untagged)
            self.assertNotIn(portcafef00d_1, dp.vlans[41].untagged)
            self.assertNotIn(portcafef00d_2, dp.vlans[40].tagged)
            self.assertNotIn(portcafef00d_2, dp.vlans[41].untagged)
            self.assertNotIn(portcafef00d_2, dp.vlans[41].tagged)
            self.assertNotIn(portcafef00d_3, dp.vlans[40].tagged)
            self.assertNotIn(portcafef00d_3, dp.vlans[41].untagged)
            self.assertNotIn(portcafef00d_4, dp.vlans[40].untagged)
            self.assertNotIn(portcafef00d_4, dp.vlans[40].tagged)
            self.assertNotIn(portcafef00d_4, dp.vlans[41].tagged)
            self.assertNotIn(portcafef00d_5, dp.vlans[40].untagged)
            self.assertNotIn(portcafef00d_5, dp.vlans[40].tagged)
            self.assertNotIn(portcafef00d_5, dp.vlans[41].tagged)
            # check get_native_vlan
            self.assertEquals(dp.get_native_vlan(1), None)
            self.assertEquals(dp.get_native_vlan(2), dp.vlans[40])
            self.assertEquals(dp.get_native_vlan(3), dp.vlans[40])
            self.assertEquals(dp.get_native_vlan(4), dp.vlans[41])
            self.assertEquals(dp.get_native_vlan(5), dp.vlans[41])
            self.assertEquals(dp.get_native_vlan(6), None)

    def test_only_one_untagged_vlan_per_port(self):
        for dp in (self.v1_dp, self.v2_dp):
            untaggedports = set()
            for vlan in dp.vlans.values():
                for port in vlan.untagged:
                    self.assertNotIn(port.number, untaggedports)
                    untaggedports.add(port.number)

    def test_permanent_learn(self):
        for dp in (self.v1_dp, self.v2_dp):
            for port in dp.ports.itervalues():
                if port.number != 5:
                    self.assertFalse(port.permanent_learn)
                else:
                    self.assertTrue(port.permanent_learn)

    def test_max_hosts(self):
        for dp in (self.v1_dp, self.v2_dp):
            self.assertEqual(20, dp.vlans[40].max_hosts)
            self.assertEqual(None, dp.vlans[41].max_hosts)

    def test_mirror(self):
        for dp in (self.v1_dp, self.v2_dp):
            self.assertEqual(dp.mirror_from_port[1], 6)
            self.assertEqual(dp.ports[6].mirror, 1)

    def test_unicast_flood(self):
        for dp in (self.v1_dp, self.v2_dp):
            self.assertFalse(dp.vlans[40].unicast_flood)
            self.assertTrue(dp.vlans[41].unicast_flood)

    def test_routing(self):
        for dp in (self.v1_dp, self.v2_dp):
            vlan = dp.vlans[41]
            self.assertIn(
                ipaddr.IPNetwork('10.0.0.253/24'),
                vlan.controller_ips
                )
            self.assertEquals(vlan.bgp_port, 9179)
            self.assertEquals(vlan.bgp_as, 1)
            self.assertEquals(vlan.bgp_routerid, '1.1.1.1')
            self.assertEquals(vlan.bgp_neighbor_address, '127.0.0.1')
            self.assertEquals(vlan.bgp_neighbor_as, 2)
            self.assertIn(
                ipaddr.IPNetwork('10.0.1.0/24'),
                vlan.ipv4_routes
                )
            self.assertIn(
                ipaddr.IPNetwork('10.0.2.0/24'),
                vlan.ipv4_routes
                )
            self.assertIn(
                ipaddr.IPNetwork('10.0.3.0/24'),
                vlan.ipv4_routes
                )

    def test_acl(self):
        for dp in (self.v1_dp, self.v2_dp):
            self.assertIn(1, dp.acl_in)
            self.assertIn(dp.ports[1].acl_in, dp.acls)

    def test_gauge_port_stats(self):
        for watcher in self.v1_watchers:
            if watcher.type == 'port_stats':
                wv1 = watcher
        for watcher in self.v2_watchers:
            if watcher.type == 'port_stats':
                wv2 = watcher
        self.assertEqual(wv1.db_type, 'influx')
        self.assertEqual(wv2.db_type, 'influx')
        self.assertEqual(wv1.interval, 40)
        self.assertEqual(wv2.interval, 40)
        self.assertEqual(wv2.influx_db, 'faucet')
        self.assertEqual(wv2.influx_host, 'localhost')
        self.assertEqual(wv2.influx_port, 8086)
        self.assertEqual(wv2.influx_user, 'kit')
        self.assertEqual(wv2.influx_pwd, 'password')
        self.assertEqual(wv2.influx_timeout, 10)

    def test_gauge_port_state(self):
        for watcher in self.v1_watchers:
            if watcher.type == 'port_state':
                wv1 = watcher
        for watcher in self.v2_watchers:
            if watcher.type == 'port_state':
                wv2 = watcher
        self.assertEqual(wv1.db_type, 'influx')
        self.assertEqual(wv2.db_type, 'influx')
        self.assertEqual(wv2.influx_db, 'faucet')
        self.assertEqual(wv2.influx_host, 'localhost')
        self.assertEqual(wv2.influx_port, 8086)
        self.assertEqual(wv2.influx_user, 'kit')
        self.assertEqual(wv2.influx_pwd, 'password')
        self.assertEqual(wv2.influx_timeout, 10)

    def test_gauge_flow_table(self):
        for watcher in self.v1_watchers + self.v2_watchers:
            if watcher.type != 'flow_table':
                continue
            self.assertEqual(watcher.db_type, 'text')
            self.assertEqual(watcher.interval, 40)
            self.assertEqual(watcher.file, 'flow_table.JSON')

if __name__ == "__main__":
    unittest.main()
