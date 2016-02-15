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

import sys, os
testdir = os.path.dirname(__file__)
srcdir = '../src/ryu_faucet/org/onfsdn/faucet'
sys.path.insert(0, os.path.abspath(os.path.join(testdir, srcdir)))

import unittest
from dp import DP

class DistConfigTestCase(unittest.TestCase):
    def setUp(self):
        self.dp = DP.parser('config/testconfig.yaml')

    def test_dps(self):
        # confirm that DPIDs match
        self.assertEqual(self.dp.dp_id, 0xcafef00d)

    def test_port_numbers(self):
        # check the port numbers line up
        self.assertEqual(set(self.dp.ports.keys()), set([1, 2, 3, 4, 5]))

    def test_ports_vlans(self):
        # load ports for easy reading
        portcafef00d_1 = self.dp.ports[1]
        portcafef00d_2 = self.dp.ports[2]
        portcafef00d_3 = self.dp.ports[3]
        portcafef00d_4 = self.dp.ports[4]
        portcafef00d_5 = self.dp.ports[5]
        # check that the ports are in the right vlans
        self.assertIn(portcafef00d_1, self.dp.vlans[40].tagged)
        self.assertIn(portcafef00d_1, self.dp.vlans[41].tagged)
        self.assertIn(portcafef00d_2, self.dp.vlans[40].untagged)
        self.assertIn(portcafef00d_3, self.dp.vlans[40].untagged)
        self.assertIn(portcafef00d_3, self.dp.vlans[41].tagged)
        self.assertIn(portcafef00d_4, self.dp.vlans[41].untagged)
        self.assertIn(portcafef00d_5, self.dp.vlans[41].untagged)
        # check that the ports are not in vlans they should not be
        self.assertNotIn(portcafef00d_1, self.dp.vlans[40].untagged)
        self.assertNotIn(portcafef00d_1, self.dp.vlans[41].untagged)
        self.assertNotIn(portcafef00d_2, self.dp.vlans[40].tagged)
        self.assertNotIn(portcafef00d_2, self.dp.vlans[41].untagged)
        self.assertNotIn(portcafef00d_2, self.dp.vlans[41].tagged)
        self.assertNotIn(portcafef00d_3, self.dp.vlans[40].tagged)
        self.assertNotIn(portcafef00d_3, self.dp.vlans[41].untagged)
        self.assertNotIn(portcafef00d_4, self.dp.vlans[40].untagged)
        self.assertNotIn(portcafef00d_4, self.dp.vlans[40].tagged)
        self.assertNotIn(portcafef00d_4, self.dp.vlans[41].tagged)
        self.assertNotIn(portcafef00d_5, self.dp.vlans[40].untagged)
        self.assertNotIn(portcafef00d_5, self.dp.vlans[40].tagged)
        self.assertNotIn(portcafef00d_5, self.dp.vlans[41].tagged)

    def test_only_one_untagged_vlan_per_port(self):
        untaggedports = set()
        for vlan in self.dp.vlans.values():
            for port in vlan.untagged:
                self.assertNotIn(port.number, untaggedports)
                untaggedports.add(port.number)

if __name__ == "__main__":
    unittest.main()

