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
        self.dps = DP.parser('config/testconfig.yaml')

    def test_dps(self):
        # confirm that DPIDs match
        self.assertEqual(self.dps[0].dp_id, 0xcafef00d)
        self.assertEqual(self.dps[1].dp_id, 0xcafebeef)

    def test_port_numbers(self):
        for dp in self.dps:
            # check the port numbers line up
            self.assertEqual(set(dp.ports.keys()), set([1, 2, 3, 4, 5]))

    def test_ports_vlans(self):
        for dp in self.dps:
            # load ports for easy reading
            port_1 = dp.ports[1]
            port_2 = dp.ports[2]
            port_3 = dp.ports[3]
            port_4 = dp.ports[4]
            port_5 = dp.ports[5]
            # check that the ports are in the right vlans
            self.assertIn(port_1, dp.vlans[40].tagged)
            self.assertIn(port_1, dp.vlans[41].tagged)
            self.assertIn(port_2, dp.vlans[40].untagged)
            self.assertIn(port_3, dp.vlans[40].untagged)
            self.assertIn(port_3, dp.vlans[41].tagged)
            self.assertIn(port_4, dp.vlans[41].untagged)
            self.assertIn(port_5, dp.vlans[41].untagged)
            # check that the ports are not in vlans they should not be
            self.assertNotIn(port_1, dp.vlans[40].untagged)
            self.assertNotIn(port_1, dp.vlans[41].untagged)
            self.assertNotIn(port_2, dp.vlans[40].tagged)
            self.assertNotIn(port_2, dp.vlans[41].untagged)
            self.assertNotIn(port_2, dp.vlans[41].tagged)
            self.assertNotIn(port_3, dp.vlans[40].tagged)
            self.assertNotIn(port_3, dp.vlans[41].untagged)
            self.assertNotIn(port_4, dp.vlans[40].untagged)
            self.assertNotIn(port_4, dp.vlans[40].tagged)
            self.assertNotIn(port_4, dp.vlans[41].tagged)
            self.assertNotIn(port_5, dp.vlans[40].untagged)
            self.assertNotIn(port_5, dp.vlans[40].tagged)
            self.assertNotIn(port_5, dp.vlans[41].tagged)

    def test_only_one_untagged_vlan_per_port(self):
        for dp in self.dps:
            untaggedports = set()
            for vlan in dp.vlans.values():
                for port in vlan.untagged:
                    self.assertNotIn(port.number, untaggedports)
                    untaggedports.add(port.number)

if __name__ == "__main__":
    unittest.main()

