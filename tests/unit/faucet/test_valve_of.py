#!/usr/bin/env python3

"""Test FAUCET valve_of."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
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

import unittest

from faucet import valve_of


class ValveOfTestCase(unittest.TestCase):  # pytype: disable=module-attr
    """Test valve_of functions."""

    def test_reorder_dupe(self):
        """Test simple reordering discards duplicate."""
        flow = valve_of.output_port(1)
        flows = [flow, flow, flow]
        reordered = valve_of.valve_flowreorder(flows, use_barriers=False)
        self.assertEqual(1, len(reordered))

    def test_delete_order(self):
        """Test delete ordering/deupdlication."""
        global_groupdel = valve_of.groupdel(group_id=valve_of.ofp.OFPG_ALL)
        global_flowdel = valve_of.flowmod(
            cookie=None, hard_timeout=None, idle_timeout=None, match_fields=None, out_port=None,
            table_id=valve_of.ofp.OFPTT_ALL, inst=(), priority=0, command=valve_of.ofp.OFPFC_DELETE,
            out_group=valve_of.ofp.OFPG_ANY)
        flowdel = valve_of.flowmod(
            cookie=None, hard_timeout=None, idle_timeout=None, match_fields=None, out_port=None,
            table_id=9, inst=(), priority=0, command=valve_of.ofp.OFPFC_DELETE,
            out_group=valve_of.ofp.OFPG_ANY)
        flow = valve_of.output_port(1)
        flows = [flowdel, flow, flow, flow, global_flowdel, global_groupdel]
        reordered = valve_of.valve_flowreorder(flows, use_barriers=True)
        reordered_str = [str(r) for r in reordered]
        # global deletes come first
        self.assertTrue(valve_of.is_global_groupdel(reordered[0]), msg=reordered)
        self.assertTrue(valve_of.is_global_flowdel(reordered[1]), msg=reordered)
        # with a berrier
        self.assertEqual(str(valve_of.barrier()), str(reordered[2]), msg=reordered)
        # without the individual delete
        self.assertTrue(str(flowdel) not in reordered_str, msg=reordered)
        # with regular flow last
        self.assertEqual(str(flow), reordered_str[-1], msg=reordered)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
