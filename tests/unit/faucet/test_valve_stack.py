#!/usr/bin/env python

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve_stack.py."""

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

from functools import partial
import unittest
import ipaddress
import yaml

from ryu.lib import mac
from ryu.ofproto import ofproto_v1_3 as ofp

from faucet import valves_manager
from faucet import valve_of
from faucet.port import (
    STACK_STATE_INIT, STACK_STATE_UP,
    LACP_PORT_SELECTED, LACP_PORT_UNSELECTED)

from fakeoftable import CONTROLLER_PORT

from valve_test_lib import (
    BASE_DP1_CONFIG, CONFIG, STACK_CONFIG, STACK_LOOP_CONFIG, ValveTestBases)


class ValveStackMCLAGTestCase(ValveTestBases.ValveTestSmall):
    """Test stacked MCLAG"""

    CONFIG = """
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
                native_vlan: 100
            3:
                description: p3
                native_vlan: 100
                lacp: 1
            4:
                description: p4
                native_vlan: 100
                lacp: 1
    s2:
        hardware: 'GenericTFM'
        dp_id: 0x2
        interfaces:
            1:
                description: p1
                stack:
                    dp: s1
                    port: 1
            2:
                description: p2
                native_vlan: 100
            3:
                description: p3
                native_vlan: 100
                lacp: 1
            4:
                description: p4
                native_vlan: 100
                lacp: 1
""" % BASE_DP1_CONFIG

    def setUp(self):
        """Setup basic loop config"""
        self.setup_valve(self.CONFIG)

    def get_other_valves(self, valve):
        """Return other running valves"""
        return self.valves_manager._other_running_valves(valve)  # pylint: disable=protected-access

    def test_dpid_nominations(self):
        """Test dpids are nominated correctly"""
        self.activate_all_ports()
        lacp_ports = {}
        for valve in self.valves_manager.valves.values():
            for port in valve.dp.ports.values():
                if port.lacp:
                    lacp_ports.setdefault(valve.dp.dp_id, [])
                    lacp_ports[valve.dp.dp_id].append(port)
                    port.actor_up()
        valve = self.valves_manager.valves[0x1]
        other_valves = self.get_other_valves(valve)
        # Equal number of LAG ports, choose root DP
        nominated_dpid = valve.get_lacp_dpid_nomination(1, other_valves)[0]
        self.assertEqual(
            nominated_dpid, 0x1,
            'Expected nominated DPID %s but found %s' % (0x1, nominated_dpid))
        # Choose DP with most UP LAG ports
        lacp_ports[0x1][0].actor_nosync()
        nominated_dpid = valve.get_lacp_dpid_nomination(1, other_valves)[0]
        self.assertEqual(
            nominated_dpid, 0x2,
            'Expected nominated DPID %s but found %s' % (0x2, nominated_dpid))

    def test_no_dpid_nominations(self):
        """Test dpid nomination doesn't nominate when no LACP ports are up"""
        self.activate_all_ports()
        valve = self.valves_manager.valves[0x1]
        other_valves = self.get_other_valves(valve)
        # No actors UP so should return None
        nominated_dpid = valve.get_lacp_dpid_nomination(1, other_valves)[0]
        self.assertEqual(
            nominated_dpid, None,
            'Did not expect to nominate DPID %s' % nominated_dpid)
        # No other valves so should return None
        for valve in self.valves_manager.valves.values():
            for port in valve.dp.ports.values():
                if port.lacp:
                    port.actor_up()
        nominated_dpid = valve.get_lacp_dpid_nomination(1, None)[0]
        self.assertEqual(
            nominated_dpid, None,
            'Did not expect to nominate DPID %s' % nominated_dpid)

    def test_nominated_dpid_port_selection(self):
        """Test a nominated port selection state is changed"""
        self.activate_all_ports()
        lacp_ports = {}
        for valve in self.valves_manager.valves.values():
            for port in valve.dp.ports.values():
                if port.lacp:
                    lacp_ports.setdefault(valve, [])
                    lacp_ports[valve].append(port)
                    port.actor_up()
        for valve, ports in lacp_ports.items():
            other_valves = self.get_other_valves(valve)
            for port in ports:
                self.assertTrue(
                    valve.lacp_update_port_selection_state(port, other_valves),
                    'Port selection state not updated')
                if valve.dp.dp_id == 0x1:
                    self.assertEqual(
                        port.lacp_port_state(), LACP_PORT_SELECTED,
                        'Expected LACP port %s DP %s to be SELECTED' % (port, valve))
                else:
                    self.assertEqual(
                        port.lacp_port_state(), LACP_PORT_UNSELECTED,
                        'Expected LACP port %s DP %s to be UNSELECTED' % (port, valve))

    def test_lag_flood(self):
        """Test flooding is allowed for UP & SELECTED LAG links only"""
        self.activate_all_ports()
        main_valve = self.valves_manager.valves[0x1]
        main_other_valves = self.get_other_valves(main_valve)
        # Start with all LAG links INIT & UNSELECTED
        self.validate_flood(2, 0, 3, False, 'Flooded out UNSELECTED & INIT LAG port')
        self.validate_flood(2, 0, 4, False, 'Flooded out UNSELECTED & INIT LAG port')
        # Set UP & SELECTED one s1 LAG link
        port3 = main_valve.dp.ports[3]
        port4 = main_valve.dp.ports[4]
        self.apply_ofmsgs(main_valve.lacp_update(port4, True, 1, 1, main_other_valves))
        self.apply_ofmsgs(main_valve.lacp_update(port3, False, 1, 1, main_other_valves))
        self.validate_flood(2, 0, 3, False, 'Flooded out NOSYNC LAG port')
        self.validate_flood(2, 0, 4, True, 'Did not flood out SELECTED LAG port')
        # Set UP & SELECTED s2 LAG links
        valve = self.valves_manager.valves[0x2]
        other_valves = self.get_other_valves(valve)
        for port in valve.dp.ports.values():
            if port.lacp:
                valve.lacp_update(port, True, 1, 1, other_valves)
        self.apply_ofmsgs(main_valve.lacp_update(port4, True, 1, 1, main_other_valves))
        self.apply_ofmsgs(main_valve.lacp_update(port3, False, 1, 1, main_other_valves))
        self.validate_flood(2, 0, 3, False, 'Flooded out UNSELECTED & NOSYNC LAG port')
        self.validate_flood(2, 0, 4, False, 'Flooded out UNSELECTED LAG port')
        # Set UP & SELECTED both s1 LAG links
        self.apply_ofmsgs(main_valve.lacp_update(port3, True, 1, 1, main_other_valves))
        self.apply_ofmsgs(main_valve.lacp_update(port4, True, 1, 1, main_other_valves))
        self.validate_flood(2, 0, 3, True, 'Did not flood out SELECTED LAG port')
        self.validate_flood(2, 0, 4, False, 'Flooded out multiple LAG ports')

    def test_lag_pipeline_accept(self):
        """Test packets entering through UP & SELECTED LAG links"""
        self.activate_all_ports()
        main_valve = self.valves_manager.valves[0x1]
        main_other_valves = self.get_other_valves(main_valve)
        # Packet initially rejected
        self.validate_flood(
            3, 0, None, False, 'Packet incoming through UNSELECTED & INIT port was accepted')
        self.validate_flood(
            4, 0, None, False, 'Packet incoming through UNSELECTED & INIT port was accepted')
        # Set one s1 LAG port 4 to SELECTED & UP
        port3 = main_valve.dp.ports[3]
        port4 = main_valve.dp.ports[4]
        self.apply_ofmsgs(main_valve.lacp_update(port4, True, 1, 1, main_other_valves))
        self.apply_ofmsgs(main_valve.lacp_update(port3, False, 1, 1, main_other_valves))
        self.validate_flood(
            3, 0, None, False, 'Packet incoming through NOSYNC port was accepted')
        self.validate_flood(
            4, 0, None, True, 'Packet incoming through SELECTED port was not accepted')
        # Set UP & SELECTED s2 LAG links, set one s1 port down
        valve = self.valves_manager.valves[0x2]
        other_valves = self.get_other_valves(valve)
        for port in valve.dp.ports.values():
            if port.lacp:
                valve.lacp_update(port, True, 1, 1, other_valves)
        self.apply_ofmsgs(main_valve.lacp_update(port4, True, 1, 1, main_other_valves))
        self.apply_ofmsgs(main_valve.lacp_update(port3, False, 1, 1, main_other_valves))
        self.validate_flood(
            3, 0, None, False, 'Packet incoming through UNSELECTED & NOSYNC port was accepted')
        self.validate_flood(
            4, 0, None, False, 'Packet incoming through UNSELECTED port was accepted')
        # Set UP & SELECTED both s1 LAG links
        self.apply_ofmsgs(main_valve.lacp_update(port3, True, 1, 1, main_other_valves))
        self.apply_ofmsgs(main_valve.lacp_update(port4, True, 1, 1, main_other_valves))
        self.validate_flood(
            3, 0, None, True, 'Packet incoming through SELECTED port was not accepted')
        self.validate_flood(
            4, 0, None, True, 'Packet incoming through SELECTED port was not accepted')


class ValveStackMCLAGRestartTestCase(ValveTestBases.ValveTestSmall):
    """Test stacked MCLAG"""

    CONFIG = """
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
                native_vlan: 100
            3:
                description: p3
                native_vlan: 100
                lacp: 1
            4:
                description: p4
                native_vlan: 100
                lacp: 1
    s2:
        hardware: 'GenericTFM'
        dp_id: 0x2
        interfaces:
            1:
                description: p1
                stack:
                    dp: s1
                    port: 1
            2:
                description: p2
                native_vlan: 100
            3:
                description: p3
                native_vlan: 100
                lacp: 1
            4:
                description: p4
                native_vlan: 100
                lacp: 1
""" % BASE_DP1_CONFIG

    def setUp(self):
        """Setup basic loop config"""
        self.setup_valve(self.CONFIG)

    def get_other_valves(self, valve):
        """Return other running valves"""
        return self.valves_manager._other_running_valves(valve)  # pylint: disable=protected-access

    def test_MCLAG_cold_start(self):
        """Test cold-starting a switch with a downed port resets LACP states"""
        self.activate_all_ports()
        valve = self.valves_manager.valves[0x1]
        other_valves = self.get_other_valves(valve)
        port = valve.dp.ports[3]
        # Make sure LACP state has been updated
        self.assertTrue(valve.lacp_update(port, True, 1, 1, other_valves), 'No OFMSGS returned')
        self.assertTrue(port.is_actor_up(), 'Actor not UP')
        # Set port DOWN
        valve.port_delete(3, other_valves=other_valves)
        self.assertTrue(port.is_actor_none(), 'Actor not NONE')
        # Restart switch & LACP port
        self.cold_start()
        self.assertTrue(valve.port_add(3), 'No OFMSGS returned')
        # Successfully restart LACP from downed
        self.assertTrue(valve.lacp_update(port, True, 1, 1, other_valves), 'No OFMSGS returned')
        self.assertTrue(port.is_actor_up(), 'Actor not UP')


class ValveStackRootExtLoopProtectTestCase(ValveTestBases.ValveTestSmall):
    """External loop protect test cases"""

    CONFIG = """
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
                native_vlan: 100
            3:
                description: p3
                native_vlan: 100
                loop_protect_external: True
            4:
                description: p4
                native_vlan: 100
                loop_protect_external: True
    s2:
        hardware: 'GenericTFM'
        dp_id: 0x2
        interfaces:
            1:
                description: p1
                stack:
                    dp: s1
                    port: 1
            2:
                description: p2
                native_vlan: 100
            3:
                description: p3
                native_vlan: 100
                loop_protect_external: True
            4:
                description: p4
                native_vlan: 100
                loop_protect_external: True
""" % BASE_DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)
        self.set_stack_port_up(1)

    def test_loop_protect(self):
        """test basic loop protection"""
        mcast_match = {
            'in_port': 2,
            'eth_dst': mac.BROADCAST_STR,
            'vlan_vid': 0,
            'eth_type': 0x800,
            'ipv4_dst': '224.0.0.5',
        }
        self.assertTrue(
            self.table.is_output(mcast_match, port=1),
            msg='mcast packet not flooded to non-root stack')
        self.assertTrue(
            self.table.is_output(mcast_match, port=3),
            msg='mcast packet not flooded locally on root')
        self.assertFalse(
            self.table.is_output(mcast_match, port=4),
            msg='mcast packet multiply flooded externally on root')


class ValveStackChainTest(ValveTestBases.ValveTestSmall):
    """Test base class for loop stack config"""

    CONFIG = STACK_CONFIG
    DP = 's2'
    DP_ID = 2

    def setUp(self):
        """Setup basic loop config"""
        self.setup_valve(self.CONFIG)

    def learn_stack_hosts(self):
        """Learn some hosts."""
        for _ in range(2):
            self.rcv_packet(3, 0, self.pkt_match(1, 2), dp_id=1)
            self.rcv_packet(1, 0, self.pkt_match(1, 2), dp_id=2)
            self.rcv_packet(4, 0, self.pkt_match(2, 1), dp_id=2)
            self.rcv_packet(1, 0, self.pkt_match(2, 1), dp_id=1)
            self.rcv_packet(1, 0, self.pkt_match(3, 2), dp_id=3)
            self.rcv_packet(3, 0, self.pkt_match(3, 2), dp_id=2)

    def _unicast_to(self, out_port, trace=False):
        ucast_match = {
            'in_port': 4,
            'eth_src': self.P2_V100_MAC,
            'eth_dst': self.P1_V100_MAC,
            'vlan_vid': 0,
            'eth_type': 0x800,
        }
        return self.table.is_output(ucast_match, port=out_port, trace=trace)

    def _learning_from_bcast(self, in_port):
        ucast_match = {
            'in_port': in_port,
            'eth_src': self.P1_V100_MAC,
            'eth_dst': self.BROADCAST_MAC,
            'vlan_vid': self.V100,
            'eth_type': 0x800,
        }
        return self.table.is_output(ucast_match, port=CONTROLLER_PORT)

    def validate_edge_learn_ports(self):
        """Validate the switch behavior before learning, and then learn hosts"""

        # Before learning, unicast should flood to stack root and packet-in.
        self.assertFalse(self._unicast_to(1), 'unlearned unicast to stack root')
        self.assertFalse(self._unicast_to(2), 'unlearned unicast to stack root')
        self.assertTrue(self._unicast_to(3), 'unlearned unicast away from stack root')
        self.assertTrue(self._unicast_to(CONTROLLER_PORT), 'unlearned unicast learn')
        self.assertFalse(self._learning_from_bcast(1), 'learn from stack root broadcast')
        self.assertFalse(self._learning_from_bcast(4), 'learn from access port broadcast')

        self.learn_stack_hosts()

        self.assertFalse(self._unicast_to(1), 'learned unicast to stack root')
        self.assertFalse(self._unicast_to(2), 'learned unicast to stack root')
        self.assertTrue(self._unicast_to(3), 'learned unicast away from stack root')
        self.assertFalse(self._unicast_to(CONTROLLER_PORT), 'no learn from unicast')
        self.assertFalse(self._learning_from_bcast(1), 'learn from stack root broadcast')
        self.assertFalse(self._learning_from_bcast(4), 'learn from access port broadcast')

    def test_stack_learn_edge(self):
        """Test stack learned edge"""
        self.activate_all_ports()
        self.validate_edge_learn_ports()

    def test_stack_learn_root(self):
        """Test stack learned root"""
        self.update_config(self._config_edge_learn_stack_root(True))
        self.activate_all_ports()
        self.validate_edge_learn_ports()


class ValveStackLoopTest(ValveTestBases.ValveTestSmall):
    """Test base class for loop stack config"""

    CONFIG = STACK_LOOP_CONFIG

    def setUp(self):
        """Setup basic loop config"""
        self.setup_valve(self.CONFIG)

    def validate_flooding(self, rerouted=False, portup=True):
        """Validate the flooding state of the stack"""
        vid = self.V100
        self.validate_flood(1, vid, 1, False, 'flooded out input stack port')
        self.validate_flood(1, vid, 2, portup, 'not flooded to stack root')
        self.validate_flood(1, vid, 3, portup, 'not flooded to external host')
        self.validate_flood(2, vid, 1, rerouted, 'flooded out other stack port')
        self.validate_flood(2, vid, 2, False, 'flooded out input stack port')
        self.validate_flood(2, vid, 3, True, 'not flooded to external host')
        vid = 0
        self.validate_flood(3, vid, 1, rerouted, 'flooded out inactive port')
        self.validate_flood(3, vid, 2, True, 'not flooded to stack root')
        self.validate_flood(3, vid, 3, False, 'flooded out hairpin')

    def learn_stack_hosts(self):
        """Learn some hosts."""
        for _ in range(2):
            self.rcv_packet(3, 0, self.pkt_match(1, 2), dp_id=1)
            self.rcv_packet(2, 0, self.pkt_match(1, 2), dp_id=2)
            self.rcv_packet(3, 0, self.pkt_match(2, 1), dp_id=2)
            self.rcv_packet(2, 0, self.pkt_match(2, 1), dp_id=1)


class ValveStackEdgeLearnTestCase(ValveStackLoopTest):
    """Edge learning test cases"""

    def _unicast_to(self, out_port):
        ucast_match = {
            'in_port': 3,
            'eth_src': self.P1_V100_MAC,
            'eth_dst': self.P2_V100_MAC,
            'vlan_vid': 0,
            'eth_type': 0x800,
        }
        return self.table.is_output(ucast_match, port=out_port)

    def _learning_from_bcast(self, in_port):
        bcast_match = {
            'in_port': in_port,
            'eth_src': self.P2_V100_MAC,
            'eth_dst': self.BROADCAST_MAC,
            'vlan_vid': self.V100,
            'eth_type': 0x800,
        }
        return self.table.is_output(bcast_match, port=CONTROLLER_PORT)

    def validate_edge_learn_ports(self):
        """Validate the switch behavior before learning, and then learn hosts"""

        # Before learning, unicast should flood to stack root and packet-in.
        self.assertFalse(self._unicast_to(1), 'unicast direct to edge')
        self.assertTrue(self._unicast_to(2), 'unicast to stack root')
        self.assertTrue(self._unicast_to(CONTROLLER_PORT), 'learn from unicast')

        self.assertTrue(self._learning_from_bcast(2), 'learn from stack root broadcast')

        self.learn_stack_hosts()

        self.assertFalse(self._unicast_to(CONTROLLER_PORT), 'learn from unicast')

    def test_edge_learn_edge_port(self):
        """Check the behavior of the basic edge_learn_port algorithm"""

        self.activate_all_ports()

        self.validate_edge_learn_ports()

        # After learning, unicast should go direct to edge switch.
        self.assertTrue(self._unicast_to(1), 'unicast direct to edge')
        self.assertFalse(self._unicast_to(2), 'unicast to stack root')

        # TODO: This should be False to prevent unnecessary packet-ins.
        self.assertTrue(self._learning_from_bcast(2), 'learn from stack root broadcast')

    def test_edge_learn_stack_root(self):
        """Check the behavior of learning always towards stack root"""

        self.update_config(self._config_edge_learn_stack_root(True))

        self.activate_all_ports()

        self.validate_edge_learn_ports()

        # After learning, unicast should go to stack root, and no more learning from root.
        self.assertFalse(self._unicast_to(1), 'unicast direct to edge')
        self.assertTrue(self._unicast_to(2), 'unicast to stack root')
        self.assertFalse(self._learning_from_bcast(2), 'learn from stack root broadcast')


class ValveStackRedundantLink(ValveStackLoopTest):
    """Check stack situations with a redundant link"""

    def test_loop_protect(self):
        """Basic loop protection check"""
        self.activate_all_ports()
        mcast_match = {
            'in_port': 3,
            'eth_dst': mac.BROADCAST_STR,
            'vlan_vid': 0,
            'eth_type': 0x800,
            'ipv4_dst': '224.0.0.5',
        }
        self.assertTrue(
            self.table.is_output(mcast_match, port=2),
            msg='mcast packet not flooded to root of stack')
        self.assertFalse(self.valve.dp.ports[2].non_stack_forwarding())
        self.assertFalse(
            self.table.is_output(mcast_match, port=1),
            msg='mcast packet flooded root of stack via not shortest path')
        self.deactivate_stack_port(self.valve.dp.ports[2])
        self.assertFalse(self.valve.dp.ports[2].non_stack_forwarding())
        self.assertFalse(
            self.table.is_output(mcast_match, port=2),
            msg='mcast packet flooded to root of stack via redundant path')
        self.assertFalse(self.valve.dp.ports[2].non_stack_forwarding())
        self.assertTrue(
            self.table.is_output(mcast_match, port=1),
            msg='mcast packet not flooded root of stack')
        self.assertFalse(self.valve.dp.ports[2].non_stack_forwarding())
        self.assertTrue(self.valve.dp.ports[3].non_stack_forwarding())


class ValveStackNonRootExtLoopProtectTestCase(ValveTestBases.ValveTestSmall):
    """Test non-root external loop protect"""

    CONFIG = """
dps:
    s1:
%s
        interfaces:
            1:
                description: p1
                stack:
                    dp: s2
                    port: 1
            2:
                description: p2
                native_vlan: 100
            3:
                description: p3
                native_vlan: 100
                loop_protect_external: True
            4:
                description: p4
                native_vlan: 100
                loop_protect_external: True
    s2:
        hardware: 'GenericTFM'
        dp_id: 0x2
        interfaces:
            1:
                description: p1
                stack:
                    dp: s1
                    port: 1
            2:
                description: p2
                stack:
                    dp: s3
                    port: 1
            3:
                description: p2
                native_vlan: 100
    s3:
        hardware: 'GenericTFM'
        dp_id: 0x3
        stack:
            priority: 1
        interfaces:
            1:
                description: p1
                stack:
                    dp: s2
                    port: 2
            2:
                description: p2
                native_vlan: 100
""" % BASE_DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)
        self.set_stack_port_up(1)

    def test_loop_protect(self):
        """Test expected table outputs for external loop protect"""
        mcast_match = {
            'in_port': 2,
            'eth_dst': mac.BROADCAST_STR,
            'vlan_vid': 0,
            'eth_type': 0x800,
            'ipv4_dst': '224.0.0.5',
        }
        self.assertTrue(
            self.table.is_output(mcast_match, port=1),
            msg='mcast packet not flooded to root of stack')
        self.assertFalse(
            self.table.is_output(mcast_match, port=3),
            msg='mcast packet flooded locally on non-root')
        self.assertFalse(
            self.table.is_output(mcast_match, port=4),
            msg='mcast packet flooded locally on non-root')


class ValveStackAndNonStackTestCase(ValveTestBases.ValveTestSmall):
    """Test stacked switches can exist with non-stacked switches"""

    CONFIG = """
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
                native_vlan: 0x100
    s2:
        hardware: 'GenericTFM'
        dp_id: 0x2
        interfaces:
            1:
                description: p1
                stack:
                    dp: s1
                    port: 1
            2:
                description: p2
                native_vlan: 0x100
    s3:
        hardware: 'GenericTFM'
        dp_id: 0x3
        interfaces:
            1:
                description: p1
                native_vlan: 0x100
            2:
                description: p2
                native_vlan: 0x100
""" % BASE_DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_nonstack_dp_port(self):
        """Test that finding a path from a stack swithc to a non-stack switch cannot happen"""
        self.assertEqual(None, self.valves_manager.valves[0x3].dp.shortest_path_port('s1'))


class ValveStackRedundancyTestCase(ValveTestBases.ValveTestSmall):
    """Valve test for root selection."""

    CONFIG = STACK_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def dp_by_name(self, dp_name):
        """Get DP by DP name"""
        for valve in self.valves_manager.valves.values():
            if valve.dp.name == dp_name:
                return valve.dp
        return None

    def set_stack_all_ports_status(self, dp_name, status):
        """Set all stack ports to status on dp"""
        dp = self.dp_by_name(dp_name)
        for port in dp.stack_ports:
            port.dyn_stack_current_state = status

    def test_redundancy(self):
        """Test redundant stack connections"""
        now = 1
        # All switches are down to start with.
        for dpid in self.valves_manager.valves:
            dp = self.valves_manager.valves[dpid].dp
            dp.dyn_running = False
            self.set_stack_all_ports_status(dp.name, STACK_STATE_INIT)
        for valve in self.valves_manager.valves.values():
            self.assertFalse(valve.dp.dyn_running)
            self.assertEqual('s1', valve.dp.stack_root_name)
            root_hop_port = valve.dp.shortest_path_port('s1')
            root_hop_port = root_hop_port.number if root_hop_port else 0
            self.assertEqual(root_hop_port, self.get_prom('dp_root_hop_port', bare=True))
        # From a cold start - we pick the s1 as root.
        self.assertEqual(None, self.valves_manager.meta_dp_state.stack_root_name)
        self.assertFalse(self.valves_manager.maintain_stack_root(now))
        self.assertEqual('s1', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(1, self.get_prom('faucet_stack_root_dpid', bare=True))
        now += (valves_manager.STACK_ROOT_DOWN_TIME * 2)
        # Time passes, still no change, s1 is still the root.
        self.assertFalse(self.valves_manager.maintain_stack_root(now))
        self.assertEqual('s1', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(1, self.get_prom('faucet_stack_root_dpid', bare=True))
        # s2 has come up, but has all stack ports down and but s1 is still down.
        self.valves_manager.meta_dp_state.dp_last_live_time['s2'] = now
        now += (valves_manager.STACK_ROOT_STATE_UPDATE_TIME * 2)
        # No change because s2 still isn't healthy.
        self.assertFalse(self.valves_manager.maintain_stack_root(now))
        # We expect s2 to be the new root because now it has stack links up.
        self.set_stack_all_ports_status('s2', STACK_STATE_UP)
        now += (valves_manager.STACK_ROOT_STATE_UPDATE_TIME * 2)
        self.valves_manager.meta_dp_state.dp_last_live_time['s2'] = now
        self.assertTrue(self.valves_manager.maintain_stack_root(now))
        self.assertEqual('s2', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(2, self.get_prom('faucet_stack_root_dpid', bare=True))
        # More time passes, s1 is still down, s2 is still the root.
        now += (valves_manager.STACK_ROOT_DOWN_TIME * 2)
        # s2 recently said something, s2 still the root.
        self.valves_manager.meta_dp_state.dp_last_live_time['s2'] = now - 1
        self.set_stack_all_ports_status('s2', STACK_STATE_UP)
        self.assertFalse(self.valves_manager.maintain_stack_root(now))
        self.assertEqual('s2', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(2, self.get_prom('faucet_stack_root_dpid', bare=True))
        # now s1 came up too, but we stay on s2 because it's healthy.
        self.valves_manager.meta_dp_state.dp_last_live_time['s1'] = now + 1
        now += valves_manager.STACK_ROOT_STATE_UPDATE_TIME
        self.assertFalse(self.valves_manager.maintain_stack_root(now))
        self.assertEqual('s2', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(2, self.get_prom('faucet_stack_root_dpid', bare=True))


class ValveRootStackTestCase(ValveTestBases.ValveTestSmall):
    """Test stacking/forwarding."""

    DP = 's3'
    DP_ID = 0x3

    def setUp(self):
        self.setup_valve(CONFIG)
        self.set_stack_port_up(5)

    def test_stack_learn(self):
        """Test host learning on stack root."""
        self.prom_inc(
            partial(self.rcv_packet, 1, 0x300, {
                'eth_src': self.P1_V300_MAC,
                'eth_dst': self.UNKNOWN_MAC,
                'ipv4_src': '10.0.0.1',
                'ipv4_dst': '10.0.0.2'}),
            'vlan_hosts_learned',
            labels={'vlan': str(int(0x300))})

    def test_stack_flood(self):
        """Test packet flooding when stacking."""
        matches = [
            {
                'in_port': 1,
                'vlan_vid': 0,
                'eth_src': self.P1_V300_MAC
            }]
        self.verify_flooding(matches)

    def test_topo(self):
        """Test DP is assigned appropriate edge/root states"""
        dp = self.valves_manager.valves[self.DP_ID].dp
        self.assertTrue(dp.is_stack_root())
        self.assertFalse(dp.is_stack_edge())


class ValveEdgeStackTestCase(ValveTestBases.ValveTestSmall):
    """Test stacking/forwarding."""

    DP = 's4'
    DP_ID = 0x4

    def setUp(self):
        self.setup_valve(CONFIG)
        self.set_stack_port_up(5)

    def test_stack_learn(self):
        """Test host learning on non-root switch."""
        self.rcv_packet(1, 0x300, {
            'eth_src': self.P1_V300_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'ipv4_src': '10.0.0.1',
            'ipv4_dst': '10.0.0.2'})
        self.rcv_packet(5, 0x300, {
            'eth_src': self.P1_V300_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'vid': 0x300,
            'ipv4_src': '10.0.0.1',
            'ipv4_dst': '10.0.0.2'})

    def test_stack_flood(self):
        """Test packet flooding when stacking."""
        matches = [
            {
                'in_port': 1,
                'vlan_vid': 0,
                'eth_src': self.P1_V300_MAC
            }]
        self.verify_flooding(matches)

    def test_no_unexpressed_packetin(self):
        """Test host learning on stack root."""
        unexpressed_vid = 0x666 | ofp.OFPVID_PRESENT
        match = {
            'vlan_vid': unexpressed_vid,
            'eth_dst': self.UNKNOWN_MAC}
        self.assertFalse(
            self.table.is_output(match, port=ofp.OFPP_CONTROLLER, vid=unexpressed_vid))

    def test_topo(self):
        """Test DP is assigned appropriate edge/root states"""
        dp = self.valves_manager.valves[self.DP_ID].dp
        self.assertFalse(dp.is_stack_root())
        self.assertTrue(dp.is_stack_edge())


class ValveStackProbeTestCase(ValveTestBases.ValveTestSmall):
    """Test stack link probing."""

    CONFIG = STACK_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_stack_probe(self):
        """Test probing works correctly."""
        stack_port = self.valve.dp.ports[1]
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[1]
        other_valves = self.valves_manager._other_running_valves(self.valve)  # pylint: disable=protected-access
        self.assertTrue(stack_port.is_stack_none())
        self.valve.fast_state_expire(self.mock_time(), other_valves)
        self.assertTrue(stack_port.is_stack_init())
        for change_func, check_func in [
                ('stack_up', 'is_stack_up')]:
            getattr(other_port, change_func)()
            self.rcv_lldp(stack_port, other_dp, other_port)
            self.assertTrue(getattr(stack_port, check_func)(), msg=change_func)

    def test_stack_miscabling(self):
        """Test probing stack with miscabling."""
        stack_port = self.valve.dp.ports[1]
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[1]
        wrong_port = other_dp.ports[2]
        wrong_dp = self.valves_manager.valves[3].dp
        other_valves = self.valves_manager._other_running_valves(self.valve)  # pylint: disable=protected-access
        self.valve.fast_state_expire(self.mock_time(), other_valves)
        for remote_dp, remote_port in [
                (wrong_dp, other_port),
                (other_dp, wrong_port)]:
            self.rcv_lldp(stack_port, other_dp, other_port)
            self.assertTrue(stack_port.is_stack_up())
            self.rcv_lldp(stack_port, remote_dp, remote_port)
            self.assertTrue(stack_port.is_stack_bad())

    def test_stack_lost_lldp(self):
        """Test stacking when LLDP packets get dropped"""
        stack_port = self.valve.dp.ports[1]
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[1]
        other_valves = self.valves_manager._other_running_valves(self.valve)  # pylint: disable=protected-access
        self.valve.fast_state_expire(self.mock_time(), other_valves)
        self.rcv_lldp(stack_port, other_dp, other_port)
        self.assertTrue(stack_port.is_stack_up())
        # simulate packet loss
        self.valve.fast_state_expire(self.mock_time(300), other_valves)
        self.assertTrue(stack_port.is_stack_gone())
        self.valve.fast_state_expire(self.mock_time(300), other_valves)
        self.rcv_lldp(stack_port, other_dp, other_port)
        self.assertTrue(stack_port.is_stack_up())


class ValveStackGraphUpdateTestCase(ValveTestBases.ValveTestSmall):
    """Valve test for updating the stack graph."""

    CONFIG = STACK_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_update_stack_graph(self):
        """Test stack graph port UP and DOWN updates"""

        def verify_stack_learn_edges(num_edges, edge=None, test_func=None):
            for dpid in (1, 2, 3):
                valve = self.valves_manager.valves[dpid]
                if not valve.dp.stack:
                    continue
                graph = valve.dp.stack['graph']
                self.assertEqual(num_edges, len(graph.edges()))
                if test_func and edge:
                    test_func(edge in graph.edges(keys=True))

        num_edges = 3
        self.all_stack_up()
        verify_stack_learn_edges(num_edges)
        ports = [self.valve.dp.ports[1], self.valve.dp.ports[2]]
        edges = [('s1', 's2', 's1:1-s2:1'), ('s1', 's2', 's1:2-s2:2')]
        for port, edge in zip(ports, edges):
            num_edges -= 1
            self.down_stack_port(port)
            verify_stack_learn_edges(num_edges, edge, self.assertFalse)
        self.up_stack_port(ports[0])
        verify_stack_learn_edges(2, edges[0], self.assertTrue)


class ValveStackGraphBreakTestCase(ValveStackLoopTest):
    """Valve test for updating the stack graph."""

    def test_update_stack_graph(self):
        """Test stack graph port UP and DOWN updates"""

        self.activate_all_ports()
        self.validate_flooding(False)
        self.assertLessEqual(self.table.flow_count(), 33, 'table overflow')
        # Deactivate link between the two other switches, not the one under test.
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[2]
        self.deactivate_stack_port(other_port)
        self.validate_flooding(rerouted=True)

    def _set_max_lldp_lost(self, new_value):
        """Set the interface config option max_lldp_lost"""
        config = yaml.load(self.CONFIG, Loader=yaml.SafeLoader)
        for dp in config['dps'].values():
            for interface in dp['interfaces'].values():
                if 'stack' in interface:
                    interface['max_lldp_lost'] = new_value
        return yaml.dump(config)

    def test_max_lldp_timeout(self):
        """Check that timeout can be increased"""

        port = self.valve.dp.ports[1]

        self.activate_all_ports()
        self.validate_flooding()

        # Deactivating the port stops simulating LLDP beacons.
        self.deactivate_stack_port(port, packets=1)

        # Should still work after only 1 interval (3 required by default)
        self.validate_flooding()

        # Wait for 3 more cycles, so should fail now.
        self.trigger_all_ports(packets=3)

        # Validate expected normal behavior with the port down.
        self.validate_flooding(portup=False)

        # Restore everything and set max_lldp_lost to 100.
        self.activate_stack_port(port)
        self.validate_flooding()
        new_config = self._set_max_lldp_lost(100)
        self.update_config(new_config, reload_expected=False)
        self.activate_all_ports()
        self.validate_flooding()

        # Like above, deactivate the port (stops LLDP beacons).
        self.deactivate_stack_port(port, packets=10)

        # After 10 packets (more than before), it should still work.
        self.validate_flooding()

        # But, after 100 more port should be down b/c limit is set to 100.
        self.trigger_all_ports(packets=100)
        self.validate_flooding(portup=False)


class ValveTestIPV4StackedRouting(ValveTestBases.ValveTestStackedRouting):
    """Test inter-vlan routing with stacking capabilities in an IPV4 network"""

    VLAN100_FAUCET_VIPS = '10.0.1.254'
    VLAN100_FAUCET_VIP_SPACE = '10.0.1.254/24'
    VLAN200_FAUCET_VIPS = '10.0.2.254'
    VLAN200_FAUCET_VIP_SPACE = '10.0.2.254/24'

    def setUp(self):
        self.setup_stack_routing()


class ValveTestIPV4StackedRoutingDPOneVLAN(ValveTestBases.ValveTestStackedRouting):
    """Test stacked intervlan routing when each DP has only one of the routed VLANs"""

    VLAN100_FAUCET_VIPS = '10.0.1.254'
    VLAN100_FAUCET_VIP_SPACE = '10.0.1.254/24'
    VLAN200_FAUCET_VIPS = '10.0.2.254'
    VLAN200_FAUCET_VIP_SPACE = '10.0.2.254/24'
    NUM_PORTS = 64

    def base_config(self):
        """Create the base config"""
        self.V100_HOSTS = [1]
        self.V200_HOSTS = [2]
        return """
    routers:
        router1:
            vlans: [vlan100, vlan200]
    dps:
        s1:
            hardware: 'GenericTFM'
            dp_id: 1
            stack: {priority: 1}
            interfaces:
                1:
                    native_vlan: vlan100
                3:
                    stack: {dp: s2, port: 3}
            interface_ranges:
                4-64:
                    native_vlan: vlan100
        s2:
            dp_id: 2
            interfaces:
                2:
                    native_vlan: vlan200
                3:
                    stack: {dp: s1, port: 3}
    """

    def setUp(self):
        self.setup_stack_routing()


class ValveTestIPV4StackedRoutingPathNoVLANS(ValveTestBases.ValveTestStackedRouting):
    """Test stacked intervlan routing when DP in path contains no routed VLANs"""

    VLAN100_FAUCET_VIPS = '10.0.1.254'
    VLAN100_FAUCET_VIP_SPACE = '10.0.1.254/24'
    VLAN200_FAUCET_VIPS = '10.0.2.254'
    VLAN200_FAUCET_VIP_SPACE = '10.0.2.254/24'

    def create_config(self):
        """Create the config file"""
        self.CONFIG = """
    vlans:
        vlan100:
            vid: 0x100
            faucet_mac: '%s'
            faucet_vips: ['%s']
        vlan200:
            vid: 0x200
            faucet_mac: '%s'
            faucet_vips: ['%s']
        vlan300:
            vid: 0x300
    %s
           """ % (self.VLAN100_FAUCET_MAC, self.VLAN100_FAUCET_VIP_SPACE,
                  self.VLAN200_FAUCET_MAC, self.VLAN200_FAUCET_VIP_SPACE,
                  self.base_config())

    def base_config(self):
        """Create the base config"""
        self.V100_HOSTS = [1]
        self.V200_HOSTS = [3]
        return """
    routers:
        router1:
            vlans: [vlan100, vlan200]
    dps:
        s1:
            hardware: 'GenericTFM'
            dp_id: 1
            stack: {priority: 1}
            interfaces:
                1:
                    native_vlan: vlan100
                3:
                    stack: {dp: s2, port: 3}
        s2:
            dp_id: 2
            interfaces:
                2:
                    native_vlan: vlan300
                3:
                    stack: {dp: s1, port: 3}
                4:
                    stack: {dp: s3, port: 3}
        s3:
            dp_id: 3
            interfaces:
                2:
                    native_vlan: vlan200
                3:
                    stack: {dp: s2, port: 4}
                4:
                    stack: {dp: s4, port: 3}
        s4:
            dp_id: 4
            interfaces:
                2:
                    native_vlan: vlan300
                3:
                    stack: {dp: s3, port: 4}
    """

    def setUp(self):
        self.setup_stack_routing()


class ValveTestIPV6StackedRouting(ValveTestBases.ValveTestStackedRouting):
    """Test inter-vlan routing with stacking capabilities in an IPV6 network"""

    VLAN100_FAUCET_VIPS = 'fc80::1:254'
    VLAN200_FAUCET_VIPS = 'fc80::2:254'
    VLAN100_FAUCET_VIP_SPACE = 'fc80::1:254/64'
    VLAN200_FAUCET_VIP_SPACE = 'fc80::1:254/64'

    def setUp(self):
        self.setup_stack_routing()

    @staticmethod
    def create_ip(vindex, host):
        """Create a IP address string"""
        return 'fc80::%u:%u' % (vindex, host)

    @staticmethod
    def get_eth_type():
        """Returns IPV6 ether type"""
        return valve_of.ether.ETH_TYPE_IPV6

    def create_match(self, vindex, host, faucet_mac, faucet_vip, code):
        """Create an NA message"""
        return {
            'eth_src': self.create_mac(vindex, host),
            'eth_dst': faucet_mac,
            'ipv6_src': self.create_ip(vindex, host),
            'ipv6_dst': faucet_vip,
            'neighbor_advert_ip': self.create_ip(vindex, host)
        }


class ValveInterVLANStackFlood(ValveTestBases.ValveTestSmall):
    """Test that the stack ports get flooded to for interVLAN packets"""

    VLAN100_FAUCET_MAC = '00:00:00:00:00:11'
    VLAN200_FAUCET_MAC = '00:00:00:00:00:22'
    VLAN100_FAUCET_VIPS = '10.1.0.254'
    VLAN100_FAUCET_VIP_SPACE = '10.1.0.254/24'
    VLAN200_FAUCET_VIPS = '10.2.0.254'
    VLAN200_FAUCET_VIP_SPACE = '10.2.0.254/24'
    DST_ADDRESS = ipaddress.IPv4Address('10.1.0.1')

    def base_config(self):
        """Create the base config"""
        return """
routers:
    router1:
        vlans: [vlan100, vlan200]
dps:
    s1:
        hardware: 'GenericTFM'
        dp_id: 1
        interfaces:
            1:
                native_vlan: vlan100
            2:
                native_vlan: vlan200
            3:
                stack: {dp: s2, port: 3}
    s2:
        dp_id: 2
        stack: {priority: 1}
        interfaces:
            1:
                native_vlan: vlan100
            2:
                native_vlan: vlan200
            3:
                stack: {dp: s1, port: 3}
            4:
                stack: {dp: s3, port: 3}
    s3:
        dp_id: 3
        interfaces:
            1:
                native_vlan: vlan100
            2:
                native_vlan: vlan200
            3:
                stack: {dp: s2, port: 4}
            4:
                stack: {dp: s4, port: 3}
    s4:
        dp_id: 4
        interfaces:
            1:
                native_vlan: vlan100
            2:
                native_vlan: vlan200
            3:
                stack: {dp: s3, port: 4}
"""

    def create_config(self):
        """Create the config file"""
        self.CONFIG = """
vlans:
    vlan100:
        vid: 100
        faucet_mac: '%s'
        faucet_vips: ['%s']
    vlan200:
        vid: 200
        faucet_mac: '%s'
        faucet_vips: ['%s']
%s
        """ % (self.VLAN100_FAUCET_MAC, self.VLAN100_FAUCET_VIP_SPACE,
               self.VLAN200_FAUCET_MAC, self.VLAN200_FAUCET_VIP_SPACE,
               self.base_config())

    def setUp(self):
        """Create a stacking config file."""
        self.create_config()
        self.setup_valve(self.CONFIG)
        self.activate_all_ports()
        for valve in self.valves_manager.valves.values():
            for port in valve.dp.ports.values():
                if port.stack:
                    self.set_stack_port_up(port.number, valve)

    def flood_manager_flood_ports(self, flood_manager):
        """Return list of port numbers that will be flooded to"""
        return [port.number for port in flood_manager._stack_flood_ports()]  # pylint: disable=protected-access

    def route_manager_ofmsgs(self, route_manager, vlan):
        """Return ofmsgs for route stack link flooding"""
        faucet_vip = list(vlan.faucet_vips_by_ipv(4))[0].ip
        ofmsgs = route_manager._flood_stack_links(  # pylint: disable=protected-access
            route_manager._gw_resolve_pkt(), vlan, route_manager.multi_out,  # pylint: disable=protected-access
            vlan.faucet_mac, valve_of.mac.BROADCAST_STR,
            faucet_vip, self.DST_ADDRESS)
        return ofmsgs

    def test_flood_towards_root_from_s1(self):
        """Test intervlan flooding goes towards the root"""
        output_ports = [3]
        valve = self.valves_manager.valves[1]
        ports = self.flood_manager_flood_ports(valve.flood_manager)
        self.assertEqual(output_ports, ports, 'InterVLAN flooding does not match expected')
        route_manager = valve._route_manager_by_ipv.get(4, None)
        vlan = valve.dp.vlans[100]
        ofmsgs = self.route_manager_ofmsgs(route_manager, vlan)
        self.assertTrue(self.packet_outs_from_flows(ofmsgs))

    def test_flood_away_from_root(self):
        """Test intervlan flooding goes away from the root"""
        output_ports = [3, 4]
        valve = self.valves_manager.valves[2]
        ports = self.flood_manager_flood_ports(valve.flood_manager)
        self.assertEqual(output_ports, ports, 'InterVLAN flooding does not match expected')
        route_manager = valve._route_manager_by_ipv.get(4, None)
        vlan = valve.dp.vlans[100]
        ofmsgs = self.route_manager_ofmsgs(route_manager, vlan)
        self.assertTrue(self.packet_outs_from_flows(ofmsgs))

    def test_flood_towards_root_from_s3(self):
        """Test intervlan flooding only goes towards the root (s4 will get the reflection)"""
        output_ports = [3]
        valve = self.valves_manager.valves[3]
        ports = self.flood_manager_flood_ports(valve.flood_manager)
        self.assertEqual(output_ports, ports, 'InterVLAN flooding does not match expected')
        route_manager = valve._route_manager_by_ipv.get(4, None)
        vlan = valve.dp.vlans[100]
        ofmsgs = self.route_manager_ofmsgs(route_manager, vlan)
        self.assertTrue(self.packet_outs_from_flows(ofmsgs))

    def test_flood_towards_root_from_s4(self):
        """Test intervlan flooding goes towards the root (through s3)"""
        output_ports = [3]
        valve = self.valves_manager.valves[4]
        ports = self.flood_manager_flood_ports(valve.flood_manager)
        self.assertEqual(output_ports, ports, 'InterVLAN flooding does not match expected')
        route_manager = valve._route_manager_by_ipv.get(4, None)
        vlan = valve.dp.vlans[100]
        ofmsgs = self.route_manager_ofmsgs(route_manager, vlan)
        self.assertTrue(self.packet_outs_from_flows(ofmsgs))


class ValveTestTunnel(ValveTestBases.ValveTestSmall):
    """Test valve tunnel methods"""

    TUNNEL_ID = 200
    CONFIG = """
acls:
    tunnel_acl:
        - rule:
            actions:
                output:
                    tunnel: {type: 'vlan', tunnel_id: %u, dp: s3, port: 1}
vlans:
    vlan100:
        vid: 100
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack:
                    dp: s2
                    port: 2
            3:
                stack:
                    dp: s2
                    port: 3
            4:
                stack:
                    dp: s3
                    port: 2
            5:
                stack:
                    dp: s3
                    port: 3
    s2:
        dp_id: 0x2
        interfaces:
            1:
                native_vlan: vlan100
                acls_in: [tunnel_acl]
            2:
                stack:
                    dp: s1
                    port: 2
            3:
                stack:
                    dp: s1
                    port: 3
    s3:
        dp_id: 0x3
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack:
                    dp: s1
                    port: 4
            3:
                stack:
                    dp: s1
                    port: 5
""" % TUNNEL_ID

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def all_stack_up(self):
        """Force stack ports UP and enabled"""
        for valve in self.valves_manager.valves.values():
            valve.dp.dyn_running = True
            for port in valve.dp.stack_ports:
                port.stack_up()
                port.dyn_finalized = False
                port.enabled = True
                port.dyn_phys_up = True
                port.dyn_finalized = True
                self.assertFalse(port.non_stack_forwarding())

    def down_stack_port(self, port):
        """Force stack port DOWN"""
        peer_port = port.stack['port']
        peer_port.stack_gone()
        port.dyn_finalized = False
        port.enabled = False
        port.dyn_phys_up = False
        port.dyn_finalized = True
        self.assertFalse(port.non_stack_forwarding())

    def update_all_flowrules(self):
        """Update all valve tunnel flowrules"""
        for valve in self.valves_manager.valves.values():
            valve.update_tunnel_flowrules()

    def update_all_tunnels(self, state):
        """Force DP tunnel updated flag state"""
        for valve in self.valves_manager.valves.values():
            valve.dp.tunnel_updated_flags[self.TUNNEL_ID] = state

    def get_valve(self, dp_id):
        """Get valve with dp_id"""
        return self.valves_manager.valves[dp_id]

    def test_update_on_stack_link_up(self):
        """Test updating acl tunnel rules on stack link status UP"""
        self.all_stack_up()
        self.update_all_flowrules()
        for valve in self.valves_manager.valves.values():
            self.assertTrue(valve.dp.tunnel_updated_flags[self.TUNNEL_ID])

    def test_update_on_stack_link_down(self):
        """Test updating acl tunnel rules on stack link status DOWN"""
        self.all_stack_up()
        self.update_all_flowrules()
        self.update_all_tunnels(False)
        self.down_stack_port(self.get_valve(0x1).dp.ports[2])
        self.down_stack_port(self.get_valve(0x1).dp.ports[4])
        self.down_stack_port(self.get_valve(0x2).dp.ports[2])
        self.down_stack_port(self.get_valve(0x3).dp.ports[2])
        self.update_all_flowrules()
        self.assertTrue(self.get_valve(0x1).dp.tunnel_updated_flags[self.TUNNEL_ID])
        self.assertTrue(self.get_valve(0x2).dp.tunnel_updated_flags[self.TUNNEL_ID])

    def test_tunnel_flowmod_count(self):
        """Test the correct number of tunnel flowmods are created"""
        for valve in self.valves_manager.valves.values():
            self.assertEqual(len(valve.get_tunnel_flowmods()), 0)
        self.all_stack_up()
        self.update_all_flowrules()
        self.assertEqual(len(self.get_valve(0x1).get_tunnel_flowmods()), 2)
        self.assertEqual(len(self.get_valve(0x2).get_tunnel_flowmods()), 1)
        self.assertEqual(len(self.get_valve(0x3).get_tunnel_flowmods()), 2)


class ValveTwoDpRoot(ValveTestBases.ValveTestSmall):
    """Test simple stack topology from root."""

    CONFIG = """
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: 100
            2:
                stack:
                    dp: s2
                    port: 2
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: 100
            2:
                stack:
                    dp: s1
                    port: 2
    """

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_topo(self):
        """Test topology functions."""
        dp = self.valves_manager.valves[self.DP_ID].dp
        self.assertTrue(dp.is_stack_root())
        self.assertFalse(dp.is_stack_edge())


class ValveTwoDpRootEdge(ValveTestBases.ValveTestSmall):
    """Test simple stack topology from edge."""

    CONFIG = """
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: 100
            2:
                stack:
                    dp: s2
                    port: 2
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: 100
            2:
                stack:
                    dp: s1
                    port: 2
    """

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_topo(self):
        """Test topology functions."""
        dp_obj = self.valves_manager.valves[self.DP_ID].dp
        self.assertFalse(dp_obj.is_stack_root())
        self.assertTrue(dp_obj.is_stack_edge())


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
