#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve_stack.py."""

# pylint: disable=protected-access
# pylint: disable=too-many-lines

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

from faucet import valve_of
from faucet.port import (
    STACK_STATE_INIT, STACK_STATE_UP,
    LACP_PORT_SELECTED, LACP_PORT_UNSELECTED)

from clib.fakeoftable import CONTROLLER_PORT

from clib.valve_test_lib import (
    BASE_DP1_CONFIG, CONFIG, STACK_CONFIG, STACK_LOOP_CONFIG, ValveTestBases)


class ValveEdgeVLANTestCase(ValveTestBases.ValveTestNetwork):
    """Test edge VLAN operation"""

    CONFIG1 = """
dps:
    s1:
        dp_id: 1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    dp: s2
                    port: 1
    s2:
        dp_id: 2
        hardware: 'GenericTFM'
        interfaces:
            1:
                stack:
                    dp: s1
                    port: 1
            2:
                stack:
                    dp: s3
                    port: 1
    s3:
        dp_id: 3
        hardware: 'GenericTFM'
        interfaces:
            1:
                stack:
                    dp: s2
                    port: 2
    """
    CONFIG2 = """
dps:
    s1:
        dp_id: 1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    dp: s2
                    port: 1
    s2:
        dp_id: 2
        hardware: 'GenericTFM'
        interfaces:
            1:
                stack:
                    dp: s1
                    port: 1
            2:
                stack:
                    dp: s3
                    port: 1
    s3:
        dp_id: 3
        hardware: 'GenericTFM'
        interfaces:
            1:
                stack:
                    dp: s2
                    port: 2
            2:
                native_vlan: 100
            3:
                native_vlan: 100
    """

    def setUp(self):
        self.setup_valves(self.CONFIG1)
        self.activate_stack()

    def activate_stack(self):
        self.activate_all_ports()
        for valve in self.valves_manager.valves.values():
            for port in valve.dp.ports.values():
                if port.stack:
                    self.set_stack_port_up(port.number, valve)

    def test_edge_vlan(self):
        self.update_config(self.CONFIG2, reload_type=None)
        self.activate_stack()
        s1 = self.valves_manager.valves[1].dp
        self.assertTrue(s1.stack.is_root())
        self.assertFalse(s1.stack.is_edge())
        s2 = self.valves_manager.valves[2].dp
        self.assertFalse(s2.stack.is_root())
        self.assertFalse(s2.stack.is_edge())
        s3 = self.valves_manager.valves[3].dp
        self.assertFalse(s3.stack.is_root())
        self.assertTrue(s3.stack.is_edge())
        match = {'in_port': 2, 'vlan_vid': 0, 'eth_src': self.P2_V100_MAC}
        self.network.tables[3].is_output(match, port=3)
        match = {'in_port': 3, 'vlan_vid': 0, 'eth_src': self.P2_V100_MAC}
        self.network.tables[3].is_output(match, port=2)


class ValveStackMCLAGTestCase(ValveTestBases.ValveTestNetwork):
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
        self.setup_valves(self.CONFIG)

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
        nominated_dpid = valve.switch_manager.get_lacp_dpid_nomination(1, valve, other_valves)[0]
        self.assertEqual(
            nominated_dpid, 0x1,
            'Expected nominated DPID %s but found %s' % (0x1, nominated_dpid))
        # Choose DP with most UP LAG ports
        lacp_ports[0x1][0].actor_nosync()
        nominated_dpid = valve.switch_manager.get_lacp_dpid_nomination(1, valve, other_valves)[0]
        self.assertEqual(
            nominated_dpid, 0x2,
            'Expected nominated DPID %s but found %s' % (0x2, nominated_dpid))
        # Set all links to no_sync
        for valve in self.valves_manager.valves.values():
            for port in valve.dp.ports.values():
                if port.lacp:
                    lacp_ports.setdefault(valve.dp.dp_id, [])
                    lacp_ports[valve.dp.dp_id].append(port)
                    port.actor_nosync()
        valve = self.valves_manager.valves[0x1]
        other_valves = self.get_other_valves(valve)
        nominated_dpid = valve.switch_manager.get_lacp_dpid_nomination(1, valve, other_valves)[0]
        self.assertEqual(
            nominated_dpid, 0x1,
            'Expected nominated DPID %s but found %s' % (0x1, nominated_dpid))
        # Set one link to up
        lacp_ports[0x1][0].actor_up()
        nominated_dpid = valve.switch_manager.get_lacp_dpid_nomination(1, valve, other_valves)[0]
        self.assertEqual(
            nominated_dpid, 0x1,
            'Expected nominated DPID %s but found %s' % (0x1, nominated_dpid))
        # Set DP 1 links to init
        lacp_ports[0x1][0].actor_init()
        lacp_ports[0x1][1].actor_init()
        nominated_dpid = valve.switch_manager.get_lacp_dpid_nomination(1, valve, other_valves)[0]
        self.assertEqual(
            nominated_dpid, 0x2,
            'Expected nominated DPID %s but found %s' % (0x2, nominated_dpid))

    def test_no_dpid_nominations(self):
        """Test dpid nomination doesn't nominate when no LACP ports are up"""
        self.activate_all_ports()
        valve = self.valves_manager.valves[0x1]
        other_valves = self.get_other_valves(valve)
        # No actors UP so should return None
        nominated_dpid = valve.switch_manager.get_lacp_dpid_nomination(1, valve, other_valves)[0]
        self.assertEqual(
            nominated_dpid, None,
            'Did not expect to nominate DPID %s' % nominated_dpid)
        # No other valves so should return None
        for valve in self.valves_manager.valves.values():
            for port in valve.dp.ports.values():
                if port.lacp:
                    port.actor_up()
        nominated_dpid = valve.switch_manager.get_lacp_dpid_nomination(1, valve, None)[0]
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
                valve.lacp_update(port, True, 1, 1, other_valves)
                # Testing accuracy of varz port_lacp_role
                port_labels = {
                    'port': port.name,
                    'port_description': port.description,
                    'dp_name': valve.dp.name,
                    'dp_id': '0x%x' % valve.dp.dp_id
                }
                lacp_role = self.get_prom('port_lacp_role', labels=port_labels, bare=True)
                self.assertEqual(
                    port.lacp_port_state(), lacp_role,
                    'Port %s DP %s role %s differs from varz value %s'
                    % (port, valve, port.lacp_port_state(), lacp_role))
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


class ValveStackMCLAGRestartTestCase(ValveTestBases.ValveTestNetwork):
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
        self.setup_valves(self.CONFIG)

    def test_mclag_cold_start(self):
        """Test cold-starting a switch with a downed port resets LACP states"""
        self.activate_all_ports()
        valve = self.valves_manager.valves[0x1]
        other_valves = self.get_other_valves(valve)
        old_port = valve.dp.ports[3]
        # Make sure LACP state has been updated
        self.assertTrue(valve.lacp_update(old_port, True, 1, 1, other_valves), 'No OFMSGS returned')
        self.assertTrue(old_port.is_actor_up(), 'Actor not UP')
        # Set port DOWN
        valve.port_delete(3, other_valves=other_valves)
        self.assertTrue(old_port.is_actor_none(), 'Actor not NONE')
        # Restart switch & LACP port
        self.cold_start()
        new_port = valve.dp.ports[3]
        # A full cold-start should change port object, but self.cold_start() is 'incomplete'
        self.assertEqual(id(old_port), id(new_port), 'Port object changed')
        self.assertTrue(valve.port_add(3), 'No OFMSGS returned')
        # Successfully restart LACP from downed
        self.assertTrue(valve.lacp_update(new_port, True, 1, 1, other_valves), 'No OFMSGS returned')
        self.assertTrue(new_port.is_actor_up(), 'Actor not UP')


class ValveStackMCLAGStandbyTestCase(ValveTestBases.ValveTestNetwork):
    """Test MCLAG with standby port option overrules unselected states"""

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
                description: p3
                native_vlan: 100
                lacp_standby: True
                lacp: 1
            3:
                description: p4
                native_vlan: 100
                lacp_standby: True
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
                description: p3
                native_vlan: 100
                lacp_standby: True
                lacp: 1
            3:
                description: p4
                native_vlan: 100
                lacp_standby: True
                lacp: 1
""" % BASE_DP1_CONFIG

    def setUp(self):
        """Setup basic loop config"""
        self.setup_valves(self.CONFIG)

    def test_mclag_standby_option(self):
        """Test MCLAG standby option forces standby state instead of unselected"""
        self.activate_all_ports()
        valve = self.valves_manager.valves[0x1]
        other_valve = self.valves_manager.valves[0x2]
        for port in valve.dp.ports.values():
            if port.lacp:
                valve.lacp_update(port, True, 1, 1, self.get_other_valves(valve))
                self.assertTrue(port.is_port_selected())
        for port in other_valve.dp.ports.values():
            if port.lacp:
                other_valve.lacp_update(port, True, 1, 1, self.get_other_valves(other_valve))
                self.assertTrue(port.is_port_standby())
        for port in valve.dp.ports.values():
            if port.lacp:
                valve.lacp_update(port, False, 1, 1, self.get_other_valves(valve))
                self.assertTrue(port.is_port_standby())
        for port in other_valve.dp.ports.values():
            if port.lacp:
                other_valve.lacp_update(port, True, 1, 1, self.get_other_valves(other_valve))
                self.assertTrue(port.is_port_selected())


class ValveStackRootExtLoopProtectTestCase(ValveTestBases.ValveTestNetwork):
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
        self.setup_valves(self.CONFIG)
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
        table = self.network.tables[self.DP_ID]
        self.assertTrue(
            table.is_output(mcast_match, port=1),
            msg='mcast packet not flooded to non-root stack')
        self.assertTrue(
            table.is_output(mcast_match, port=3),
            msg='mcast packet not flooded locally on root')
        self.assertFalse(
            table.is_output(mcast_match, port=4),
            msg='mcast packet multiply flooded externally on root')


class ValveStackChainTest(ValveTestBases.ValveTestNetwork):
    """Test base class for loop stack config"""

    CONFIG = STACK_CONFIG
    DP = 's2'
    DP_ID = 2

    def setUp(self):
        """Setup basic loop config"""
        self.setup_valves(self.CONFIG)

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
        table = self.network.tables[self.DP_ID]
        return table.is_output(ucast_match, port=out_port, trace=trace)

    def _learning_from_bcast(self, in_port, trace=False):
        ucast_match = {
            'in_port': in_port,
            'eth_src': self.P1_V100_MAC,
            'eth_dst': self.BROADCAST_MAC,
            'vlan_vid': self.V100,
            'eth_type': 0x800,
        }
        table = self.network.tables[self.DP_ID]
        if trace:
            self.network.print_table(2)
        return table.is_output(ucast_match, port=CONTROLLER_PORT, trace=trace)

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

    def test_stack_learn_not_root(self):
        """Test stack learned when not root"""
        self.update_config(self._config_edge_learn_stack_root(False), reload_type='warm')
        self.activate_all_ports()
        self.validate_edge_learn_ports()


class ValveStackLoopTest(ValveTestBases.ValveTestNetwork):
    """Test base class for loop stack config"""

    CONFIG = STACK_LOOP_CONFIG

    def setUp(self):
        """Setup basic loop config"""
        self.setup_valves(self.CONFIG)

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
        table = self.network.tables[self.DP_ID]
        return table.is_output(ucast_match, port=out_port)

    def _learning_from_bcast(self, in_port):
        bcast_match = {
            'in_port': in_port,
            'eth_src': self.P2_V100_MAC,
            'eth_dst': self.BROADCAST_MAC,
            'vlan_vid': self.V100,
            'eth_type': 0x800,
        }
        table = self.network.tables[self.DP_ID]
        return table.is_output(bcast_match, port=CONTROLLER_PORT)

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

        self.update_config(self._config_edge_learn_stack_root(False), reload_type='warm')

        self.activate_all_ports()

        self.validate_edge_learn_ports()

        # After learning, unicast should go direct to edge switch.
        self.assertTrue(self._unicast_to(1), 'unicast direct to edge')
        self.assertFalse(self._unicast_to(2), 'unicast to stack root')

        # TODO: This should be False to prevent unnecessary packet-ins.
        self.assertTrue(self._learning_from_bcast(2), 'learn from stack root broadcast')

    def test_edge_learn_stack_root(self):
        """Check the behavior of learning always towards stack root"""

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
        table = self.network.tables[self.DP_ID]
        valve = self.valves_manager.valves[self.DP_ID]
        self.assertTrue(
            table.is_output(mcast_match, port=2),
            msg='mcast packet not flooded to root of stack')
        self.assertFalse(valve.dp.ports[2].non_stack_forwarding())
        self.assertFalse(
            table.is_output(mcast_match, port=1),
            msg='mcast packet flooded root of stack via not shortest path')
        self.deactivate_stack_port(valve.dp.ports[2])
        self.assertFalse(valve.dp.ports[2].non_stack_forwarding())
        self.assertFalse(
            table.is_output(mcast_match, port=2),
            msg='mcast packet flooded to root of stack via redundant path')
        self.assertFalse(valve.dp.ports[2].non_stack_forwarding())
        self.assertTrue(
            table.is_output(mcast_match, port=1),
            msg='mcast packet not flooded root of stack')
        self.assertFalse(valve.dp.ports[2].non_stack_forwarding())
        self.assertTrue(valve.dp.ports[3].non_stack_forwarding())


class ValveStackNonRootExtLoopProtectTestCase(ValveTestBases.ValveTestNetwork):
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
        self.setup_valves(self.CONFIG)
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
        table = self.network.tables[self.DP_ID]
        self.assertTrue(
            table.is_output(mcast_match, port=1),
            msg='mcast packet not flooded to root of stack')
        self.assertFalse(
            table.is_output(mcast_match, port=3),
            msg='mcast packet flooded locally on non-root')
        self.assertFalse(
            table.is_output(mcast_match, port=4),
            msg='mcast packet flooded locally on non-root')


class ValveStackAndNonStackTestCase(ValveTestBases.ValveTestNetwork):
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
        self.setup_valves(self.CONFIG)

    def test_nonstack_dp_port(self):
        """Test that finding a path from a stack swithc to a non-stack switch cannot happen"""
        self.assertIsNone(None, self.valves_manager.valves[0x3].dp.stack)
        self.assertEqual(None, self.valves_manager.valves[0x1].dp.stack.shortest_path_port('s3'))


class ValveStackRedundancyTestCase(ValveTestBases.ValveTestNetwork):
    """Valve test for root selection."""

    CONFIG = STACK_CONFIG
    STACK_ROOT_STATE_UPDATE_TIME = 10
    STACK_ROOT_DOWN_TIME = STACK_ROOT_STATE_UPDATE_TIME * 3

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def dp_by_name(self, dp_name):
        """Get DP by DP name"""
        for valve in self.valves_manager.valves.values():
            if valve.dp.name == dp_name:
                return valve.dp
        return None

    def set_stack_all_ports_status(self, dp_name, status):
        """Set all stack ports to status on dp"""
        dp = self.dp_by_name(dp_name)
        for port in dp.stack_ports():
            port.dyn_stack_current_state = status

    def test_redundancy(self):
        """Test redundant stack connections"""
        now = 1
        self.trigger_stack_ports()
        # All switches are down to start with.
        for dp in [valve.dp for valve in self.valves_manager.valves.values()]:
            dp.dyn_running = False
            self.set_stack_all_ports_status(dp.name, STACK_STATE_INIT)
        for valve in self.valves_manager.valves.values():
            self.assertFalse(valve.dp.dyn_running)
            self.assertEqual('s1', valve.dp.stack.root_name)
            root_hop_port = valve.dp.stack.shortest_path_port('s1')
            root_hop_port = root_hop_port.number if root_hop_port else 0
            self.assertEqual(root_hop_port, self.get_prom('dp_root_hop_port', dp_id=valve.dp.dp_id))
        # From a cold start - we pick the s1 as root.
        self.assertEqual(None, self.valves_manager.meta_dp_state.stack_root_name)
        self.assertFalse(
            self.valves_manager.maintain_stack_root(now, self.STACK_ROOT_STATE_UPDATE_TIME))
        self.assertEqual('s1', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(1, self.get_prom('faucet_stack_root_dpid', bare=True))
        self.assertTrue(self.get_prom('is_dp_stack_root', dp_id=1))
        self.assertFalse(self.get_prom('is_dp_stack_root', dp_id=2))
        self.assertEqual(1, self.get_prom('stack_root_change_count_total', bare=True))
        now += (self.STACK_ROOT_DOWN_TIME * 2)
        # Time passes, still no change, s1 is still the root.
        self.assertFalse(
            self.valves_manager.maintain_stack_root(now, self.STACK_ROOT_STATE_UPDATE_TIME))
        self.assertEqual('s1', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(1, self.get_prom('faucet_stack_root_dpid', bare=True))
        self.assertTrue(self.get_prom('is_dp_stack_root', dp_id=1))
        self.assertFalse(self.get_prom('is_dp_stack_root', dp_id=2))
        self.assertEqual(1, self.get_prom('stack_root_change_count_total', bare=True))
        # s2 has come up, but has all stack ports down and s1 is still down.
        self.valves_manager.meta_dp_state.dp_last_live_time['s2'] = now
        now += (self.STACK_ROOT_STATE_UPDATE_TIME * 2)
        # We expect s2 to be the new root because now it has stack links up.
        self.set_stack_all_ports_status('s2', STACK_STATE_UP)
        now += (self.STACK_ROOT_STATE_UPDATE_TIME * 2)
        self.valves_manager.meta_dp_state.dp_last_live_time['s2'] = now
        self.assertTrue(
            self.valves_manager.maintain_stack_root(now, self.STACK_ROOT_STATE_UPDATE_TIME))
        self.assertEqual('s2', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(2, self.get_prom('faucet_stack_root_dpid', bare=True))
        self.assertFalse(self.get_prom('is_dp_stack_root', dp_id=1))
        self.assertTrue(self.get_prom('is_dp_stack_root', dp_id=2))
        self.assertEqual(2, self.get_prom('stack_root_change_count_total', bare=True))
        # More time passes, s1 is still down, s2 is still the root.
        now += (self.STACK_ROOT_DOWN_TIME * 2)
        # s2 recently said something, s2 still the root.
        self.valves_manager.meta_dp_state.dp_last_live_time['s2'] = now - 1
        self.set_stack_all_ports_status('s2', STACK_STATE_UP)
        self.assertFalse(
            self.valves_manager.maintain_stack_root(now, self.STACK_ROOT_STATE_UPDATE_TIME))
        self.assertEqual('s2', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(2, self.get_prom('faucet_stack_root_dpid', bare=True))
        self.assertFalse(self.get_prom('is_dp_stack_root', dp_id=1))
        self.assertTrue(self.get_prom('is_dp_stack_root', dp_id=2))
        self.assertEqual(2, self.get_prom('stack_root_change_count_total', bare=True))
        # now s1 came up too, but we stay on s2 because it's healthy.
        self.valves_manager.meta_dp_state.dp_last_live_time['s1'] = now + 1
        now += self.STACK_ROOT_STATE_UPDATE_TIME
        self.assertFalse(
            self.valves_manager.maintain_stack_root(now, self.STACK_ROOT_STATE_UPDATE_TIME))
        self.assertEqual('s2', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(2, self.get_prom('faucet_stack_root_dpid', bare=True))
        self.assertFalse(self.get_prom('is_dp_stack_root', dp_id=1))
        self.assertTrue(self.get_prom('is_dp_stack_root', dp_id=2))
        self.assertEqual(2, self.get_prom('stack_root_change_count_total', bare=True))


class ValveRootStackTestCase(ValveTestBases.ValveTestNetwork):
    """Test stacking/forwarding."""

    DP = 's3'
    DP_ID = 0x3

    def setUp(self):
        self.setup_valves(CONFIG)
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

    def test_stack_off_on(self):
        SIMPLE_DP_CONFIG = """
        dps:
            s3:
                dp_id: 3
                hardware: Open vSwitch
                interfaces:
                    1:
                        native_vlan: 100
        """
        self.update_config(SIMPLE_DP_CONFIG, reload_expected=True)
        dp = self.valves_manager.valves[self.DP_ID].dp
        self.assertFalse(dp.stack)
        self.update_config(CONFIG, reload_expected=True)
        self.set_stack_port_up(5)
        dp = self.valves_manager.valves[self.DP_ID].dp
        self.assertTrue(dp.stack.is_root())

    def test_topo(self):
        """Test DP is assigned appropriate edge/root states"""
        dp = self.valves_manager.valves[self.DP_ID].dp
        self.assertTrue(dp.stack.is_root())
        self.assertFalse(dp.stack.is_edge())


class ValveEdgeStackTestCase(ValveTestBases.ValveTestNetwork):
    """Test stacking/forwarding."""

    DP = 's4'
    DP_ID = 0x4

    def setUp(self):
        self.setup_valves(CONFIG)
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
        table = self.network.tables[self.DP_ID]
        self.assertFalse(
            table.is_output(match, port=ofp.OFPP_CONTROLLER, vid=unexpressed_vid))

    def test_topo(self):
        """Test DP is assigned appropriate edge/root states"""
        dp = self.valves_manager.valves[self.DP_ID].dp
        self.assertFalse(dp.stack.is_root())
        self.assertTrue(dp.stack.is_edge())


class ValveStackProbeTestCase(ValveTestBases.ValveTestNetwork):
    """Test stack link probing."""

    CONFIG = STACK_CONFIG

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_stack_probe(self):
        """Test probing works correctly."""
        valve = self.valves_manager.valves[self.DP_ID]
        stack_port = valve.dp.ports[1]
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[1]
        other_valves = self.valves_manager._other_running_valves(valve)
        self.assertTrue(stack_port.is_stack_none())
        valve.fast_state_expire(self.mock_time(), other_valves)
        self.assertTrue(stack_port.is_stack_init())
        for change_func, check_func in [
                ('stack_up', 'is_stack_up')]:
            getattr(other_port, change_func)()
            self.rcv_lldp(stack_port, other_dp, other_port)
            self.assertTrue(getattr(stack_port, check_func)(), msg=change_func)

    def test_stack_miscabling(self):
        """Test probing stack with miscabling."""
        valve = self.valves_manager.valves[self.DP_ID]
        stack_port = valve.dp.ports[1]
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[1]
        wrong_port = other_dp.ports[2]
        wrong_dp = self.valves_manager.valves[3].dp
        other_valves = self.valves_manager._other_running_valves(valve)
        valve.fast_state_expire(self.mock_time(), other_valves)
        for remote_dp, remote_port in [
                (wrong_dp, other_port),
                (other_dp, wrong_port)]:
            self.rcv_lldp(stack_port, other_dp, other_port)
            self.assertTrue(stack_port.is_stack_up())
            self.rcv_lldp(stack_port, remote_dp, remote_port)
            self.assertTrue(stack_port.is_stack_bad())

    def test_stack_lost_lldp(self):
        """Test stacking when LLDP packets get dropped"""
        valve = self.valves_manager.valves[self.DP_ID]
        stack_port = valve.dp.ports[1]
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[1]
        other_valves = self.valves_manager._other_running_valves(valve)
        valve.fast_state_expire(self.mock_time(), other_valves)
        self.rcv_lldp(stack_port, other_dp, other_port)
        self.assertTrue(stack_port.is_stack_up())
        # simulate packet loss
        valve.fast_state_expire(self.mock_time(300), other_valves)
        self.assertTrue(stack_port.is_stack_gone())
        valve.fast_state_expire(self.mock_time(300), other_valves)
        self.rcv_lldp(stack_port, other_dp, other_port)
        self.assertTrue(stack_port.is_stack_up())
        port_labels = {
            'port': stack_port.name,
            'port_description': stack_port.description,
            'dp_name': valve.dp.name,
            'dp_id': '0x%x' % valve.dp.dp_id
        }
        stack_change_count = self.get_prom(
            'port_stack_state_change_count_total', labels=port_labels, bare=True)
        self.assertEqual(
            4, stack_change_count,
            'Port %s DP %s expected stack change count %s differs from varz value %s'
            % (stack_port, valve.dp.name, 4, stack_change_count)
        )


class ValveStackGraphUpdateTestCase(ValveTestBases.ValveTestNetwork):
    """Valve test for updating the stack graph."""

    CONFIG = STACK_CONFIG

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_update_stack_graph(self):
        """Test stack graph port UP and DOWN updates"""

        def verify_stack_learn_edges(num_edges, edge=None, test_func=None):
            for dpid in (1, 2, 3):
                valve = self.valves_manager.valves[dpid]
                if not valve.dp.stack:
                    continue
                graph = valve.dp.stack.graph
                self.assertEqual(num_edges, len(graph.edges()))
                if test_func and edge:
                    test_func(edge in graph.edges(keys=True))

        num_edges = 3
        self.all_stack_up()
        verify_stack_learn_edges(num_edges)
        valve = self.valves_manager.valves[self.DP_ID]
        ports = [valve.dp.ports[1], valve.dp.ports[2]]
        edges = [('s1', 's2', 's1:1-s2:1'), ('s1', 's2', 's1:2-s2:2')]
        for port, edge in zip(ports, edges):
            num_edges -= 1
            self.down_stack_port(port)
            verify_stack_learn_edges(num_edges, edge, self.assertFalse)
        self.up_stack_port(ports[0])
        verify_stack_learn_edges(2, edges[0], self.assertTrue)


class ValveStackGraphBreakTestCase(ValveStackLoopTest):
    """Valve test for updating the stack graph."""

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

    def test_update_stack_graph(self):
        """Test stack graph port UP and DOWN updates"""

        self.activate_all_ports()
        self.validate_flooding(False)
        table = self.network.tables[self.DP_ID]
        self.assertLessEqual(table.flow_count(), 33, 'table overflow')
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

        valve = self.valves_manager.valves[self.DP_ID]
        port = valve.dp.ports[1]

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
        self.update_config(new_config, reload_expected=False, no_reload_no_table_change=False)
        self.activate_all_ports()
        self.validate_flooding()

        # Like above, deactivate the port (stops LLDP beacons).
        self.deactivate_stack_port(port, packets=10)

        # After 10 packets (more than before), it should still work.
        self.validate_flooding()

        # But, after 100 more port should be down b/c limit is set to 100.
        self.trigger_all_ports(packets=100)
        self.validate_flooding(portup=False)


class ValveTestIPV4StackedRouting(ValveTestBases.ValveTestStackedRouting):  # pylint: disable=too-few-public-methods
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

    V100_HOSTS = [1]
    V200_HOSTS = [2]

    NUM_PORTS = 64

    @staticmethod
    def base_config():
        """Create the base config"""
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
            hardware: 'GenericTFM'
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

    V100_HOSTS = [1]
    V200_HOSTS = [3]

    def create_config(self):
        """Create the config file"""
        # pylint: disable=attribute-defined-outside-init
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

    @staticmethod
    def base_config():
        """Create the base config"""
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
            hardware: 'GenericTFM'
            interfaces:
                2:
                    native_vlan: vlan300
                3:
                    stack: {dp: s1, port: 3}
                4:
                    stack: {dp: s3, port: 3}
        s3:
            dp_id: 3
            hardware: 'GenericTFM'
            interfaces:
                2:
                    native_vlan: vlan200
                3:
                    stack: {dp: s2, port: 4}
                4:
                    stack: {dp: s4, port: 3}
        s4:
            dp_id: 4
            hardware: 'GenericTFM'
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

    def create_match(self, vindex, host, faucet_mac, faucet_vip, _code):
        """Create an NA message"""
        return {
            'eth_src': self.create_mac(vindex, host),
            'eth_dst': faucet_mac,
            'ipv6_src': self.create_ip(vindex, host),
            'ipv6_dst': faucet_vip,
            'neighbor_advert_ip': self.create_ip(vindex, host)
        }


class ValveInterVLANStackFlood(ValveTestBases.ValveTestNetwork):
    """Test that the stack ports get flooded to for interVLAN packets"""

    VLAN100_FAUCET_MAC = '00:00:00:00:00:11'
    VLAN200_FAUCET_MAC = '00:00:00:00:00:22'
    VLAN100_FAUCET_VIPS = '10.1.0.254'
    VLAN100_FAUCET_VIP_SPACE = '10.1.0.254/24'
    VLAN200_FAUCET_VIPS = '10.2.0.254'
    VLAN200_FAUCET_VIP_SPACE = '10.2.0.254/24'
    DST_ADDRESS = ipaddress.IPv4Address('10.1.0.1')

    @staticmethod
    def base_config():
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
        hardware: 'GenericTFM'
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
        hardware: 'GenericTFM'
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
        hardware: 'GenericTFM'
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
        self.setup_valves(self.CONFIG)
        self.trigger_stack_ports()

    @staticmethod
    def stack_manager_flood_ports(stack_manager):
        """Return list of port numbers that will be flooded to"""
        stack_manager.reset_peer_distances()
        ports = list()
        if stack_manager.stack.is_root():
            ports = (stack_manager.away_ports - stack_manager.inactive_away_ports
                     - stack_manager.pruned_away_ports)
        else:
            ports = [stack_manager.chosen_towards_port]
        return sorted([port.number for port in ports])

    def route_manager_ofmsgs(self, route_manager, vlan):
        """Return ofmsgs for route stack link flooding"""
        faucet_vip = list(vlan.faucet_vips_by_ipv(4))[0].ip
        ofmsgs = route_manager._flood_stack_links(
            route_manager._gw_resolve_pkt(), vlan, route_manager.multi_out,
            vlan.faucet_mac, valve_of.mac.BROADCAST_STR,
            faucet_vip, self.DST_ADDRESS)
        return ofmsgs

    def test_flood_towards_root_from_s1(self):
        """Test intervlan flooding goes towards the root"""
        output_ports = [3]
        valve = self.valves_manager.valves[1]
        ports = self.stack_manager_flood_ports(valve.stack_manager)
        self.assertEqual(output_ports, ports, 'InterVLAN flooding does not match expected')
        route_manager = valve._route_manager_by_ipv.get(4, None)
        vlan = valve.dp.vlans[100]
        ofmsgs = self.route_manager_ofmsgs(route_manager, vlan)
        self.assertTrue(ValveTestBases.packet_outs_from_flows(ofmsgs))

    def test_flood_away_from_root(self):
        """Test intervlan flooding goes away from the root"""
        output_ports = [3, 4]
        valve = self.valves_manager.valves[2]
        ports = self.stack_manager_flood_ports(valve.stack_manager)
        self.assertEqual(output_ports, ports, 'InterVLAN flooding does not match expected')
        route_manager = valve._route_manager_by_ipv.get(4, None)
        vlan = valve.dp.vlans[100]
        ofmsgs = self.route_manager_ofmsgs(route_manager, vlan)
        self.assertTrue(ValveTestBases.packet_outs_from_flows(ofmsgs))

    def test_flood_towards_root_from_s3(self):
        """Test intervlan flooding only goes towards the root (s4 will get the reflection)"""
        output_ports = [3]
        valve = self.valves_manager.valves[3]
        ports = self.stack_manager_flood_ports(valve.stack_manager)
        self.assertEqual(output_ports, ports, 'InterVLAN flooding does not match expected')
        route_manager = valve._route_manager_by_ipv.get(4, None)
        vlan = valve.dp.vlans[100]
        ofmsgs = self.route_manager_ofmsgs(route_manager, vlan)
        self.assertTrue(ValveTestBases.packet_outs_from_flows(ofmsgs))

    def test_flood_towards_root_from_s4(self):
        """Test intervlan flooding goes towards the root (through s3)"""
        output_ports = [3]
        valve = self.valves_manager.valves[4]
        ports = self.stack_manager_flood_ports(valve.stack_manager)
        self.assertEqual(output_ports, ports, 'InterVLAN flooding does not match expected')
        route_manager = valve._route_manager_by_ipv.get(4, None)
        vlan = valve.dp.vlans[100]
        ofmsgs = self.route_manager_ofmsgs(route_manager, vlan)
        self.assertTrue(ValveTestBases.packet_outs_from_flows(ofmsgs))


class ValveTestTunnel2DP(ValveTestBases.ValveTestTunnel):
    """Test Tunnel ACL implementation"""

    SRC_ID = 5
    DST_ID = 2
    SAME_ID = 4
    NONE_ID = 3

    CONFIG = """
acls:
    src_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    tunnel: {dp: s2, port: 1}
    dst_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    tunnel: {dp: s1, port: 1}
    same_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    tunnel: {dp: s1, port: 1}
    none_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    tunnel: {dp: s2, port: 1}
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                name: src_tunnel_host
                native_vlan: vlan100
                acls_in: [src_acl]
            2:
                name: same_tunnel_host
                native_vlan: vlan100
                acls_in: [same_acl]
            3:
                stack: {dp: s2, port: 3}
            4:
                stack: {dp: s2, port: 4}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                name: dst_tunnel_host
                native_vlan: vlan100
                acls_in: [dst_acl]
            2:
                name: transit_tunnel_host
                native_vlan: vlan100
                acls_in: [none_acl]
            3:
                stack: {dp: s1, port: 3}
            4:
                stack: {dp: s1, port: 4}
"""

    def test_update_src_tunnel(self):
        """Test tunnel rules when encapsulating and forwarding to the destination switch"""
        valve = self.valves_manager.valves[0x1]
        port = valve.dp.ports[3]
        # Apply tunnel to ofmsgs on valve
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        # Should encapsulate and output packet towards tunnel destination s3
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 3, self.SRC_ID, True,
            'Did not encapsulate and forward')
        new_config_yaml = yaml.safe_load(self.CONFIG)
        new_config_yaml['dps']['s1']['interfaces'][1]['description'] = 'changed'
        self.update_config(yaml.dump(new_config_yaml), reload_type=None)
        self.activate_all_ports()
        # warm start with no topo change with tunnel.
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 3, self.SRC_ID, True,
            'Did not encapsulate and forward')
        # Set the chosen port down to force a recalculation on the tunnel path
        self.set_port_down(port.number)
        ofmsgs = valve.stack_manager.add_tunnel_acls()
        self.assertTrue(ofmsgs, 'No tunnel ofmsgs returned after a topology change')
        self.apply_ofmsgs(ofmsgs)
        # Should encapsulate and output packet using the new path
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 4, self.SRC_ID, True,
            'Did not encapsulate and forward out re-calculated port')
        self.flap_port(1)
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 4, self.SRC_ID, True,
            'Did not encapsulate and forward after port flap')

    def test_update_same_tunnel(self):
        """Test tunnel rules when outputting to host on the same switch as the source"""
        valve = self.valves_manager.valves[0x1]
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            2, 0, 1, 0, True, 'Did not forward to host on same DP')

    def test_update_dst_tunnel(self):
        """Test a tunnel outputting to the correct tunnel destination"""
        valve = self.valves_manager.valves[0x1]
        port = valve.dp.ports[3]
        # Apply tunnel to ofmsgs on valve
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        # Should accept encapsulated packet and output to the destination host
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            3, self.DST_ID, 1, 0, True, 'Did not output to host',
            pcp=valve_of.PCP_TUNNEL_FLAG)
        # Set the chosen port down to force a recalculation on the tunnel path
        self.set_port_down(port.number)
        ofmsgs = valve.stack_manager.add_tunnel_acls()
        self.assertTrue(ofmsgs, 'No tunnel ofmsgs returned after a topology change')
        self.apply_ofmsgs(ofmsgs)
        # Should accept encapsulated packet and output using the new path
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            4, self.DST_ID, 1, 0, True, 'Did not output to host',
            pcp=valve_of.PCP_TUNNEL_FLAG)

    def test_update_none_tunnel(self):
        """Test tunnel on a switch not using a tunnel ACL"""
        valve = self.valves_manager.valves[0x1]
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        # Should drop any packets received from the tunnel
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            5, self.NONE_ID, None, None, False,
            'Should not output a packet')
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            6, self.NONE_ID, None, None, False,
            'Should not output a packet')


class ValveTestTransitTunnel(ValveTestBases.ValveTestTunnel):  # pylint: disable=too-few-public-methods
    """Test tunnel ACL implementation"""

    TRANSIT_ID = 2

    CONFIG = """
acls:
    transit_acl:
         - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    tunnel: {dp: s3, port: 1}
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            3:
                stack: {dp: s2, port: 3}
            4:
                stack: {dp: s2, port: 4}
            5:
                stack: {dp: s3, port: 5}
            6:
                stack: {dp: s3, port: 6}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                name: source_host
                native_vlan: vlan100
                acls_in: [transit_acl]
            3:
                stack: {dp: s1, port: 3}
            4:
                stack: {dp: s1, port: 4}
    s3:
        dp_id: 0x3
        hardware: 'GenericTFM'
        interfaces:
            1:
                name: destination_host
                native_vlan: vlan100
            5:
                stack: {dp: s1, port: 5}
            6:
                stack: {dp: s1, port: 6}
"""

    def test_update_transit_tunnel(self):
        """Test a tunnel through a transit switch (forwards to the correct switch)"""
        valve = self.valves_manager.valves[0x1]
        port1 = valve.dp.ports[3]
        port2 = valve.dp.ports[5]
        # Apply tunnel to ofmsgs on valve
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        # Should accept packet from stack and output to the next switch
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            3, self.TRANSIT_ID, 5, self.TRANSIT_ID, True,
            'Did not output to next switch',
            pcp=valve_of.PCP_TUNNEL_FLAG)
        # Set the chosen port down to force a recalculation on the tunnel path
        self.set_port_down(port1.number)
        # Should accept encapsulated packet and output using the new path
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            4, self.TRANSIT_ID, 5, self.TRANSIT_ID, True,
            'Did not output to next switch',
            pcp=valve_of.PCP_TUNNEL_FLAG)
        # Set the chosen port to the next switch down to force a path recalculation
        self.set_port_down(port2.number)
        ofmsgs = valve.stack_manager.add_tunnel_acls()
        self.assertTrue(ofmsgs, 'No tunnel ofmsgs returned after a topology change')
        self.apply_ofmsgs(ofmsgs)
        # Should accept encapsulated packet and output using the new path
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            4, self.TRANSIT_ID, 6, self.TRANSIT_ID, True,
            'Did not output to next switch',
            pcp=valve_of.PCP_TUNNEL_FLAG)


class ValveTestMultipleTunnel(ValveTestBases.ValveTestTunnel):
    """Test tunnel ACL implementation with multiple hosts containing tunnel ACL"""

    TUNNEL_ID = 2

    CONFIG = """
acls:
    tunnel_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    tunnel: {dp: s2, port: 1}
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: vlan100
                acls_in: [tunnel_acl]
            2:
                native_vlan: vlan100
                acls_in: [tunnel_acl]
            3:
                stack: {dp: s2, port: 3}
            4:
                stack: {dp: s2, port: 4}
            5:
                native_vlan: vlan100
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: vlan100
            3:
                stack: {dp: s1, port: 3}
            4:
                stack: {dp: s1, port: 4}
"""

    def test_new_tunnel_source(self):
        config = yaml.load(self.CONFIG, Loader=yaml.SafeLoader)
        config['dps']['s1']['interfaces'][5]['acls_in'] = ['tunnel_acl']
        self.update_config(yaml.dump(config), reload_type='warm')
        self.activate_all_ports()
        self.test_tunnel_update_multiple_tunnels()

    def test_tunnel_update_multiple_tunnels(self):
        """Test having multiple hosts with the same tunnel"""
        valve = self.valves_manager.valves[0x1]
        port = valve.dp.ports[3]
        # Apply tunnel to ofmsgs on valve
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        # Should encapsulate and output packet towards tunnel destination s3
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 3, self.TUNNEL_ID, True,
            'Did not encapsulate and forward')
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            2, 0, 3, self.TUNNEL_ID, True,
            'Did not encapsulate and forward')
        # Set the chosen port down to force a recalculation on the tunnel path
        self.set_port_down(port.number)
        ofmsgs = valve.stack_manager.add_tunnel_acls()
        self.assertTrue(ofmsgs, 'No tunnel ofmsgs returned after a topology change')
        self.apply_ofmsgs(ofmsgs)
        # Should encapsulate and output packet using the new path
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 4, self.TUNNEL_ID, True,
            'Did not encapsulate and forward out re-calculated port')
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 4, self.TUNNEL_ID, True,
            'Did not encapsulate and forward out re-calculated port')


class ValveTestOrderedTunnel2DP(ValveTestBases.ValveTestTunnel):
    """Test Tunnel ACL implementation"""

    SRC_ID = 6
    DST_ID = 2
    SAME_ID = 4
    NONE_ID = 3

    CONFIG = """
acls:
    src_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {dp: s2, port: 1}
        - rule:
            dl_type: 0x86dd
            ip_proto: 56
            actions:
                output:
                    - tunnel: {dp: s2, port: 1}
    dst_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {dp: s1, port: 1}
    same_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {dp: s1, port: 1}
    none_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {dp: s2, port: 1}
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                name: src_tunnel_host
                native_vlan: vlan100
                acls_in: [src_acl]
            2:
                name: same_tunnel_host
                native_vlan: vlan100
                acls_in: [same_acl]
            3:
                stack: {dp: s2, port: 3}
            4:
                stack: {dp: s2, port: 4}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                name: dst_tunnel_host
                native_vlan: vlan100
                acls_in: [dst_acl]
            2:
                name: transit_tunnel_host
                native_vlan: vlan100
                acls_in: [none_acl]
            3:
                stack: {dp: s1, port: 3}
            4:
                stack: {dp: s1, port: 4}
"""

    def test_update_src_tunnel(self):
        """Test tunnel rules when encapsulating and forwarding to the destination switch"""
        valve = self.valves_manager.valves[0x1]
        port = valve.dp.ports[3]
        # Apply tunnel to ofmsgs on valve
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        # Should encapsulate and output packet towards tunnel destination s3
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 3, self.SRC_ID, True,
            'Did not encapsulate and forward')
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 3, self.SRC_ID, True,
            'Did not encapsulate and forward',
            eth_type=0x86dd, ip_proto=56)
        # Set the chosen port down to force a recalculation on the tunnel path
        self.set_port_down(port.number)
        ofmsgs = valve.stack_manager.add_tunnel_acls()
        self.assertTrue(ofmsgs, 'No tunnel ofmsgs returned after a topology change')
        self.apply_ofmsgs(ofmsgs)
        # Should encapsulate and output packet using the new path
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 4, self.SRC_ID, True,
            'Did not encapsulate and forward out re-calculated port')

    def test_update_same_tunnel(self):
        """Test tunnel rules when outputting to host on the same switch as the source"""
        valve = self.valves_manager.valves[0x1]
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            2, 0, 1, 0, True, 'Did not forward to host on same DP')

    def test_update_dst_tunnel(self):
        """Test a tunnel outputting to the correct tunnel destination"""
        valve = self.valves_manager.valves[0x1]
        port = valve.dp.ports[3]
        # Apply tunnel to ofmsgs on valve
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        # Should accept encapsulated packet and output to the destination host
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            3, self.DST_ID, 1, 0, True, 'Did not output to host',
            pcp=valve_of.PCP_TUNNEL_FLAG)
        # Set the chosen port down to force a recalculation on the tunnel path
        self.set_port_down(port.number)
        ofmsgs = valve.stack_manager.add_tunnel_acls()
        self.assertTrue(ofmsgs, 'No tunnel ofmsgs returned after a topology change')
        self.apply_ofmsgs(ofmsgs)
        # Should accept encapsulated packet and output using the new path
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            4, self.DST_ID, 1, 0, True, 'Did not output to host',
            pcp=valve_of.PCP_TUNNEL_FLAG)

    def test_update_none_tunnel(self):
        """Test tunnel on a switch not using a tunnel ACL"""
        valve = self.valves_manager.valves[0x1]
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        # Should drop any packets received from the tunnel
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            5, self.NONE_ID, None, None, False,
            'Should not output a packet')
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            6, self.NONE_ID, None, None, False,
            'Should not output a packet')


class ValveTestTransitOrderedTunnel(ValveTestBases.ValveTestTunnel):  # pylint: disable=too-few-public-methods
    """Test tunnel ACL implementation"""

    TRANSIT_ID = 2

    CONFIG = """
acls:
    transit_acl:
         - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {dp: s3, port: 1}
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            3:
                stack: {dp: s2, port: 3}
            4:
                stack: {dp: s2, port: 4}
            5:
                stack: {dp: s3, port: 5}
            6:
                stack: {dp: s3, port: 6}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                name: source_host
                native_vlan: vlan100
                acls_in: [transit_acl]
            3:
                stack: {dp: s1, port: 3}
            4:
                stack: {dp: s1, port: 4}
    s3:
        dp_id: 0x3
        hardware: 'GenericTFM'
        interfaces:
            1:
                name: destination_host
                native_vlan: vlan100
            5:
                stack: {dp: s1, port: 5}
            6:
                stack: {dp: s1, port: 6}
"""

    def test_update_transit_tunnel(self):
        """Test a tunnel through a transit switch (forwards to the correct switch)"""
        valve = self.valves_manager.valves[0x1]
        port1 = valve.dp.ports[3]
        port2 = valve.dp.ports[5]
        # Apply tunnel to ofmsgs on valve
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        # Should accept packet from stack and output to the next switch
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            3, self.TRANSIT_ID, 5, self.TRANSIT_ID, True,
            'Did not output to next switch',
            pcp=valve_of.PCP_TUNNEL_FLAG)
        # Set the chosen port down to force a recalculation on the tunnel path
        self.set_port_down(port1.number)
        # Should accept encapsulated packet and output using the new path
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            4, self.TRANSIT_ID, 5, self.TRANSIT_ID, True,
            'Did not output to next switch',
            pcp=valve_of.PCP_TUNNEL_FLAG)
        # Set the chosen port to the next switch down to force a path recalculation
        self.set_port_down(port2.number)
        ofmsgs = valve.stack_manager.add_tunnel_acls()
        self.assertTrue(ofmsgs, 'No tunnel ofmsgs returned after a topology change')
        self.apply_ofmsgs(ofmsgs)
        # Should accept encapsulated packet and output using the new path
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            4, self.TRANSIT_ID, 6, self.TRANSIT_ID, True,
            'Did not output to next switch',
            pcp=valve_of.PCP_TUNNEL_FLAG)


class ValveTestMultipleOrderedTunnel(ValveTestBases.ValveTestTunnel):  # pylint: disable=too-few-public-methods
    """Test tunnel ACL implementation with multiple hosts containing tunnel ACL"""

    TUNNEL_ID = 2

    CONFIG = """
acls:
    tunnel_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {dp: s2, port: 1}
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: vlan100
                acls_in: [tunnel_acl]
            2:
                native_vlan: vlan100
                acls_in: [tunnel_acl]
            3:
                stack: {dp: s2, port: 3}
            4:
                stack: {dp: s2, port: 4}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: vlan100
            3:
                stack: {dp: s1, port: 3}
            4:
                stack: {dp: s1, port: 4}
"""

    def test_tunnel_update_multiple_tunnels(self):
        """Test having multiple hosts with the same tunnel"""
        valve = self.valves_manager.valves[0x1]
        port = valve.dp.ports[3]
        # Apply tunnel to ofmsgs on valve
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        # Should encapsulate and output packet towards tunnel destination s3
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 3, self.TUNNEL_ID, True,
            'Did not encapsulate and forward')
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            2, 0, 3, self.TUNNEL_ID, True,
            'Did not encapsulate and forward')
        # Set the chosen port down to force a recalculation on the tunnel path
        self.set_port_down(port.number)
        ofmsgs = valve.stack_manager.add_tunnel_acls()
        self.assertTrue(ofmsgs, 'No tunnel ofmsgs returned after a topology change')
        self.apply_ofmsgs(ofmsgs)
        # Should encapsulate and output packet using the new path
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 4, self.TUNNEL_ID, True,
            'Did not encapsulate and forward out re-calculated port')
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 4, self.TUNNEL_ID, True,
            'Did not encapsulate and forward out re-calculated port')


class ValveTestMultipleOrderedDPTunnelACL(ValveTestBases.ValveTestTunnel):  # pylint: disable=too-few-public-methods
    """Test tunnel DP ACL implementation with multiple hosts/DP containing tunnel ACL"""

    TUNNEL_ID = 2

    CONFIG = """
acls:
    tunnel_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {dp: s2, port: 1}
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        dp_acls: [tunnel_acl]
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: vlan100
            2:
                native_vlan: vlan100
            3:
                stack: {dp: s2, port: 3}
            4:
                stack: {dp: s2, port: 4}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: vlan100
                acls_in: [tunnel_acl]
            3:
                stack: {dp: s1, port: 3}
            4:
                stack: {dp: s1, port: 4}
"""

    def test_tunnel_update_multiple_tunnels(self):
        """Test having multiple hosts with the same tunnel"""
        valve = self.valves_manager.valves[0x1]
        port = valve.dp.ports[3]
        # Apply tunnel to ofmsgs on valve
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        # Should encapsulate and output packet towards tunnel destination s3
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 3, self.TUNNEL_ID, True,
            'Did not encapsulate and forward')
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            2, 0, 3, self.TUNNEL_ID, True,
            'Did not encapsulate and forward')
        # Set the chosen port down to force a recalculation on the tunnel path
        self.set_port_down(port.number)
        ofmsgs = valve.stack_manager.add_tunnel_acls()
        self.assertTrue(ofmsgs, 'No tunnel ofmsgs returned after a topology change')
        self.apply_ofmsgs(ofmsgs)
        # Should encapsulate and output packet using the new path
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 4, self.TUNNEL_ID, True,
            'Did not encapsulate and forward out re-calculated port')
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 4, self.TUNNEL_ID, True,
            'Did not encapsulate and forward out re-calculated port')


class ValveTestMultipleOrderedTunnelDestinationDPACL(
    ValveTestBases.ValveTestTunnel
):  # pylint: disable=too-few-public-methods
    """Test tunnel DP ACL implementation with a tunnel ACL with a DP destination"""

    TUNNEL_ID = 2

    CONFIG = """
acls:
    tunnel_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {dp: s2}
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        dp_acls: [tunnel_acl]
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: vlan100
            2:
                native_vlan: vlan100
            3:
                stack: {dp: s2, port: 3}
            4:
                stack: {dp: s2, port: 4}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: vlan100
                acls_in: [tunnel_acl]
            3:
                stack: {dp: s1, port: 3}
            4:
                stack: {dp: s1, port: 4}
"""

    def test_tunnel_update_multiple_dp_dest_tunnels(self):
        """Test having multiple hosts with the same tunnel"""
        valve = self.valves_manager.valves[0x1]
        port = valve.dp.ports[3]
        # Apply tunnel to ofmsgs on valve
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        # Should encapsulate and output packet towards tunnel destination s3
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 3, self.TUNNEL_ID, True,
            'Did not encapsulate and forward')
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            2, 0, 3, self.TUNNEL_ID, True,
            'Did not encapsulate and forward')
        # Set the chosen port down to force a recalculation on the tunnel path
        self.set_port_down(port.number)
        ofmsgs = valve.stack_manager.add_tunnel_acls()
        self.assertTrue(ofmsgs, 'No tunnel ofmsgs returned after a topology change')
        self.apply_ofmsgs(ofmsgs)
        # Should encapsulate and output packet using the new path
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 4, self.TUNNEL_ID, True,
            'Did not encapsulate and forward out re-calculated port')
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 4, self.TUNNEL_ID, True,
            'Did not encapsulate and forward out re-calculated port')


class ValveTestOrderedTunnelExitInstructions(ValveTestBases.ValveTestTunnel):  # pylint: disable=too-few-public-methods
    """Test tunnel DP ACL implementation with a tunnel ACL with exit instructions"""

    TUNNEL_ID = 2

    CONFIG = """
acls:
    tunnel_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {
                        dp: s2,
                        port: 1,
                        exit_instructions: [{'vlan_vid': 101}]
                    }
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: vlan100
                acls_in: [tunnel_acl]
            3:
                stack: {dp: s2, port: 3}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: vlan100
            3:
                stack: {dp: s1, port: 3}
"""

    def test_tunnel_additional_exit_instructions(self):
        """Test having additional exit instructions"""
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 3, self.TUNNEL_ID, True, 'Did not encapsulate and forward')
        self.validate_tunnel(
            int(0x2), int(0x2),
            3, self.TUNNEL_ID, 1, 101, True, 'Did not apply additional exit instructions',
            pcp=valve_of.PCP_TUNNEL_FLAG)


class ValveTestRemoteDHCPCoprocessorTunnelACL(ValveTestBases.ValveTestTunnel):  # pylint: disable=too-few-public-methods
    """Test bi_directional tunnel implementation to a remote coprocessor port with a DHCP server"""

    SW1_TUNNEL_ID = 101
    SW2_TUNNEL_ID = 102

    CONFIG = """
acls:
    sw1_dhcp:
        - rule:
            actions:
                allow: 0
                output:
                    tunnel:
                        bi_directional: true
                        dp: s01
                        maintain_encapsulation: true
                        port: 4
            in_port: 3
            dl_type: 0x800
            nw_proto: 17
            udp_dst: 67
            udp_src: 68
        - rule:
            dl_type: 0x800
            nw_proto: 17
            udp_dst: 67
            udp_src: 68
            actions:
                allow: 0
        - rule:
            dl_type: 0x800
            nw_proto: 17
            udp_dst: 68
            udp_src: 67
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
    sw2_dhcp:
        - rule:
            actions:
                allow: 0
                output:
                    tunnel:
                        bi_directional: true
                        dp: s01
                        maintain_encapsulation: true
                        port: 4
            in_port: 3
            dl_type: 0x800
            nw_proto: 17
            udp_dst: 67
            udp_src: 68
        - rule:
            dl_type: 0x800
            nw_proto: 17
            udp_dst: 67
            udp_src: 68
            actions:
                allow: 0
        - rule:
            dl_type: 0x800
            nw_proto: 17
            udp_dst: 68
            udp_src: 67
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
dps:
    s01:
        dp_acls: [sw1_dhcp]
        dp_id: 1
        hardware: 'GenericTFM'
        stack: {priority: 1}
        interfaces:
            1:
                name: b1
                stack: {dp: s02, port: 1}
            2:
                name: b2
                stack: {dp: s02, port: 2}
            3:
                name: b3
                native_vlan: vlan-1
            4:
                coprocessor:
                    strategy: vlan_vid
                name: b4
    s02:
        dp_acls: [sw2_dhcp]
        dp_id: 2
        hardware: 'GenericTFM'
        interfaces:
            1:
                name: b1
                stack: {dp: s01, port: 1}
            2:
                name: b2
                stack: {dp: s01, port: 2}
            3:
                name: b3
                native_vlan: vlan-1
vlans:
    vlan-1:
        faucet_mac: 00:00:00:00:00:11
        faucet_vips: [10.1.0.254/24]
        vid: 100
"""

    def test_tunnel_remote_bi_directional_tunnel_coprocessor(self):
        """Test having a bi_directional tunnel to a remote coprocessor"""
        dhcp_options = {
            'ip_proto': 17,
            'eth_type': 0x0800,
            'udp_dst': 67,
            'udp_src': 68}
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            3, 0, 4, self.SW1_TUNNEL_ID, True,
            'Did not encapsulate and output to coprocessor on same switch',
            packet_match=dhcp_options)
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            4, [self.SW1_TUNNEL_ID, 100], 3, 0, True,
            'Did not output reverse, return DHCP packet to host on the same switch',
            pcp=valve_of.PCP_TUNNEL_REVERSE_DIRECTION_FLAG,
            packet_match=dhcp_options)
        self.validate_tunnel(
            2, self.DP_ID,
            3, 0, 4, self.SW2_TUNNEL_ID, True,
            'Did not encapsulate and output to coprocessor on remote switch',
            packet_match=dhcp_options)
        self.validate_tunnel(
            self.DP_ID, 2,
            4, [self.SW2_TUNNEL_ID, 100], 3, 0, True,
            'Did not output reverse, return DHCP packet to host on the remote switch',
            pcp=valve_of.PCP_TUNNEL_REVERSE_DIRECTION_FLAG,
            packet_match=dhcp_options)


class ValveTestOrderedBiDirectionalTunnelACL(ValveTestBases.ValveTestTunnel):  # pylint: disable=too-few-public-methods
    """Test tunnel DP ACL implementation with a tunnel ACL with bidirectionality"""

    TUNNEL_ID = 2

    CONFIG = """
acls:
    tunnel_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {
                        dp: s2,
                        port: 1,
                        bi_directional: True
                    }
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: vlan100
                acls_in: [tunnel_acl]
            3:
                stack: {dp: s2, port: 3}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: vlan100
            3:
                stack: {dp: s1, port: 3}
"""

    def test_tunnel_bidirectionality(self):
        """Test bidirectionality on a tunnel"""
        valve = self.valves_manager.valves[0x1]
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        self.validate_tunnel(
            int(0x2), int(0x2),
            1, self.TUNNEL_ID, 3, self.TUNNEL_ID, True,
            'Did not accept reverse tunnel packet',
            pcp=valve_of.PCP_TUNNEL_REVERSE_DIRECTION_FLAG)
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            3, self.TUNNEL_ID, 1, 0, True,
            'Did not output to original source, the reverse tunnelled packet',
            pcp=valve_of.PCP_TUNNEL_REVERSE_DIRECTION_FLAG)


class ValveTestOrderedMaintainTunnelEncapsulationACL(
    ValveTestBases.ValveTestTunnel
):  # pylint: disable=too-few-public-methods
    """Test tunnel maintains encapsulation with maintain_encapsulation option"""

    TUNNEL_ID = 2

    CONFIG = """
acls:
    tunnel_acl:
        - rule:
            in_port: 1
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {
                        dp: s2,
                        port: 1,
                        maintain_encapsulation: True
                    }
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: vlan100
                acls_in: [tunnel_acl]
            3:
                stack: {dp: s2, port: 3}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: vlan100
            3:
                stack: {dp: s1, port: 3}
"""

    def test_tunnel_maintain_encapsulation(self):
        """Test having tunnel with maintain_encapsulation option, maintains encapsulation"""
        valve = self.valves_manager.valves[0x1]
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 3, self.TUNNEL_ID, True, 'Did not encapsulate and forward')
        self.validate_tunnel(
            int(0x2), int(0x2),
            3, self.TUNNEL_ID, 1, self.TUNNEL_ID, True, 'Did not maintain tunnel encapsulation',
            pcp=valve_of.PCP_TUNNEL_FLAG)


class ValveTestOrderedBiDirectionalDPTunnelACL(
    ValveTestBases.ValveTestTunnel
):  # pylint: disable=too-few-public-methods
    """Test tunnel DP ACL implementation with a tunnel DP ACL with bidirectionality"""

    TUNNEL_ID = 2

    CONFIG = """
acls:
    tunnel_acl:
        - rule:
            in_port: 1
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {
                        dp: s2,
                        port: 1,
                        bi_directional: True,
                        maintain_encapsulation: True
                    }
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        dp_acls: [tunnel_acl]
        interfaces:
            1:
                native_vlan: vlan100
            3:
                stack: {dp: s2, port: 3}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: vlan100
            3:
                stack: {dp: s1, port: 3}
"""

    def test_tunnel_bi_directional_dp_acl(self):
        """Test bi-directionality on a DP ACL"""
        valve = self.valves_manager.valves[0x1]
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        self.validate_tunnel(
            int(0x2), int(0x2),
            1, self.TUNNEL_ID, 3, self.TUNNEL_ID, True, 'Did not accept reverse tunnel packet',
            pcp=valve_of.PCP_TUNNEL_REVERSE_DIRECTION_FLAG)
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            3, [self.TUNNEL_ID, 1], 1, 0,
            True, 'Did not output to original source, the reverse tunnelled packet',
            pcp=valve_of.PCP_TUNNEL_REVERSE_DIRECTION_FLAG)


class ValveTestOrderedBidirectionalTunnelACLwithExitInstructions(
    ValveTestBases.ValveTestTunnel
):  # pylint: disable=too-few-public-methods
    """Test tunnel implementation with bi-directionality and exit instructions"""

    TUNNEL_ID = 2

    CONFIG = """
acls:
    tunnel_acl:
        - rule:
            in_port: 1
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {
                        dp: s2,
                        port: 1,
                        bi_directional: True,
                        exit_instructions: [{'vlan_vid': 101}]
                    }
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        dp_acls: [tunnel_acl]
        interfaces:
            1:
                native_vlan: vlan100
            3:
                stack: {dp: s2, port: 3}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: vlan100
            3:
                stack: {dp: s1, port: 3}
"""

    def test_tunnel_bi_directional_with_exit_instructions(self):
        """Test bi-directionality tunnel with exit instructions"""
        # The exit instructions will only apply to the forward tunnel
        valve = self.valves_manager.valves[0x1]
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            1, 0, 3, self.TUNNEL_ID, True, 'Did not encapsulate and forward')
        self.validate_tunnel(
            int(0x2), int(0x2),
            3, self.TUNNEL_ID, 1, 101, True, 'Did not apply additional exit instructions',
            pcp=valve_of.PCP_TUNNEL_FLAG)
        self.validate_tunnel(
            int(0x2), int(0x2),
            1, self.TUNNEL_ID, 3, self.TUNNEL_ID, True, 'Did not accept reverse tunnel packet',
            pcp=valve_of.PCP_TUNNEL_REVERSE_DIRECTION_FLAG)
        self.validate_tunnel(
            self.DP_ID, self.DP_ID,
            3, [self.TUNNEL_ID, 1], 1, 0,
            True, 'Did not output to original source, the reverse tunnelled packet',
            pcp=valve_of.PCP_TUNNEL_REVERSE_DIRECTION_FLAG)


class ValveTestOrderedReverseTunnelOption(ValveTestBases.ValveTestTunnel):  # pylint: disable=too-few-public-methods
    """Test tunnel implementation with reverse tunnel option"""

    TUNNEL_ID = 3

    CONFIG = """
acls:
    forward_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {
                        dp: s2,
                        port: 1,
                        tunnel_id: 3,
                    }
    reverse_acl:
        - rule:
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {
                        dp: s1,
                        port: 1,
                        tunnel_id: 3,
                        reverse: True,
                    }
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: vlan100
                acls_in: [forward_acl]
            3:
                stack: {dp: s2, port: 3}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: vlan100
                acls_in: [reverse_acl]
            3:
                stack: {dp: s1, port: 3}
"""

    def test_tunnel_reverse_option(self):
        """Test separate reverse tunnel ACL using the `reverse` tunnel option"""
        valve = self.valves_manager.valves[0x1]
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        self.validate_tunnel(
            int(0x2), int(0x2),
            1, 1, 3, self.TUNNEL_ID,
            True, 'Did not output to original source, the reverse tunnelled packet')
        self.validate_tunnel(
            int(0x1), int(0x1),
            3, self.TUNNEL_ID, 1, 0,
            True, 'Did not output to original source, the reverse tunnelled packet',
            pcp=valve_of.PCP_TUNNEL_REVERSE_DIRECTION_FLAG)


class ValveTestOrderedBiDirectionalDPACLTunnelDPDestination(
    ValveTestBases.ValveTestTunnel
):  # pylint: disable=too-few-public-methods
    """Test tunnel configured as a DP ACL with bi-directionality and destination as a DP"""

    TUNNEL_ID = 2

    CONFIG = """
acls:
    tunnel_acl:
        - rule:
            in_port: 1
            dl_type: 0x0800
            ip_proto: 1
            actions:
                output:
                    - tunnel: {
                        dp: s2,
                        bi_directional: True
                    }
vlans:
    vlan100:
        vid: 1
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        dp_acls: [tunnel_acl]
        interfaces:
            1:
                native_vlan: vlan100
            3:
                stack: {dp: s2, port: 3}
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: vlan100
            3:
                stack: {dp: s1, port: 3}
"""

    def test_dp_destination_tunnel_bi_directional_dp_acl(self):
        """Test bi-directionality on a DP ACL with DP destination"""
        valve = self.valves_manager.valves[0x1]
        self.apply_ofmsgs(valve.stack_manager.add_tunnel_acls())
        self.validate_tunnel(
            int(0x1), int(0x1),
            1, 0, 3, self.TUNNEL_ID,
            True, 'Did not encapsulate and output towards destination')
        self.validate_tunnel(
            int(0x2), int(0x2),
            3, [self.TUNNEL_ID, 1], 1, 0,
            True, 'Did not output to host as flood',
            pcp=valve_of.PCP_TUNNEL_FLAG)
        self.validate_tunnel(
            int(0x2), int(0x2),
            1, self.TUNNEL_ID, 3, self.TUNNEL_ID,
            True, 'Did not output reverse packet towards reverse destination',
            pcp=valve_of.PCP_TUNNEL_REVERSE_DIRECTION_FLAG)
        self.validate_tunnel(
            int(0x1), int(0x1),
            3, [self.TUNNEL_ID, 1], 1, 0,
            True, 'Did not output reverse packet to host as flood',
            pcp=valve_of.PCP_TUNNEL_REVERSE_DIRECTION_FLAG)
        self.validate_tunnel(
            int(0x1), int(0x1),
            3, self.TUNNEL_ID, None, None,
            False,
            'Expected a drop of the reverse tunnel packet as it fell through to the flood table without a VID',
            pcp=valve_of.PCP_TUNNEL_REVERSE_DIRECTION_FLAG)
        self.validate_tunnel(
            int(0x2), int(0x2),
            3, self.TUNNEL_ID, None, None,
            False,
            'Expected a drop of the tunnel packet as it fell through to the flood table without a VID',
            pcp=valve_of.PCP_TUNNEL_FLAG)


class ValveTwoDpRoot(ValveTestBases.ValveTestNetwork):
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

    CONFIG3 = """
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
            3:
                tagged_vlans: [100]
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
        self.setup_valves(self.CONFIG)

    def test_topo(self):
        """Test topology functions."""
        dp = self.valves_manager.valves[self.DP_ID].dp
        self.assertTrue(dp.stack.is_root())
        self.assertFalse(dp.stack.is_edge())

    def test_add_remove_port(self):
        self.update_and_revert_config(self.CONFIG, self.CONFIG3, 'warm')


class ValveTwoDpRootEdge(ValveTestBases.ValveTestNetwork):
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

    CONFIG3 = """
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
            3:
                tagged_vlans: [100]
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
        self.setup_valves(self.CONFIG)

    def test_topo(self):
        """Test topology functions."""
        dp_obj = self.valves_manager.valves[self.DP_ID].dp
        self.assertFalse(dp_obj.stack.is_root())
        self.assertTrue(dp_obj.stack.is_edge())

    def test_add_remove_port(self):
        self.update_and_revert_config(self.CONFIG, self.CONFIG3, 'warm')


class GroupDeleteACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test that a group ACL creates a groupdel for the group_id"""

    CONFIG = """
acls:
    group-acl:
        - rule:
            dl_dst: "0e:00:00:00:02:02"
            actions:
                output:
                    failover:
                        group_id: 1001
                        ports: [2, 3]
vlans:
    vlan100:
        vid: 100
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        interfaces:
            1:
                native_vlan: vlan100
                acls_in: [group-acl]
            2:
                native_vlan: vlan100
            3:
                native_vlan: vlan100
"""

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def check_groupmods_exist(self, ofmsgs, groupdel_exists=True):
        """Test that the ACL groupmods exist when expected"""
        groupdel = None
        groupmod = None
        for ofmsg in ofmsgs:
            if valve_of.is_groupdel(ofmsg) and not valve_of.is_global_groupdel(ofmsg):
                groupdel = ofmsg
            elif valve_of.is_groupmod(ofmsg):
                groupmod = ofmsg
        self.assertIsNotNone(groupmod)
        if groupdel_exists:
            self.assertIsNotNone(groupdel)
            if groupdel is not None:
                self.assertTrue(groupdel.group_id, 1001)
        else:
            self.assertIsNone(groupdel)

    def test_groupdel_exists(self):
        """Test valve_flowreorder doesn't remove groupmods unless expected"""
        valve = self.valves_manager.valves[0x1]
        port = valve.dp.ports[1]
        ofmsgs = valve.acl_manager.add_port(port)
        self.check_groupmods_exist(valve_of.valve_flowreorder(ofmsgs))
        global_flowmod = valve_of.flowmod(
            0, ofp.OFPFC_DELETE, ofp.OFPTT_ALL,
            0, ofp.OFPP_CONTROLLER, ofp.OFPP_CONTROLLER,
            valve_of.match_from_dict({}), (), 0, 0, 0)
        self.check_groupmods_exist(
            valve_of.valve_flowreorder(ofmsgs + [global_flowmod]))
        global_metermod = valve_of.meterdel()
        self.check_groupmods_exist(
            valve_of.valve_flowreorder(ofmsgs + [global_flowmod, global_metermod]))
        global_groupmod = valve_of.groupdel()
        self.check_groupmods_exist(
            valve_of.valve_flowreorder(
                ofmsgs + [global_flowmod, global_metermod, global_groupmod]), False)

    def test_all_offset(self):
        """Test groups with the redundant controller offset check for all possible offsets"""
        valve = self.valves_manager.valves[0x1]
        port = valve.dp.ports[1]
        ofmsgs = valve.acl_manager.add_port(port)
        self.apply_ofmsgs(ofmsgs, 0x1, all_offsets=True)


class ValveWarmStartStackTest(ValveTestBases.ValveTestNetwork):
    """Test warm starting stack ports"""

    CONFIG = """
vlans:
    vlan100:
        vid: 100
    vlan200:
        vid: 200
dps:
    s1:
        dp_id: 1
        hardware: 'GenericTFM'
        stack: {priority: 1}
        interfaces:
            1:
                stack: {dp: s2, port: 1}
            2:
                name: host1
                native_vlan: vlan100
            3:
                name: host2
                native_vlan: vlan200
            4:
                name: host3
                native_vlan: vlan200
    s2:
        dp_id: 2
        hardware: 'GenericTFM'
        interfaces:
            1:
                stack: {dp: s1, port: 1}
            2:
                stack: {dp: s3, port: 1}
            4:
                name: host4
                native_vlan: vlan100
            5:
                name: host5
                native_vlan: vlan200
    s3:
        dp_id: 3
        hardware: 'GenericTFM'
        interfaces:
            1:
                stack: {dp: s2, port: 2}
            3:
                name: host6
                native_vlan: vlan100
            4:
                name: host7
                native_vlan: vlan200
"""

    NEW_PORT_CONFIG = """
vlans:
    vlan100:
        vid: 100
    vlan200:
        vid: 200
dps:
    s1:
        dp_id: 1
        hardware: 'GenericTFM'
        stack: {priority: 1}
        interfaces:
            1:
                stack: {dp: s2, port: 1}
            2:
                name: host1
                native_vlan: vlan100
            3:
                name: host2
                native_vlan: vlan200
            4:
                name: host3
                native_vlan: vlan200
    s2:
        dp_id: 2
        hardware: 'GenericTFM'
        interfaces:
            1:
                stack: {dp: s1, port: 1}
            2:
                stack: {dp: s3, port: 1}
            3:
                stack: {dp: s3, port: 2}
            4:
                name: host4
                native_vlan: vlan100
            5:
                name: host5
                native_vlan: vlan200
    s3:
        dp_id: 3
        hardware: 'GenericTFM'
        interfaces:
            1:
                stack: {dp: s2, port: 2}
            2:
                stack: {dp: s2, port: 3}
            3:
                name: host6
                native_vlan: vlan100
            4:
                name: host7
                native_vlan: vlan200
"""

    NEW_VLAN_CONFIG = """
vlans:
    vlan100:
        vid: 100
    vlan200:
        vid: 200
dps:
    s1:
        dp_id: 1
        hardware: 'GenericTFM'
        stack: {priority: 1}
        interfaces:
            1:
                stack: {dp: s2, port: 1}
            2:
                name: host1
                native_vlan: vlan100
            3:
                name: host2
                native_vlan: vlan100
            4:
                name: host3
                native_vlan: vlan200
    s2:
        dp_id: 2
        hardware: 'GenericTFM'
        interfaces:
            1:
                stack: {dp: s1, port: 1}
            2:
                stack: {dp: s3, port: 1}
            4:
                name: host4
                native_vlan: vlan100
            5:
                name: host5
                native_vlan: vlan200
    s3:
        dp_id: 3
        hardware: 'GenericTFM'
        interfaces:
            1:
                stack: {dp: s2, port: 2}
            3:
                name: host6
                native_vlan: vlan100
            4:
                name: host7
                native_vlan: vlan200
"""

    def setUp(self):
        """Setup network and start stack ports"""
        self.setup_valves(self.CONFIG)

    def test_reload_topology_change_warmstart(self):
        """Test reload with topology change forces stack ports down, only warm starts"""
        self.update_and_revert_config(
            self.CONFIG, self.NEW_PORT_CONFIG, 'warm')

    def test_reload_topology_change(self):
        """Test reload with topology change forces stack ports down"""
        with open(self.config_file, 'w', encoding='utf-8') as config_file:
            config_file.write(self.NEW_PORT_CONFIG)
        new_dps = self.valves_manager.parse_configs(self.config_file)
        for new_dp in new_dps:
            valve = self.valves_manager.valves[new_dp.dp_id]
            changes = valve.dp.get_config_changes(valve.logger, new_dp)
            changed_ports, all_ports_changed = changes[1], changes[6]
            for port in valve.dp.stack_ports():
                if not all_ports_changed:
                    self.assertIn(
                        port.number, changed_ports,
                        'Stack port not detected as changed on topology change')

    def test_reload_vlan_change_warmstart(self):
        """Test reload with topology change, only do a warm start"""
        valve = self.valves_manager.valves[1]
        self.assertEqual(valve.dp.ports[3].native_vlan.vid, 200)
        self.assertTrue(valve.dp.ports[3].dyn_update_time)

        # DPID 1 Port 3 changes vlan from 200, to 100, back to 200
        self.update_and_revert_config(
            self.CONFIG, self.NEW_VLAN_CONFIG, 'warm',
            verify_func=lambda: self.assertEqual(valve.dp.ports[3].native_vlan.vid, 100))

        self.assertTrue(valve.dp.ports[3].dyn_update_time)
        self.assertEqual(valve.dp.ports[3].native_vlan.vid, 200)

    def test_reload_vlan_change(self):
        """Test reload with topology change, stack ports stay up"""
        with open(self.config_file, 'w', encoding='utf-8') as config_file:
            config_file.write(self.NEW_VLAN_CONFIG)
        new_dps = self.valves_manager.parse_configs(self.config_file)
        for new_dp in new_dps:
            valve = self.valves_manager.valves[new_dp.dp_id]
            changed = valve.dp.get_config_changes(valve.logger, new_dp)
            changed_ports = changed[1]
            for port in valve.dp.stack_ports():
                self.assertNotIn(
                    port.number, changed_ports,
                    'Stack port detected as changed on non-topology change')


class ValveStackHealthTest(ValveTestBases.ValveTestNetwork):
    """Test stack root health metrics"""

    UPDATE_TIME = 10

    CONFIG = """
vlans:
    vlan100:
        vid: 100
dps:
    sw1:
        hardware: 'GenericTFM'
        dp_id: 1
        stack: {priority: 1, down_time_multiple: 1}
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw2, port: 2}
            3:
                stack: {dp: sw3, port: 2}
            4:
                native_vlan: vlan100
                lacp: 1
            5:
                native_vlan: vlan100
                lacp: 1
            6:
                stack: {dp: sw2, port: 3}
            7:
                stack: {dp: sw3, port: 3}
    sw2:
        hardware: 'GenericTFM'
        dp_id: 2
        stack: {priority: 2, down_time_multiple: 2}
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw1, port: 2}
            3:
                stack: {dp: sw1, port: 6}
            4:
                native_vlan: vlan100
                lacp: 1
            5:
                native_vlan: vlan100
                lacp: 1
            6:
                native_vlan: vlan100
                lacp: 2
            7:
                native_vlan: vlan100
                lacp: 2
    sw3:
        hardware: 'GenericTFM'
        dp_id: 3
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw1, port: 3}
            3:
                stack: {dp: sw1, port: 7}
"""

    def setUp(self):
        """Start network for test"""
        self.setup_valves(self.CONFIG)

    def test_timeout(self):
        """Test stack health on health timeouts"""
        dps = [valve.dp for valve in self.valves_manager.valves.values()]
        for dp in dps:
            for port in dp.ports.values():
                if port.lacp:
                    port.actor_up()
                    port.select_port()
                if port.stack:
                    port.stack_up()
        last_live_times = {'sw1': 100, 'sw2': 100, 'sw3': 100}
        self.assertTrue(dps[0].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])
        self.assertFalse(dps[0].stack.update_health(
            120, last_live_times, self.UPDATE_TIME)[0])
        self.assertTrue(dps[1].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])
        self.assertFalse(dps[1].stack.update_health(
            130, last_live_times, self.UPDATE_TIME)[0])
        self.assertTrue(dps[2].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])
        self.assertFalse(dps[2].stack.update_health(
            140, last_live_times, self.UPDATE_TIME)[0])

    def test_lacp_down(self):
        """Test stack health on LACP ports being DOWN"""
        dps = [valve.dp for valve in self.valves_manager.valves.values()]
        for dp in dps:
            for port in dp.ports.values():
                if port.lacp:
                    port.actor_up()
                    port.select_port()
                if port.stack:
                    port.stack_up()
        last_live_times = {'sw1': 100, 'sw2': 100, 'sw3': 100}
        self.assertTrue(dps[0].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])
        for port in dps[0].ports.values():
            if port.lacp:
                port.actor_notconfigured()
        self.assertFalse(dps[0].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])
        self.assertTrue(dps[1].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])
        for port in dps[1].ports.values():
            if port.lacp:
                port.actor_nosync()
        self.assertFalse(dps[1].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])
        self.assertTrue(dps[2].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])

    def test_stack_port_down(self):
        """Test stack health on stack ports being DOWN"""
        dps = [valve.dp for valve in self.valves_manager.valves.values()]
        for dp in dps:
            for port in dp.ports.values():
                if port.lacp:
                    port.actor_up()
                    port.select_port()
                if port.stack:
                    port.stack_up()
        last_live_times = {'sw1': 100, 'sw2': 100, 'sw3': 100}
        self.assertTrue(dps[0].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])
        for port in dps[0].ports.values():
            if port.stack:
                port.stack_bad()
        self.assertFalse(dps[0].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])
        self.assertTrue(dps[1].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])
        for port in dps[1].ports.values():
            if port.stack:
                port.stack_gone()
        self.assertFalse(dps[1].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])
        self.assertTrue(dps[2].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])
        for port in dps[2].ports.values():
            if port.stack:
                port.stack_admin_down()
        self.assertFalse(dps[2].stack.update_health(
            110, last_live_times, self.UPDATE_TIME)[0])


class ValveVariableRootHealthTest(ValveTestBases.ValveTestNetwork):
    """Test stack root health metrics"""

    UPDATE_TIME = 10

    CONFIG = """
vlans:
    vlan100:
        vid: 100
dps:
    sw1:
        hardware: 'GenericTFM'
        dp_id: 1
        stack: {priority: 1, down_time_multiple: 1, min_stack_health: 0.5, min_lacp_health: 0.1}
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw2, port: 2}
            3:
                stack: {dp: sw3, port: 2}
            4:
                native_vlan: vlan100
                lacp: 1
            5:
                native_vlan: vlan100
                lacp: 1
            6:
                stack: {dp: sw2, port: 3}
            7:
                stack: {dp: sw3, port: 3}
    sw2:
        hardware: 'GenericTFM'
        dp_id: 2
        stack: {priority: 2, down_time_multiple: 2, min_stack_health: 0.1, min_lacp_health: 0.5}
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw1, port: 2}
            3:
                stack: {dp: sw1, port: 6}
            4:
                native_vlan: vlan100
                lacp: 1
            5:
                native_vlan: vlan100
                lacp: 1
            6:
                native_vlan: vlan100
                lacp: 2
            7:
                native_vlan: vlan100
                lacp: 2
    sw3:
        hardware: 'GenericTFM'
        dp_id: 3
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw1, port: 3}
            3:
                stack: {dp: sw1, port: 7}
"""

    def setUp(self):
        """Start network for test"""
        self.setup_valves(self.CONFIG)

    def other_valves(self, root_valve):
        return [valve for valve in self.valves_manager.valves.values() if valve != root_valve]

    def test_sw3_lacp(self):
        """Test LACP health metrics with SW3"""
        dps = [valve.dp for valve in self.valves_manager.valves.values()]
        for dp in dps:
            for port in dp.ports.values():
                if port.lacp:
                    port.actor_up()
                    port.select_port()
                if port.stack:
                    port.stack_up()
        last_live_times = {'sw1': 100, 'sw2': 100, 'sw3': 100}
        # SW3 has no LACP ports, so LACP health percentage should be 0.0,
        #   but overall should be considered healthy
        dps[2].stack.update_health(100, last_live_times, self.UPDATE_TIME)
        self.assertEqual(dps[2].stack.dyn_healthy_info[2], 0.0)
        self.assertTrue(dps[2].stack.dyn_healthy)

    def test_sw1_lacp_down(self):
        """Test LACP health metrics with SW1"""
        dps = [valve.dp for valve in self.valves_manager.valves.values()]
        for dp in dps:
            for port in dp.ports.values():
                if port.lacp:
                    port.actor_up()
                    port.select_port()
                if port.stack:
                    port.stack_up()
        last_live_times = {'sw1': 100, 'sw2': 100, 'sw3': 100}
        # Take down some LACP ports, health percentage configured so
        #   SW1 will still be healthy
        for port in dps[0].ports.values():
            if port.lacp:
                port.actor_nosync()
                port.deselect_port()
                break
        dps[0].stack.update_health(100, last_live_times, self.UPDATE_TIME)
        self.assertEqual(dps[0].stack.dyn_healthy_info[2], 0.5)
        self.assertTrue(dps[0].stack.dyn_healthy)
        # Take down the remaining LACP ports, now unhealthy
        for port in dps[0].ports.values():
            if port.lacp:
                port.actor_nosync()
                port.deselect_port()
        dps[0].stack.update_health(100, last_live_times, self.UPDATE_TIME)
        self.assertEqual(dps[0].stack.dyn_healthy_info[2], 0.0)
        self.assertFalse(dps[0].stack.dyn_healthy)

    def test_sw2_lacp_down(self):
        """Test LACP health metrics with SW2"""
        dps = [valve.dp for valve in self.valves_manager.valves.values()]
        for dp in dps:
            for port in dp.ports.values():
                if port.lacp:
                    port.actor_up()
                    port.select_port()
                if port.stack:
                    port.stack_up()
        last_live_times = {'sw1': 100, 'sw2': 100, 'sw3': 100}
        # Take down some LACP ports, health percentage configured
        #   so SW2 will still be healthy
        for port_num in [4, 5]:
            port = dps[1].ports[port_num]
            if port.lacp:
                port.actor_nosync()
                port.deselect_port()
        dps[1].stack.update_health(100, last_live_times, self.UPDATE_TIME)
        self.assertEqual(dps[1].stack.dyn_healthy_info[2], 0.5)
        self.assertTrue(dps[1].stack.dyn_healthy)
        # Take down the remaining LACP ports
        for port_num in [6]:
            port = dps[1].ports[port_num]
            if port.lacp:
                port.actor_nosync()
                port.deselect_port()
        dps[1].stack.update_health(100, last_live_times, self.UPDATE_TIME)
        self.assertEqual(dps[1].stack.dyn_healthy_info[2], 0.25)
        self.assertFalse(dps[1].stack.dyn_healthy)

    def test_sw1_stack_down(self):
        """Test stack health metrics with SW1"""
        dps = [valve.dp for valve in self.valves_manager.valves.values()]
        for dp in dps:
            for port in dp.ports.values():
                if port.lacp:
                    port.actor_up()
                    port.select_port()
                if port.stack:
                    port.stack_up()
        last_live_times = {'sw1': 100, 'sw2': 100, 'sw3': 100}
        # All switches running, stack and LACP UP
        for port_num in [2, 3]:
            port = dps[0].ports[port_num]
            if port.stack:
                port.stack_bad()
        dps[0].stack.update_health(100, last_live_times, self.UPDATE_TIME)
        self.assertEqual(dps[0].stack.dyn_healthy_info[1], 0.5)
        self.assertTrue(dps[0].stack.dyn_healthy)
        for port_num in [6]:
            port = dps[0].ports[port_num]
            if port.stack:
                port.stack_bad()
        dps[0].stack.update_health(100, last_live_times, self.UPDATE_TIME)
        self.assertEqual(dps[0].stack.dyn_healthy_info[1], 0.25)
        self.assertFalse(dps[0].stack.dyn_healthy)

    def test_sw2_stack_down(self):
        """Test stack health metrics with SW2"""
        dps = [valve.dp for valve in self.valves_manager.valves.values()]
        for dp in dps:
            for port in dp.ports.values():
                if port.lacp:
                    port.actor_up()
                    port.select_port()
                if port.stack:
                    port.stack_up()
        last_live_times = {'sw1': 100, 'sw2': 100, 'sw3': 100}
        # All switches running, stack and LACP UP
        for port_num in [2]:
            port = dps[1].ports[port_num]
            if port.stack:
                port.stack_bad()
        dps[1].stack.update_health(100, last_live_times, self.UPDATE_TIME)
        self.assertEqual(dps[1].stack.dyn_healthy_info[1], 0.5)
        self.assertTrue(dps[1].stack.dyn_healthy)
        for port_num in [3]:
            port = dps[1].ports[port_num]
            if port.stack:
                port.stack_bad()
        dps[1].stack.update_health(100, last_live_times, self.UPDATE_TIME)
        self.assertEqual(dps[1].stack.dyn_healthy_info[1], 0.0)
        self.assertFalse(dps[1].stack.dyn_healthy)


class ValveRootVariableNominationTest(ValveStackHealthTest):
    """Test ValveStackManager root nomination calculations"""

    UPDATE_TIME = 10

    CONFIG = """
vlans:
    vlan100:
        vid: 100
dps:
    sw1:
        hardware: 'GenericTFM'
        dp_id: 1
        stack: {priority: 1, down_time_multiple: 1, min_stack_health: 0.5, min_lacp_health: 0.1}
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw2, port: 2}
            3:
                stack: {dp: sw3, port: 2}
            4:
                native_vlan: vlan100
                lacp: 1
            5:
                native_vlan: vlan100
                lacp: 1
            6:
                stack: {dp: sw2, port: 3}
            7:
                stack: {dp: sw3, port: 3}
    sw2:
        hardware: 'GenericTFM'
        dp_id: 2
        stack: {priority: 2, down_time_multiple: 2, min_stack_health: 0.1, min_lacp_health: 0.5}
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw1, port: 2}
            3:
                stack: {dp: sw1, port: 6}
            4:
                native_vlan: vlan100
                lacp: 1
            5:
                native_vlan: vlan100
                lacp: 1
            6:
                native_vlan: vlan100
                lacp: 2
            7:
                native_vlan: vlan100
                lacp: 2
    sw3:
        hardware: 'GenericTFM'
        dp_id: 3
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw1, port: 3}
            3:
                stack: {dp: sw1, port: 7}
"""

    def setUp(self):
        """Start network for test"""
        self.setup_valves(self.CONFIG)

    def other_valves(self, root_valve):
        return [valve for valve in self.valves_manager.valves.values() if valve != root_valve]

    def test_lacp_root_nomination(self):
        """Test root selection health"""
        dps = [valve.dp for valve in self.valves_manager.valves.values()]
        for dp in dps:
            for port in dp.ports.values():
                if port.lacp:
                    port.actor_up()
                    port.select_port()
                if port.stack:
                    port.stack_up()
        valves = self.valves_manager.valves
        last_live_times = {'sw1': 100, 'sw2': 100, 'sw3': 100}
        # Start not root currently selected, all valves should select root sw1
        for valve in valves.values():
            self.assertEqual(valve.stack_manager.nominate_stack_root(
                None, list(valves.values()), 100, last_live_times, self.UPDATE_TIME), 'sw1')
        # Create some LACP ports DOWN, but maintain above the health threshold, Equal percentage
        #   of LACP ports taken down so LACP stays the same
        for port_num in [4]:
            port = dps[0].ports[port_num]
            port.actor_nosync()
        for port_num in [4, 5]:
            port = dps[1].ports[port_num]
            port.actor_nosync()
        for valve in valves.values():
            self.assertEqual(valve.stack_manager.nominate_stack_root(
                None, list(valves.values()), 100, last_live_times, self.UPDATE_TIME), 'sw1')
        # Change it so SW2 has greater percentage of LACP ports UP, so should be elected
        for port_num in [4]:
            port = dps[1].ports[port_num]
            port.actor_up()
        for valve in valves.values():
            self.assertEqual(valve.stack_manager.nominate_stack_root(
                None, list(valves.values()), 100, last_live_times, self.UPDATE_TIME), 'sw2')
        # Stats of Sw1 and Sw2 the same, should choose lower priority: SW1
        for port_num in [4]:
            port = dps[1].ports[port_num]
            port.actor_nosync()
        for valve in valves.values():
            self.assertEqual(valve.stack_manager.nominate_stack_root(
                None, list(valves.values()), 100, last_live_times, self.UPDATE_TIME), 'sw1')
        # SW2 considered DOWN, so should only nominate SW1
        for port_num in [4, 5]:
            port = dps[1].ports[port_num]
            port.actor_nosync()
        for valve in valves.values():
            self.assertEqual(valve.stack_manager.nominate_stack_root(
                None, list(valves.values()), 100, last_live_times, self.UPDATE_TIME), 'sw1')

    def test_stack_root_nomination(self):
        """Test root selection health"""
        dps = [valve.dp for valve in self.valves_manager.valves.values()]
        for dp in dps:
            for port in dp.ports.values():
                if port.lacp:
                    port.actor_up()
                    port.select_port()
                if port.stack:
                    port.stack_up()
        valves = self.valves_manager.valves
        last_live_times = {'sw1': 100, 'sw2': 100, 'sw3': 100}
        # Start not root currently selected, all valves should select root sw1
        for valve in valves.values():
            self.assertEqual(valve.stack_manager.nominate_stack_root(
                None, list(valves.values()), 100, last_live_times, self.UPDATE_TIME), 'sw1')
        # Create some stack ports DOWN, but maintain above the health threshold, Equal percentage
        #   of stack ports taken down so stack stays the same
        for port_num in [2]:
            port = dps[1].ports[port_num]
            port.stack_bad()
        for port_num in [2, 3]:
            port = dps[0].ports[port_num]
            port.stack_bad()
        for valve in valves.values():
            self.assertEqual(valve.stack_manager.nominate_stack_root(
                None, list(valves.values()), 100, last_live_times, self.UPDATE_TIME), 'sw1')
        # Change it so SW2 has greater percentage of stack ports UP, so should be elected
        for port_num in [2]:
            port = dps[1].ports[port_num]
            port.stack_up()
        for valve in valves.values():
            self.assertEqual(valve.stack_manager.nominate_stack_root(
                None, list(valves.values()), 100, last_live_times, self.UPDATE_TIME), 'sw2')


class ValveRootNominationTest(ValveStackHealthTest):
    """Test ValveStackManager root nomination calculations"""

    UPDATE_TIME = 10

    CONFIG = """
vlans:
    vlan100:
        vid: 100
dps:
    sw1:
        hardware: 'GenericTFM'
        dp_id: 1
        stack: {priority: 1, down_time_multiple: 1}
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw2, port: 2}
            3:
                stack: {dp: sw3, port: 2}
            4:
                native_vlan: vlan100
                lacp: 1
            5:
                native_vlan: vlan100
                lacp: 1
            6:
                stack: {dp: sw2, port: 3}
            7:
                stack: {dp: sw3, port: 3}
    sw2:
        hardware: 'GenericTFM'
        dp_id: 2
        stack: {priority: 2, down_time_multiple: 2}
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw1, port: 2}
            3:
                stack: {dp: sw1, port: 6}
            4:
                native_vlan: vlan100
                lacp: 1
            5:
                native_vlan: vlan100
                lacp: 1
            6:
                native_vlan: vlan100
                lacp: 2
            7:
                native_vlan: vlan100
                lacp: 2
    sw3:
        hardware: 'GenericTFM'
        dp_id: 3
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw1, port: 3}
            3:
                stack: {dp: sw1, port: 7}
"""

    def setUp(self):
        """Start network for test"""
        self.setup_valves(self.CONFIG)

    def other_valves(self, root_valve):
        """Return a list of the other valves"""
        return [valve for valve in self.valves_manager.valves.values() if valve != root_valve]

    def test_root_nomination(self):
        """Test root selection health"""
        dps = [valve.dp for valve in self.valves_manager.valves.values()]
        for dp in dps:
            for port in dp.ports.values():
                if port.lacp:
                    port.actor_up()
                    port.select_port()
                if port.stack:
                    port.stack_up()
        valves = self.valves_manager.valves
        last_live_times = {'sw1': 100, 'sw2': 100, 'sw3': 100}
        # Start not root currently selected, all valves should select root sw1
        for valve in valves.values():
            self.assertEqual(valve.stack_manager.nominate_stack_root(
                None, list(valves.values()), 100, last_live_times, self.UPDATE_TIME), 'sw1')
        # timeout SW1, all valves should select sw2
        for valve in valves.values():
            self.assertEqual(valve.stack_manager.nominate_stack_root(
                valves[1], self.other_valves(valves[1]), 111,
                last_live_times, self.UPDATE_TIME), 'sw2')
        # timeout sw2, should return None because there are no healthy switches
        for valve in valves.values():
            self.assertEqual(valve.stack_manager.nominate_stack_root(
                valves[2], self.other_valves(valves[2]),
                121, last_live_times, self.UPDATE_TIME), None)
        # timeout sw1, despite being unhealthy, all valves should select sw2
        for port in valves[2].dp.ports.values():
            if port.stack:
                port.stack_bad()
        for valve in valves.values():
            self.assertEqual(valve.stack_manager.nominate_stack_root(
                valves[1], self.other_valves(valves[1]), 111,
                last_live_times, self.UPDATE_TIME), 'sw2')

    def test_consistent_roots(self):
        """Test inconsistent root detection"""
        valves = self.valves_manager.valves
        for valve in valves.values():
            valve.dp.stack.root_name = 'sw1'
        for valve in valves.values():
            self.assertTrue(valve.stack_manager.consistent_roots(
                'sw1', valve, self.other_valves(valve)))
        valves[1].dp.stack.root_name = 'sw2'
        for valve in valves.values():
            self.assertFalse(valve.stack_manager.consistent_roots(
                'sw1', valve, self.other_valves(valve)))


class ValveStackConfigTest(ValveTestBases.ValveTestNetwork):
    """Test recompiling Stack into YAML config object"""

    CONFIG = """
vlans:
    vlan100:
        vid: 100
dps:
    sw1:
        hardware: 'GenericTFM'
        dp_id: 1
        stack: {priority: 1, down_time_multiple: 1}
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw2, port: 2}
            3:
                stack: {dp: sw3, port: 2}
            4:
                native_vlan: vlan100
                lacp: 1
            5:
                native_vlan: vlan100
                lacp: 1
            6:
                stack: {dp: sw2, port: 3}
            7:
                stack: {dp: sw3, port: 3}
    sw2:
        hardware: 'GenericTFM'
        dp_id: 2
        stack: {priority: 2, down_time_multiple: 2}
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw1, port: 2}
            3:
                stack: {dp: sw1, port: 6}
            4:
                native_vlan: vlan100
                lacp: 1
            5:
                native_vlan: vlan100
                lacp: 1
            6:
                native_vlan: vlan100
                lacp: 2
            7:
                native_vlan: vlan100
                lacp: 2
    sw3:
        hardware: 'GenericTFM'
        dp_id: 3
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack: {dp: sw1, port: 3}
            3:
                stack: {dp: sw1, port: 7}
"""

    def setUp(self):
        """Start network for test"""
        self.setup_valves(self.CONFIG)

    def test_stack(self):
        """Test getting config for stack with correct config"""
        dp = self.valves_manager.valves[1].dp
        stack_conf = yaml.safe_load(dp.stack.to_conf())
        self.assertIsInstance(stack_conf, dict)
        self.assertIn('priority', stack_conf)
        self.assertIn('down_time_multiple', stack_conf)
        self.assertIn('route_learning', stack_conf)
        self.assertNotIn('dyn_healthy', stack_conf)
        self.assertNotIn('canonical_port_order', stack_conf)
        self.assertNotIn('graph', stack_conf)
        self.assertNotIn('name', stack_conf)

    def test_dp_stack(self):
        """Test getting config for DP with correct subconfig stack"""
        dp = self.valves_manager.valves[1].dp
        dp_conf = yaml.safe_load(dp.to_conf())
        stack_conf = yaml.safe_load(dp.stack.to_conf())
        self.assertIn('stack', dp_conf)
        self.assertIsInstance(dp_conf['stack'], dict)
        self.assertEqual(dp_conf['stack'], stack_conf)


class ValveStackLLDPRestartTestCase(ValveTestBases.ValveTestNetwork):
    """Test restarting stacked LLDP"""

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
    s2:
        hardware: 'GenericTFM'
        dp_id: 0x2
        stack:
            priority: 1
        interfaces:
            1:
                description: p1
                stack:
                    dp: s1
                    port: 1
            2:
                description: p2
                native_vlan: 100
""" % BASE_DP1_CONFIG

    def setUp(self):
        """Setup basic loop config"""
        self.setup_valves(self.CONFIG)

    def test_lldp_cold_start(self):
        """Test cold-starting a switch preserves LLDP states"""
        self.migrate_stack_root('s1')
        self.activate_all_ports()
        valve = self.valves_manager.valves[0x1]
        old_port = valve.dp.ports[1]
        self.assertTrue(old_port.is_stack_up(), 'Port stack not UP')
        init_events = self.get_events()
        init_ports = [event for event in init_events if 'PORTS_STATUS' in event]
        self.assertEqual(2, len(init_ports), 'Expected 2 PORTS_STATUS events')

        self.migrate_stack_root('s2')
        migrate_events = self.get_events()

        def is_coldstart(event):
            return 'CONFIG_CHANGE' in event and event['CONFIG_CHANGE']['restart_type'] == 'cold'
        migrate_coldstarts = [event for event in migrate_events if is_coldstart(event)]
        self.assertEqual(2, len(migrate_coldstarts), 'Expected 2 coldstart events')

        migrate_stack = [event for event in migrate_events if 'STACK_STATE' in event]
        self.assertEqual(0, len(migrate_stack), 'Expected 0 stack state events')

        migrate_topo = [event for event in migrate_events if 'STACK_TOPO_CHANGE' in event]
        self.assertEqual(2, len(migrate_topo), 'Expected 2 topo change events')

        new_port = valve.dp.ports[1]
        self.assertNotEqual(id(old_port), id(new_port), 'Port object not changed')
        self.assertTrue(new_port.is_stack_up(), 'Port stack not UP')


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
