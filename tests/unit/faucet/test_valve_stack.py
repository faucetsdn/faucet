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
import yaml

from ryu.lib import mac
from ryu.ofproto import ofproto_v1_3 as ofp

from faucet import valves_manager
from faucet import valve_of
from faucet.port import STACK_STATE_INIT, STACK_STATE_UP

from valve_test_lib import (
    BASE_DP1_CONFIG, CONFIG, STACK_CONFIG, STACK_LOOP_CONFIG, ValveTestBases)


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


class ValveStackRedundantLink(ValveTestBases.ValveTestSmall):
    """Check stack situations with a redundant link"""

    CONFIG = STACK_LOOP_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_loop_protect(self):
        """Basic loop protection check"""
        self.set_stack_port_up(1)
        self.set_stack_port_up(2)
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
        self.assertFalse(
            self.table.is_output(mcast_match, port=1),
            msg='mcast packet flooded root of stack via not shortest path')
        self.set_stack_port_down(2)
        self.assertFalse(
            self.table.is_output(mcast_match, port=2),
            msg='mcast packet flooded to root of stack via redundant path')
        self.assertTrue(
            self.table.is_output(mcast_match, port=1),
            msg='mcast packet not flooded root of stack')


class ValveStackNonRootExtLoopProtectTestCase(ValveTestBases.ValveTestSmall):

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
        self.assertEqual(None, self.valves_manager.valves[0x3].dp.shortest_path_port('s1'))


class ValveStackRedundancyTestCase(ValveTestBases.ValveTestSmall):
    """Valve test for root selection."""

    CONFIG = STACK_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def dp_by_name(self, dp_name):
        for valve in self.valves_manager.valves.values():
            if valve.dp.name == dp_name:
                return valve.dp
        return None

    def set_stack_all_ports_status(self, dp_name, status):
        dp = self.dp_by_name(dp_name)
        for port in dp.stack_ports:
            port.dyn_stack_current_state = status

    def test_redundancy(self):
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


class ValveStackGraphBreakTestCase(ValveTestBases.ValveTestSmall):
    """Valve test for updating the stack graph."""

    CONFIG = STACK_LOOP_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def validate_in_out(self, in_port, out_port, expected, msg):
        bcast_match = {
            'in_port': in_port,
            'eth_dst': mac.BROADCAST_STR,
            'vlan_vid': 0x1064 if in_port < 3 else 0,
            'eth_type': 0x800,
        }
        if expected:
            self.assertTrue(self.table.is_output(bcast_match, port=out_port), msg=msg)
        else:
            self.assertFalse(self.table.is_output(bcast_match, port=out_port), msg=msg)

    def validate_flooding(self, rerouted=False, portup=True):
        self.validate_in_out(1, 1, False, 'flooded out input stack port')
        self.validate_in_out(1, 2, portup, 'not flooded to stack root')
        self.validate_in_out(1, 3, portup, 'not flooded to external host')
        self.validate_in_out(2, 1, rerouted, 'flooded out other stack port')
        self.validate_in_out(2, 2, False, 'flooded out input stack port')
        self.validate_in_out(2, 3, True, 'not flooded to external host')
        self.validate_in_out(3, 1, rerouted, 'flooded out inactive port')
        self.validate_in_out(3, 2, True, 'not flooded to stack root')
        self.validate_in_out(3, 3, False, 'flooded out hairpin')

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
        config = yaml.load(self.CONFIG)
        for dp in config['dps'].values():
            for interface in dp['interfaces'].values():
                if 'stack' in interface:
                    interface['max_lldp_lost'] = new_value
        return yaml.dump(config)

    def test_max_lldp_timeout(self):
        """Check that timeout can be increased"""

        port = self.valve.dp.ports[1]

        self.activate_all_ports()
        self.validate_flooding(portup=True)

        # Deactivating the port stops simulating LLDP beacons.
        self.deactivate_stack_port(port, packets=1)

        # Should still work after only 1 interval (3 required by default)
        self.validate_flooding(portup=True)

        # Wait for 3 more cycles, so should fail now.
        self.trigger_all_ports(packets=3)

        # Validate expected normal behavior with the portup=False.
        self.validate_flooding(portup=False)

        # Restore everything and set max_lldp_lost to 100.
        self.activate_stack_port(port)
        self.validate_flooding()
        new_config = self._set_max_lldp_lost(100)
        self.update_config(new_config, reload_expected=False)
        self.activate_all_ports()
        self.validate_flooding(portup=True)

        # Like above, deactivate the port (stops LLDP beacons).
        self.deactivate_stack_port(port, packets=10)

        # After 10 packets (more than before), it should still work.
        self.validate_flooding(portup=True)

        # But, after 100 more it should now fail b/c limit is set to 100.
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

    @staticmethod
    def down_stack_port(port):
        """Force stack port DOWN"""
        peer_port = port.stack['port']
        peer_port.stack_gone()
        port.dyn_finalized = False
        port.enabled = False
        port.dyn_phys_up = False
        port.dyn_finalized = True

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


class ValveStackCollectDistributeLACPTestCase(ValveTestBases.ValveTestSmall):
    """Test stack topology with 3 electable roots and one LACP link each."""

    CONFIG = """
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                lacp: 1
                native_vlan: 100
                loop_protect_external: True
            2:
                stack:
                    dp: s2
                    port: 2
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        stack:
            priority: 2
        interfaces:
            1:
                lacp: 1
                native_vlan: 100
                loop_protect_external: True
            2:
                stack:
                    dp: s1
                    port: 2
            3:
                stack:
                    dp: s3
                    port: 2
    s3:
        dp_id: 0x3
        hardware: 'GenericTFM'
        stack:
            priority: 3
        interfaces:
            1:
                lacp: 1
                native_vlan: 100
                loop_protect_external: True
                lacp_collect_and_distribute: True
            2:
                stack:
                    dp: s2
                    port: 3
    """

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_topo(self):
        """Test topology functions."""
        dp_ids = [0x1, 0x2, 0x3]
        port = 1
        want_collect_and_distribute = [1, 0, 1]

        valves = [self.valves_manager.valves[dp_id] for dp_id in dp_ids]
        ports = [valve.dp.ports[port] for valve in valves]
        c_and_d = [valves[i].dp.lacp_collect_and_distribute(ports[i]) for i in range(0, len(dp_ids))]
        self.assertEqual(c_and_d, want_collect_and_distribute)


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
