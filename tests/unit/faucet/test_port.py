"""Unit tests for Port"""

import unittest

from faucet.port import Port
from faucet.port import (
    LACP_STATE_NONE, LACP_ACTOR_INIT, LACP_ACTOR_UP, LACP_ACTOR_NOACT,
    LACP_PORT_UNSELECTED, LACP_PORT_SELECTED, LACP_PORT_STANDBY)


class MockVLAN(object):  # pylint: disable=too-few-public-methods
    """Mock class for VLAN so we can inject into Port"""

    def __init__(self, name):
        self.name = name


class FaucetPortMethodTest(unittest.TestCase):  # pytype: disable=module-attr
    """Test a range of methods on Port"""

    def test_vlans(self):
        """Test that the vlans() method behaves correctly"""

        vlan100 = MockVLAN('v100')
        vlan200 = MockVLAN('v200')
        vlan300 = MockVLAN('v300')

        tagged_vlans = [vlan200, vlan300]
        native_vlan = vlan100

        port = Port(1, 1, {})
        port.native_vlan = native_vlan
        self.assertIn(native_vlan, port.vlans())
        port.tagged_vlans = tagged_vlans
        self.assertEqual(set(port.vlans()), set([native_vlan] + tagged_vlans))
        port.native_vlan = None
        self.assertEqual(set(port.vlans()), set(tagged_vlans))


class FaucetLACPPortFunctions(unittest.TestCase):  # pytype: disable=module-attr
    """Test port LACP state functions work as expected"""

    def test_lacp_update(self):
        """Test updating port LACP information causes correct actor state changes"""
        port = Port(1, 1, {})
        port.dyn_phys_up = True
        # Initial state: Not configured
        self.assertEqual(port.dyn_lacp_port_selected, LACP_STATE_NONE)
        self.assertEqual(port.dyn_lacp_actor_state, LACP_STATE_NONE)
        # Initializing
        port.lacp_update(True, None, None)
        self.assertEqual(port.dyn_lacp_actor_state, LACP_ACTOR_INIT)
        # Receiving first packets but no sync
        port.lacp_update(False, 1, 1)
        self.assertEqual(port.dyn_lacp_actor_state, LACP_ACTOR_NOACT)
        # Receiving sync packets
        port.lacp_update(True, 1, 1)
        self.assertEqual(port.dyn_lacp_actor_state, LACP_ACTOR_UP)

    def test_lacp_flags(self):
        """Test port LACP flags returns correct flags for current port states"""
        port = Port(1, 1, {})
        # LACP config option to force flags on
        port.lacp_collect_and_distribute = True
        self.assertEqual(port.get_lacp_flags(), (1, 1, 1))
        port.lacp_collect_and_distribute = False
        # Port is selected, so flags should be on
        port.dyn_lacp_port_selected = LACP_PORT_SELECTED
        self.assertEqual(port.get_lacp_flags(), (1, 1, 1))
        # Port in standby, only allow sync
        port.dyn_lacp_port_selected = LACP_PORT_STANDBY
        self.assertEqual(port.get_lacp_flags(), (1, 0, 0))
        # Port not in standby, or selected
        port.dyn_lacp_port_selected = LACP_PORT_UNSELECTED
        self.assertEqual(port.get_lacp_flags(), (0, 0, 0))
        port.dyn_lacp_port_selected = LACP_STATE_NONE
        self.assertEqual(port.get_lacp_flags(), (0, 0, 0))


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr
