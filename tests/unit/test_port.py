"""Unit tests for Port"""

import unittest

from faucet.port import Port

class MockVLAN(object): # pylint: disable=too-few-public-methods
    """Mock class for VLAN so we can inject into Port"""

    def __init__(self, name):
        self.name = name


class FaucetPortMethodTest(unittest.TestCase): # pytype: disable=module-attr
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


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr
