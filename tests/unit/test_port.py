"""Unit tests for Port"""

import unittest

from faucet.port import Port

class MockVLAN(object): # pylint: disable=too-few-public-methods
    """Mock class for VLAN so we can inject into Port"""

    def __init__(self, name):
        self.name = name


class FaucetPortConfigTest(unittest.TestCase): # pytype: disable=module-attr
    """Test that Port serialises config as it receives it"""

    def setUp(self):
        """Defines the default config - this should match the documentation"""

        self.default_config = {
            'acl_in': None,
            'acls_in': None,
            'description': None,
            'enabled': True,
            'hairpin': False,
            'lacp': 0,
            'lldp_beacon': {},
            'loop_protect': False,
            'max_hosts': 255,
            'mirror': None,
            # .to_conf() doesn't export name
            'native_vlan': None,
            'number': None,
            'opstatus_reconf': True,
            'output_only': False,
            'override_output_port': None,
            'permanent_learn': False,
            'receive_lldp': False,
            'stack': None,
            'tagged_vlans': [],
            'unicast_flood': True
        }

    def test_basic_config(self):
        """Tests the minimal config"""

        port_number = 1
        port_key = 1

        input_config = {}
        output_config = {
            'description': str(port_key),
            'number': port_number
        }

        expected_config = self.default_config
        expected_config.update(input_config)
        expected_config.update(output_config)

        port = Port(port_key, 1, input_config)
        output_config = port.to_conf()

        self.assertEqual(output_config, expected_config)

        key_exceptions = [
            'name',
            '_id',
            'dp_id',
            'dyn_phys_up'
        ]
        dict_keys = set(port.__dict__.keys())
        conf_keys = set(port.to_conf().keys())

        for exception in key_exceptions:
            dict_keys.remove(exception)

        self.assertEqual(dict_keys, conf_keys)

    def test_config_with_port_number(self):
        """Tests the minimal config"""

        port_number = 1
        port_key = 'port_1'

        input_config = {
            'number': port_number
        }
        output_config = {
            'description': str(port_key),
            'number': port_number
        }

        expected_config = self.default_config
        expected_config.update(input_config)
        expected_config.update(output_config)

        port = Port(port_key, 1, input_config)
        output_config = port.to_conf()

        self.assertEqual(output_config, expected_config)

    def test_config_with_vlans(self):
        """Tests the config with tagged and native vlans"""

        vlan100 = MockVLAN('v100')
        vlan200 = MockVLAN('v200')
        vlan300 = MockVLAN('v300')

        tagged_vlans = [vlan200, vlan300]
        native_vlan = vlan100

        port_number = 1
        port_key = 'port_1'

        input_config = {
            'number': port_number
        }
        output_config = {
            'description': str(port_key),
            'number': port_number,
            'native_vlan': vlan100.name,
            'tagged_vlans': [vlan200.name, vlan300.name]
        }

        expected_config = self.default_config
        expected_config.update(input_config)
        expected_config.update(output_config)

        port = Port(port_key, 1, input_config)
        port.native_vlan = native_vlan
        port.tagged_vlans = tagged_vlans

        output_config = port.to_conf()

        self.assertEqual(output_config, expected_config)


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
        self.assertEqual(port.vlans(), [native_vlan])
        port.tagged_vlans = tagged_vlans
        self.assertEqual(set(port.vlans()), set([native_vlan] + tagged_vlans))
        port.native_vlan = None
        self.assertEqual(set(port.vlans()), set(tagged_vlans))
