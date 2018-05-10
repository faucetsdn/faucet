"""Unit tests for VLAN"""

import unittest

from faucet.vlan import VLAN

class FaucetVLANConfigTest(unittest.TestCase):
    """Test that VLAN serialises config as it receives it"""

    def setUp(self):
        """Defines the default config - this should match the documentation"""

        self.default_config = {
            'acl_in': None,
            'acls_in': None,
            'bgp_as': None,
            'bgp_connect_mode': 'both',
            'bgp_local_address': None,
            'bgp_neighbour_addresses': [],
            'bgp_neighbour_as': None,
            'bgp_port': 9179,
            'bgp_routerid': None,
            'bgp_server_addresses': ['0.0.0.0', '::'],
            'description': None,
            'faucet_mac': '0e:00:00:00:00:01',
            'faucet_vips': [],
            'max_hosts': 255,
            'minimum_ip_size_check': True,
            'proactive_arp_limit': 2052,
            'proactive_nd_limit': 2052,
            'routes': None,
            'targeted_gw_resolution': False,
            'unicast_flood': True,
        }

    def test_basic_config(self):
        """Tests the minimal config"""

        input_config = {
            'vid': 100
        }

        expected_config = self.default_config
        expected_config.update(input_config)

        vlan = VLAN(1, 1, input_config)
        output_config = vlan.to_conf()

        self.assertEqual(output_config, expected_config)

    def test_with_routes(self):
        """Tests a config with routes"""

        input_config = {
            'routes': [
                {'route' : {'ip_dst': '10.99.99.0/24', 'ip_gw': '10.0.0.1'}},
                {'route' : {'ip_dst': '10.99.98.0/24', 'ip_gw': '10.0.0.99'}}
            ],
            'vid': 100
        }

        expected_config = self.default_config
        expected_config.update(input_config)

        vlan = VLAN(1, 1, input_config)
        output_config = vlan.to_conf()

        self.assertEqual(output_config, expected_config)
