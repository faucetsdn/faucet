"""Unit tests for VLAN"""

import unittest
from ipaddress import ip_address, ip_network, ip_interface

from faucet.vlan import VLAN


class FaucetVLANBaseTest(unittest.TestCase): # pytype: disable=module-attr
    """Set up defaults for VLAN tests"""

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

class FaucetVLANConfigTest(FaucetVLANBaseTest):
    """Test that VLAN serialises config as it receives it"""

    default_config = None

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

        key_exceptions = [
            'name',
            'tagged',
            'dyn_gws_by_ipv',
            'dyn_host_cache_by_port',
            'dp_id',
            'bgp_neighbor_addresses',
            'bgp_neighbor_as',
            'dyn_routes_by_ipv',
            '_id',
            'dyn_neigh_cache_by_ipv',
            'dyn_ipvs',
            'dyn_bgp_ipvs',
            'dyn_host_cache',
            'dyn_faucet_vips_by_ipv',
            'dyn_bgp_neighbor_addresses_by_ipv',
            'dyn_bgp_server_addresses_by_ipv',
            'untagged'
        ]
        dict_keys = set(vlan.__dict__.keys())
        conf_keys = set(vlan.to_conf().keys())

        for exception in key_exceptions:
            dict_keys.remove(exception)

        self.assertEqual(dict_keys, conf_keys)

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

    def test_with_vips(self):
        """Tests a config with virtual IPs"""

        input_config = {
            'faucet_vips': ['10.0.0.254/24'],
            'vid': 100
        }

        expected_config = self.default_config
        expected_config.update(input_config)

        vlan = VLAN(1, 1, input_config)
        output_config = vlan.to_conf()

        self.assertEqual(output_config, expected_config)

class FaucetVLANMethodTest(FaucetVLANBaseTest):
    """Initialises VLANs with different configs and sanity checks the associated methods"""

    def setUp(self):
        """Use the default config as a base"""

        super(FaucetVLANMethodTest, self).setUp()

        self.input_config = self.default_config

    def test_ipvs_no_ips(self):
        """Tests the ipvs() method with no vips"""

        vlan = VLAN(1, 1, self.input_config)
        self.assertEqual(vlan.ipvs(), [])

    def test_ipvs_ipv4(self):
        """Tests the ipvs() method with an IPv4 vip"""

        self.input_config.update({
            'faucet_vips': ['10.0.0.254/24']
        })

        vlan = VLAN(1, 1, self.input_config)
        self.assertEqual(vlan.ipvs(), [4])

    def test_ipvs_ipv6(self):
        """Tests the ipvs() method with an IPv6 vip"""

        self.input_config.update({
            'faucet_vips': ['2001::1/16']
        })

        vlan = VLAN(1, 1, self.input_config)
        self.assertEqual(vlan.ipvs(), [6])

    def test_ipvs_ipv4_ipv6(self):
        """Tests the ipvs() method with both IPv4 and IPv6 vips"""

        self.input_config.update({
            'faucet_vips': [
                '2001::1/16',
                'fe80::1/64',
                '10.0.0.254/24'
            ]
        })

        vlan = VLAN(1, 1, self.input_config)
        self.assertEqual(set(vlan.ipvs()), set([4, 6]))

    def test_bgp_servers_change_bgp_ipvs_ipv4(self):
        """Tests the ipvs() method with an IPv4 BGP server"""

        self.input_config.update({
            'bgp_server_addresses': ['127.0.0.1']
        })

        vlan = VLAN(1, 1, self.input_config)
        self.assertEqual(vlan.bgp_ipvs(), [4])

    def test_bgp_servers_change_bgp_ipvs_ipv6(self):
        """Tests the ipvs() method with an IPv4 BGP server"""

        self.input_config.update({
            'bgp_server_addresses': ['::1']
        })

        vlan = VLAN(1, 1, self.input_config)
        self.assertEqual(vlan.bgp_ipvs(), [6])

    def test_bgp_servers_change_bgp_ipvs_both(self):
        """Tests the ipvs() method with an IPv4 BGP server"""

        self.input_config.update({
            'bgp_server_addresses': ['127.0.0.1', '::1']
        })

        vlan = VLAN(1, 1, self.input_config)
        self.assertEqual(vlan.bgp_ipvs(), [4, 6])
        self.assertEqual(vlan.bgp_server_addresses_by_ipv(4), [ip_address('127.0.0.1')])
        self.assertEqual(vlan.bgp_server_addresses_by_ipv(6), [ip_address('::1')])

    def test_faucet_vips_by_ipv_none(self):
        """Tests the faucet_vips_by_ipv() method when there are no vips"""

        vlan = VLAN(1, 1, self.input_config)
        self.assertEqual(vlan.faucet_vips_by_ipv(4), [])
        self.assertEqual(vlan.faucet_vips_by_ipv(6), [])

    def test_faucet_vips_by_ipv_both(self):
        """Tests the faucet_vips_by_ipv() method when there are both IPv4 and IPv6 vips"""

        self.input_config.update({
            'faucet_vips': [
                '2001::1/16',
                'fe80::1/64',
                '10.0.0.254/24'
            ]
        })

        vlan = VLAN(1, 1, self.input_config)
        self.assertEqual(set(vlan.faucet_vips_by_ipv(4)), set([
            ip_interface('10.0.0.254/24')
        ]))
        self.assertEqual(set(vlan.faucet_vips_by_ipv(6)), set([
            ip_interface('2001::1/16'),
            ip_interface('fe80::1/64')
        ]))

    def test_routes_by_ipv_none(self):
        """Tests the routes_by_ipv() and route_count_by_ipv() methods with no routes"""

        vlan = VLAN(1, 1, self.input_config)
        self.assertEqual(vlan.routes_by_ipv(4), {})
        self.assertEqual(vlan.routes_by_ipv(6), {})
        self.assertEqual(vlan.route_count_by_ipv(4), 0)
        self.assertEqual(vlan.route_count_by_ipv(6), 0)

    def test_routes_by_ipv_both(self):
        """Tests the routes_by_ipv() and route_count_by_ipv() methods with both
        IPv4 and IPv6 routes"""

        self.input_config.update({
            'routes': [
                {'route': {'ip_dst': '10.99.99.0/24', 'ip_gw': '10.0.0.1'}},
                {'route': {'ip_dst': '10.99.98.0/24', 'ip_gw': '10.0.0.99'}},
                {'route': {'ip_dst': '10.99.97.0/24', 'ip_gw': '10.0.0.99'}},
                {'route': {'ip_dst': 'fc00::10:0/112', 'ip_gw': 'fc00::1:1'}},
                {'route': {'ip_dst': 'fc00::20:0/112', 'ip_gw': 'fc00::1:99'}}
            ],
        })

        vlan = VLAN(1, 1, self.input_config)

        self.assertEqual(vlan.routes_by_ipv(4), {
            ip_network('10.99.99.0/24'): ip_address('10.0.0.1'),
            ip_network('10.99.98.0/24'): ip_address('10.0.0.99'),
            ip_network('10.99.97.0/24'): ip_address('10.0.0.99'),
        })
        self.assertEqual(vlan.routes_by_ipv(6), {
            ip_network('fc00::10:0/112'): ip_address('fc00::1:1'),
            ip_network('fc00::20:0/112'): ip_address('fc00::1:99'),
        })
        self.assertEqual(vlan.route_count_by_ipv(4), 3)
        self.assertEqual(vlan.route_count_by_ipv(6), 2)

    def test_modify_routes_v4(self):
        """Tests the add_route() and remove_route() methods with IPv4 routes"""

        vlan = VLAN(1, 1, self.input_config)

        self.assertEqual(vlan.routes_by_ipv(4), {})
        vlan.add_route(ip_network('10.99.99.0/24'), ip_address('10.0.0.1'))
        vlan.add_route(ip_network('10.99.98.0/24'), ip_address('10.0.0.99'))
        self.assertEqual(vlan.routes_by_ipv(4), {
            ip_network('10.99.99.0/24'): ip_address('10.0.0.1'),
            ip_network('10.99.98.0/24'): ip_address('10.0.0.99')
        })
        self.assertEqual(vlan.route_count_by_ipv(4), 2)
        vlan.del_route(ip_network('10.99.99.0/24'))
        self.assertEqual(vlan.routes_by_ipv(4), {
            ip_network('10.99.98.0/24'): ip_address('10.0.0.99')
        })
        self.assertEqual(vlan.route_count_by_ipv(4), 1)
        vlan.del_route(ip_network('10.99.98.0/24'))
        self.assertEqual(vlan.route_count_by_ipv(4), 0)
        self.assertEqual(vlan.routes_by_ipv(4), {})

    def test_modify_routes_v6(self):
        """Tests the add_route() and remove_route() methods with IPv4 routes"""

        vlan = VLAN(1, 1, self.input_config)

        self.assertEqual(vlan.routes_by_ipv(6), {})
        vlan.add_route(ip_network('fc00::10:0/112'), ip_address('fc00::1:1'))
        vlan.add_route(ip_network('fc00::20:0/112'), ip_address('fc00::1:99'))
        self.assertEqual(vlan.routes_by_ipv(6), {
            ip_network('fc00::10:0/112'): ip_address('fc00::1:1'),
            ip_network('fc00::20:0/112'): ip_address('fc00::1:99')
        })
        self.assertEqual(vlan.route_count_by_ipv(6), 2)
        vlan.del_route(ip_network('fc00::10:0/112'))
        self.assertEqual(vlan.routes_by_ipv(6), {
            ip_network('fc00::20:0/112'): ip_address('fc00::1:99')
        })
        self.assertEqual(vlan.route_count_by_ipv(6), 1)
        vlan.del_route(ip_network('fc00::20:0/112'))
        self.assertEqual(vlan.route_count_by_ipv(6), 0)
        self.assertEqual(vlan.routes_by_ipv(6), {})

    def test_modify_routes_static_v4(self):
        """Tests the add_route() and remove_route() methods,
        starting with configured static routes for IPv4"""

        self.input_config.update({
            'routes': [
                {'route': {'ip_dst': '10.99.97.0/24', 'ip_gw': '10.0.0.99'}},
            ],
        })

        vlan = VLAN(1, 1, self.input_config)

        self.assertEqual(vlan.routes_by_ipv(4), {
            ip_network('10.99.97.0/24'): ip_address('10.0.0.99')
        })
        vlan.add_route(ip_network('10.99.99.0/24'), ip_address('10.0.0.1'))
        vlan.add_route(ip_network('10.99.98.0/24'), ip_address('10.0.0.99'))
        self.assertEqual(vlan.routes_by_ipv(4), {
            ip_network('10.99.99.0/24'): ip_address('10.0.0.1'),
            ip_network('10.99.98.0/24'): ip_address('10.0.0.99'),
            ip_network('10.99.97.0/24'): ip_address('10.0.0.99')
        })
        self.assertEqual(vlan.route_count_by_ipv(4), 3)
        vlan.del_route(ip_network('10.99.99.0/24'))
        self.assertEqual(vlan.routes_by_ipv(4), {
            ip_network('10.99.97.0/24'): ip_address('10.0.0.99'),
            ip_network('10.99.98.0/24'): ip_address('10.0.0.99')
        })
        self.assertEqual(vlan.route_count_by_ipv(4), 2)
        vlan.del_route(ip_network('10.99.98.0/24'))
        self.assertEqual(vlan.route_count_by_ipv(4), 1)
        self.assertEqual(vlan.routes_by_ipv(4), {
            ip_network('10.99.97.0/24'): ip_address('10.0.0.99')
        })

    def test_modify_routes_static_v6(self):
        """Tests the add_route() and remove_route() methods,
        starting with configured static routes for IPv6"""

        self.input_config.update({
            'routes': [
                {'route': {'ip_dst': 'fc00::30:0/112', 'ip_gw': 'fc00::1:99'}},
            ],
        })

        vlan = VLAN(1, 1, self.input_config)

        self.assertEqual(vlan.routes_by_ipv(6), {
            ip_network('fc00::30:0/112'): ip_address('fc00::1:99')
        })
        vlan.add_route(ip_network('fc00::10:0/112'), ip_address('fc00::1:1'))
        vlan.add_route(ip_network('fc00::20:0/112'), ip_address('fc00::1:99'))
        self.assertEqual(vlan.routes_by_ipv(6), {
            ip_network('fc00::10:0/112'): ip_address('fc00::1:1'),
            ip_network('fc00::20:0/112'): ip_address('fc00::1:99'),
            ip_network('fc00::30:0/112'): ip_address('fc00::1:99')
        })
        self.assertEqual(vlan.route_count_by_ipv(6), 3)
        vlan.del_route(ip_network('fc00::10:0/112'))
        self.assertEqual(vlan.routes_by_ipv(6), {
            ip_network('fc00::30:0/112'): ip_address('fc00::1:99'),
            ip_network('fc00::20:0/112'): ip_address('fc00::1:99')
        })
        self.assertEqual(vlan.route_count_by_ipv(6), 2)
        vlan.del_route(ip_network('fc00::20:0/112'))
        self.assertEqual(vlan.route_count_by_ipv(6), 1)
        self.assertEqual(vlan.routes_by_ipv(6), {
            ip_network('fc00::30:0/112'): ip_address('fc00::1:99')
        })
