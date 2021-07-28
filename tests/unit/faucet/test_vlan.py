"""Unit tests for VLAN"""

import unittest
from ipaddress import ip_address, ip_network, ip_interface

from faucet.vlan import VLAN


class FaucetVLANMethodTest(unittest.TestCase):
    """Initialises VLANs with different configs and sanity checks the associated methods"""

    def test_ipvs_no_ips(self):
        """Tests the ipvs() method with no vips"""

        vlan = VLAN(1, 1, {})
        self.assertEqual(len(vlan.ipvs()), 0)

    def test_ipvs_ipv4(self):
        """Tests the ipvs() method with an IPv4 vip"""

        vlan_config = {
            'faucet_vips': ['10.0.0.254/24']
        }

        vlan = VLAN(1, 1, vlan_config)
        self.assertIn(4, vlan.ipvs())
        self.assertNotIn(6, vlan.ipvs())

    def test_ipvs_ipv6(self):
        """Tests the ipvs() method with an IPv6 vip"""

        vlan_config = {
            'faucet_vips': ['2001::1/16']
        }

        vlan = VLAN(1, 1, vlan_config)
        self.assertIn(6, vlan.ipvs())
        self.assertNotIn(4, vlan.ipvs())

    def test_ipvs_ipv4_ipv6(self):
        """Tests the ipvs() method with both IPv4 and IPv6 vips"""

        vlan_config = {
            'faucet_vips': [
                '2001::1/16',
                'fe80::1/64',
                '10.0.0.254/24'
            ]
        }

        vlan = VLAN(1, 1, vlan_config)
        self.assertIn(4, vlan.ipvs())
        self.assertIn(6, vlan.ipvs())

    def test_faucet_vips_by_ipv_none(self):
        """Tests the faucet_vips_by_ipv() method when there are no vips"""

        vlan = VLAN(1, 1, {})
        self.assertEqual(len(vlan.faucet_vips_by_ipv(4)), 0)
        self.assertEqual(len(vlan.faucet_vips_by_ipv(6)), 0)

    def test_faucet_vips_by_ipv_both(self):
        """Tests the faucet_vips_by_ipv() method when there are both IPv4 and IPv6 vips"""

        vlan_config = {
            'faucet_vips': [
                '2001::1/16',
                'fe80::1/64',
                '10.0.0.254/24'
            ]
        }

        vlan = VLAN(1, 1, vlan_config)
        self.assertEqual(set(vlan.faucet_vips_by_ipv(4)), set([
            ip_interface('10.0.0.254/24')
        ]))
        self.assertEqual(set(vlan.faucet_vips_by_ipv(6)), set([
            ip_interface('2001::1/16'),
            ip_interface('fe80::1/64')
        ]))

    def test_routes_by_ipv_none(self):
        """Tests the routes_by_ipv() and route_count_by_ipv() methods with no routes"""

        vlan = VLAN(1, 1, {})
        self.assertEqual(vlan.routes_by_ipv(4), {})
        self.assertEqual(vlan.routes_by_ipv(6), {})
        self.assertEqual(vlan.route_count_by_ipv(4), 0)
        self.assertEqual(vlan.route_count_by_ipv(6), 0)

    def test_routes_by_ipv_both(self):
        """Tests the routes_by_ipv() and route_count_by_ipv() methods with both
        IPv4 and IPv6 routes"""

        vlan_config = {
            'routes': [
                {'route': {'ip_dst': '10.99.99.0/24', 'ip_gw': '10.0.0.1'}},
                {'route': {'ip_dst': '10.99.98.0/24', 'ip_gw': '10.0.0.99'}},
                {'route': {'ip_dst': '10.99.97.0/24', 'ip_gw': '10.0.0.99'}},
                {'route': {'ip_dst': 'fc00::10:0/112', 'ip_gw': 'fc00::1:1'}},
                {'route': {'ip_dst': 'fc00::20:0/112', 'ip_gw': 'fc00::1:99'}}
            ],
        }

        vlan = VLAN(1, 1, vlan_config)

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

        vlan = VLAN(1, 1, {})

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

        vlan = VLAN(1, 1, {})

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

        vlan_config = {
            'routes': [
                {'route': {'ip_dst': '10.99.97.0/24', 'ip_gw': '10.0.0.99'}},
            ],
        }

        vlan = VLAN(1, 1, vlan_config)

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

        vlan_config = {
            'routes': [
                {'route': {'ip_dst': 'fc00::30:0/112', 'ip_gw': 'fc00::1:99'}},
            ],
        }

        vlan = VLAN(1, 1, vlan_config)

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


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
