"""Unit tests for FaucetBgp"""

import unittest
from unittest.mock import patch

from ipaddress import ip_address, ip_interface

from faucet.faucet_bgp import FaucetBgp


class FakeVLAN:
    """Fakes a VLAN object"""

    def __init__(self, vlan_config):
        self.dp_id = 1
        self.vid = 101
        self.vlan_config = vlan_config
        self.bgp_port = 1234
        self.bgp_as = 12345
        self.bgp_routerid = '1.1.1.1'
        self.bgp_neighbor_as = 54321

    def bgp_ipvs(self): # pylint: disable=missing-docstring
        return self.vlan_config['bgp_ipvs']

    def bgp_server_addresses_by_ipv(self, ipv): # pylint: disable=missing-docstring
        return self.vlan_config['bgp_server_addresses_by_ipv'][ipv]

    def faucet_vips_by_ipv(self, ipv): # pylint: disable=missing-docstring
        return self.vlan_config['faucet_vips_by_ipv'][ipv]

    def routes_by_ipv(self, ipv): # pylint: disable=missing-docstring
        return self.vlan_config['routes_by_ipv'][ipv]

    def bgp_neighbor_addresses_by_ipv(self, ipv): # pylint: disable=missing-docstring
        return self.vlan_config['bgp_neighbor_addresses_by_ipv'][ipv]


class FakeDP: # pylint: disable=too-few-public-methods
    """Fakes a DP object"""

    def __init__(self, vlans):
        self.vlans = vlans

    def bgp_vlans(self): # pylint: disable=missing-docstring
        return self.vlans


class FakeValve: # pylint: disable=too-few-public-methods
    """Fakes a Valve object"""

    def __init__(self, dp):
        self.dp = dp # pylint: disable=invalid-name


class FakeLogger: # pylint: disable=too-few-public-methods
    """Fakes a Ryu logger object"""

    def __init__(self):
        self.warning = None


class FaucetBgpTest(unittest.TestCase): # pytype: disable=module-attr
    """Test Faucet BGP"""

    def test_creates_one_ipv4_speaker(self):
        """Check that we create one IPv4 speaker"""

        vlan_config = {
            'bgp_server_addresses_by_ipv': {
                4: [ip_address('127.0.0.1')],
                6: []
            },
            'faucet_vips_by_ipv': {
                4: [ip_interface('10.0.0.1/24')],
                6: []
            },
            'routes_by_ipv': {
                4: {},
                6: {}
            },
            'bgp_neighbor_addresses_by_ipv': {
                4: [ip_address('172.0.0.2')],
                6: []
            },
            'bgp_ipvs': [4]
        }
        vlan = FakeVLAN(vlan_config)
        dp = FakeDP([vlan]) # pylint: disable=invalid-name
        valves = {'sw1': FakeValve(dp)}
        logger = FakeLogger()

        with patch('faucet.faucet_bgp.Beka') as beka:
            faucet_bgp = FaucetBgp(logger, None, None)
            faucet_bgp.reset(valves)

        self.assertEqual(beka.call_count, 1)

    def test_creates_one_ipv6_speaker(self):
        """Check that we create one IPv6 speaker"""

        vlan_config = {
            'bgp_server_addresses_by_ipv': {
                4: [],
                6: [ip_address('2001:db1::1')]
            },
            'faucet_vips_by_ipv': {
                4: [],
                6: [ip_interface('2001:db9::/32')]
            },
            'routes_by_ipv': {
                4: {},
                6: {}
            },
            'bgp_neighbor_addresses_by_ipv': {
                4: [],
                6: [ip_address('2001:db1::2')]
            },
            'bgp_ipvs': [6]
        }
        vlan = FakeVLAN(vlan_config)
        dp = FakeDP([vlan]) # pylint: disable=invalid-name
        valves = {'sw1': FakeValve(dp)}
        logger = FakeLogger()

        with patch('faucet.faucet_bgp.Beka') as beka:
            faucet_bgp = FaucetBgp(logger, None, None)
            faucet_bgp.reset(valves)

        self.assertEqual(beka.call_count, 1)

    def test_creates_dualstack_speakers(self):
        """Check that we create one IPv4 and one IPv6 speaker"""

        vlan_config = {
            'bgp_server_addresses_by_ipv': {
                4: [ip_address('127.0.0.1')],
                6: [ip_address('2001:db1::1')]
            },
            'faucet_vips_by_ipv': {
                4: [ip_interface('10.0.0.1/24')],
                6: [ip_interface('2001:db9::/32')]
            },
            'routes_by_ipv': {
                4: {},
                6: {}
            },
            'bgp_neighbor_addresses_by_ipv': {
                4: [ip_address('172.0.0.2')],
                6: [ip_address('2001:db1::2')]
            },
            'bgp_ipvs': [4, 6]
        }
        vlan = FakeVLAN(vlan_config)
        dp = FakeDP([vlan]) # pylint: disable=invalid-name
        valves = {'sw1': FakeValve(dp)}
        logger = FakeLogger()

        with patch('faucet.faucet_bgp.Beka') as beka:
            faucet_bgp = FaucetBgp(logger, None, None)
            faucet_bgp.reset(valves)

        self.assertEqual(beka.call_count, 2)
