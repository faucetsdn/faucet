"""Unit tests for DP"""

import unittest

from faucet.dp import DP

class FaucetDPConfigTest(unittest.TestCase): # pytype: disable=module-attr
    """Test that DP serialises config as it receives it"""

    def setUp(self):
        """Defines the default config - this should match the documentation"""

        self.default_config = {
            'advertise_interval': 30,
            'arp_neighbor_timeout': 250,
            'combinatorial_port_flood': False,
            'cookie': 1524372928,
            'drop_broadcast_source_address': True,
            'drop_lldp': True,
            'drop_spoofed_faucet_mac': True,
            'faucet_dp_mac': '0e:00:00:00:00:01',
            'group_table': False,
            'group_table_routing': False,
            'hardware': 'Open vSwitch',
            'high_priority': 9001,
            'highest_priority': 9099,
            'ignore_learn_ins': 10,
            'interface_ranges': {},
            'interfaces': {},
            'learn_ban_timeout': 10,
            'learn_jitter': 10,
            'lldp_beacon': {},
            'low_priority': 9000,
            'lowest_priority': 0,
            'max_host_fib_retry_count': 10,
            'max_hosts_per_resolve_cycle': 5,
            'max_resolve_backoff_time': 32,
            'metrics_rate_limit_sec': 0,
            'ofchannel_log': None,
            'packetin_pps': None,
            'pipeline_config_dir': '/etc/faucet',
            'priority_offset': 0,
            'proactive_learn': True,
            'stack': None,
            'timeout': 300,
            'use_idle_timeout': False
        }

    def test_basic_config(self):
        """Tests the minimal config"""
        dp_id = 12345

        input_config = {
            'interfaces': {
                1: {}
            }
        }
        output_config = {
            'description': str(dp_id),
            'dp_id': dp_id,
            'interfaces': {}
        }

        expected_config = self.default_config
        expected_config.update(input_config)
        expected_config.update(output_config)

        dp = DP(dp_id, None, input_config) # pylint: disable=invalid-name
        output_config = dp.to_conf()

        self.assertEqual(output_config, expected_config)

        key_exceptions = [
            'lldp_beacon_ports',
            'output_only_ports',
            'vlans',
            'routers',
            'acls',
            'ports',
            'stack_ports',
            '_id',
            'groups',
            'name'
        ]
        dict_keys = set(dp.__dict__.keys())
        conf_keys = set(dp.to_conf().keys())

        for exception in key_exceptions:
            dict_keys.remove(exception)

        self.assertEqual(dict_keys, conf_keys)
