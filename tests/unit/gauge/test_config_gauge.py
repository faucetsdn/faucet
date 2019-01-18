#!/usr/bin/env python3

"""Test config parsing"""

import logging
import os
import shutil
import tempfile
import unittest
from faucet import config_parser as cp
from faucet.conf import InvalidConfigError

LOGNAME = '/dev/null'


class TestGaugeConfig(unittest.TestCase): # pytype: disable=module-attr
    """Test gauge.yaml config parsing."""

    DEFAULT_FAUCET_CONFIG = """
dps:
    dp1:
        dp_id: 1
        interfaces:
            1:
                native_vlan: v1
    dp2:
        dp_id: 2
        interfaces:
            1:
                native_vlan: v1
vlans:
    v1:
        vid: 1
"""

    GAUGE_CONFIG_HEADER = """
faucet_configs:
    - '{}'
"""
    tmpdir = None

    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        logging.disable(logging.NOTSET)
        shutil.rmtree(self.tmpdir)

    @staticmethod
    def parse_conf_result(gauge_file, gauge_dir):
        """Return True if config parses successfully."""
        try:
            cp.watcher_parser(gauge_file, gauge_dir, None)
        except InvalidConfigError:
            return False
        return True

    def conf_file_name(self, faucet=False):
        """Return path for configuration file."""
        if faucet:
            return os.path.join(self.tmpdir, 'faucet.yaml')
        return os.path.join(self.tmpdir, 'gauge.yaml')

    def create_config_files(self, config, faucet_config=None):
        """Returns file path to file containing the config parameter."""
        gauge_file_name = self.conf_file_name()
        faucet_file_name = self.conf_file_name(faucet=True)
        with open(gauge_file_name, 'w') as conf_file:
            conf_file.write(config.format(faucet_file_name))
        with open(faucet_file_name, 'w') as conf_file:
            if faucet_config:
                conf_file.write(faucet_config)
            else:
                conf_file.write(self.DEFAULT_FAUCET_CONFIG)
        return (gauge_file_name, faucet_file_name)

    def get_config(self, conf_suffix):
        """Return config file together with header template."""
        return self.GAUGE_CONFIG_HEADER + conf_suffix

    def test_all_dps(self):
        """Test config applies for all DPs."""
        GAUGE_CONF = """
watchers:
    port_stats_poller:
        type: 'port_stats'
        all_dps: True
        interval: 10
        db: 'prometheus'
dbs:
    prometheus:
        type: 'prometheus'
"""
        conf = self.get_config(GAUGE_CONF)
        gauge_file, _ = self.create_config_files(conf)
        watcher_confs = cp.watcher_parser(gauge_file, 'gauge_config_test', None)
        self.assertEqual(len(watcher_confs), 2, 'failed to create config for each dp')
        for watcher_conf in watcher_confs:
            msg = 'all_dps config not applied to each dp'
            self.assertEqual(watcher_conf.type, 'port_stats', msg)
            self.assertEqual(watcher_conf.interval, 10, msg)
            self.assertEqual(watcher_conf.db_type, 'prometheus', msg)

    def test_no_all_dps(self):
        """Test setting all_dps and dps together."""
        GAUGE_CONF = """
watchers:
    port_stats_poller:
        type: 'port_stats'
        dps: []
        all_dps: True
        interval: 10
        db: 'prometheus'
dbs:
    prometheus:
        type: 'prometheus'
"""
        conf = self.get_config(GAUGE_CONF)
        gauge_file, _ = self.create_config_files(conf)
        self.assertFalse(self.parse_conf_result(gauge_file, 'gauge_config_test'))

    def test_file_not_writable(self):
        """Test file arg is not writable."""
        GAUGE_CONF = """
watchers:
    ft_10:
        interval: 600
        type: 'flow_table'
        all_dps: True
        db: 'text'
dbs:
    text:
        file: '/not/writable/ft.yml.gz'
        type: 'text'
        compress: True
"""
        conf = self.get_config(GAUGE_CONF)
        gauge_file, _ = self.create_config_files(conf)
        self.assertFalse(self.parse_conf_result(gauge_file, 'gauge_config_test'))

    def test_no_faucet_config_file(self):
        """Test missing FAUCET config."""
        GAUGE_CONF = """
faucet:
    dps:
        dp1:
            dp_id: 1
            interfaces:
                1:
                    native_vlan: v1
    vlans:
        v1:
            vid: 1
watchers:
    port_stats_poller:
        type: 'port_stats'
        dps: ['dp1']
        db: 'prometheus'
dbs:
    prometheus:
        type: 'prometheus'
"""
        gauge_file, _ = self.create_config_files(GAUGE_CONF, '')
        watcher_conf = cp.watcher_parser(
            gauge_file, 'gauge_config_test', None)[0]
        msg = 'failed to create watcher correctly when dps configured in gauge.yaml'
        self.assertEqual(watcher_conf.dps[0], 'dp1', msg)
        self.assertEqual(watcher_conf.type, 'port_stats', msg)
        self.assertEqual(watcher_conf.db_type, 'prometheus', msg)


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr
