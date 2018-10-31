#!/usr/bin/env python3

"""Test config parsing"""

import logging
import re
import shutil
import tempfile
import os
import unittest

from faucet import config_parser as cp

LOGNAME = '/dev/null'


class TestConfig(unittest.TestCase): # pytype: disable=module-attr
    """Test config parsing raises correct exception."""

    tmpdir = None

    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        logging.disable(logging.NOTSET)
        shutil.rmtree(self.tmpdir)

    def conf_file_name(self):
        """Return path to test config file in test directory."""
        return os.path.join(self.tmpdir, 'faucet.yaml')

    def create_config_file(self, config):
        """Returns file path to file containing the config parameter."""
        conf_file_name = self.conf_file_name()
        with open(conf_file_name, 'wb') as conf_file:
            if isinstance(config, bytes):
                conf_file.write(config)
            else:
                conf_file.write(config.encode('utf-8'))
        return conf_file_name

    def run_function_with_config(self, config, function, before_function=None):
        """Return False with error if provided function raises InvalidConfigError."""
        # TODO: Check acls_in work now acl_in is deprecated
        if isinstance(config, str) and 'acl_in' in config and not 'acls_in':
            config = re.sub('(acl_in: )(.*)', 'acls_in: [\\2]', config)
        conf_file = self.create_config_file(config)
        if before_function:
            before_function()
        try:
            function(conf_file, LOGNAME)
        except cp.InvalidConfigError as err:
            return (False, err)
        return (True, None)

    def check_config_failure(self, config, function, before_function=None):
        """Ensure config parsing reported as failed."""
        config_success, config_err = self.run_function_with_config(
            config, function, before_function)
        self.assertEqual(config_success, False, config_err)

    def check_config_success(self, config, function, before_function=None):
        """Ensure config parsing reported succeeded."""
        config_success, config_err = self.run_function_with_config(
            config, function, before_function)
        self.assertEqual(config_success, True, config_err)

    def _get_dps_as_dict(self, config):
        result = {}
        _, dps = cp.dp_parser(self.create_config_file(config), LOGNAME)
        for dp in dps:
            result[dp.dp_id] = dp
        return result

    def test_one_port_dp(self):
        """Test basic port configuration."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            testing:
                number: 1
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)
        dps = self._get_dps_as_dict(config)
        self.assertTrue(1 in dps, 'datapath configured with incorrect dp_id')
        dp = dps[1]
        self.assertEqual(
            dp.name, 'sw1', 'datapath configured with incorrect name')
        self.assertTrue(
            1 in dp.ports, 'interface not configured in datapath')
        self.assertEqual(
            len(dp.ports),
            1,
            'unexpected interface configured in datapath'
            )
        self.assertTrue(100 in dp.vlans, 'vlan not configured in datapath')
        self.assertEqual(
            len(dp.vlans),
            1,
            'unexpected vlan configured in datapath'
            )
        port = dp.ports[1]
        self.assertEqual(port.number, 1, 'port number configured incorrectly')
        self.assertEqual(
            port.name, 'testing', 'port name configured incorrectly')
        vlan = dp.vlans[100]
        self.assertEqual(vlan.vid, 100, 'vlan vid configured incorrectly')
        self.assertEqual(
            vlan.name, 'office', 'vlan name configured incorrectly')
        self.assertEqual(
            port.native_vlan,
            vlan,
            'native vlan configured incorrectly in port'
            )

    def test_config_stack(self):
        """Test valid stacking config."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    dp: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        hardware: "Open vSwitch"
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)
        dps = self._get_dps_as_dict(config)
        for dp in dps.values():
            self.assertTrue(
                dp.stack is not None, 'stack not configured for DP')
            self.assertEqual(
                dp.stack['root_dp'].dp_id, 1, 'root_dp configured incorrectly')
            self.assertEqual(
                len(dp.stack['graph'].nodes),
                2,
                'stack graph has incorrect nodes'
                )
        for dp_id, remote_dp_id in ((1, 2), (2, 1)):
            stack_port = dps[dp_id].stack_ports[0]
            self.assertEqual(
                stack_port.number, 1, 'incorrect stack port configured')
            self.assertTrue(
                stack_port.stack is not None, 'stack not configured for port')
            self.assertEqual(
                stack_port.stack['dp'].dp_id,
                remote_dp_id,
                'remote stack dp configured incorrectly'
                )
            self.assertEqual(
                stack_port.stack['port'].number,
                1,
                'remote stack port configured incorrectly'
                )

    def test_config_stack_and_non_stack(self):
        """Test stack and non-stacking config."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    dp: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        hardware: "Open vSwitch"
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
    sw3:
        dp_id: 0x3
        hardware: "Open vSwitch"
        interfaces:
            1:
                native_vlan: office
            2:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)

    def test_override_port(self):
        """Test override port is valid."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            testing:
                number: 1
                native_vlan: office
                override_output_port: output_port
            output_port:
                number: 2
                output_only: True
"""
        self.check_config_success(config, cp.dp_parser)
        dps = self._get_dps_as_dict(config)
        self.assertEqual(
            dps[1].ports[1].override_output_port.number,
            2,
            'override output port not configured correctly'
            )
        self.assertTrue(
            dps[1].ports[2].output_only,
            'output only port configured incorrectly'
            )
        self.assertTrue(
            bool(dps[1].output_only_ports),
            'no output only ports configured for dp'
            )
        self.assertEqual(
            dps[1].output_only_ports[0].number,
            2,
            'output only port configured incorrectly'
            )

    def test_valid_mac(self):
        """Test with valid MAC."""
        config = """
vlans:
    office:
        vid: 100
        faucet_mac: '11:22:33:44:55:66'
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)
        dp = self._get_dps_as_dict(config)[0x1]
        self.assertEqual(
            dp.vlans[100].faucet_mac,
            '11:22:33:44:55:66',
            'faucet mac configured incorrectly'
            )

    def test_resolved_mirror_port(self):
        """Test can use name reference to mirrored port."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            mirrored_port:
                number: 1
                native_vlan: office
            2:
                mirror: mirrored_port
"""
        self.check_config_success(config, cp.dp_parser)
        sw1 = self._get_dps_as_dict(config)[0x1]
        self.assertTrue(
            sw1.ports[2].output_only,
            'mirror port not set to output only'
            )
        self.assertTrue(
            sw1.ports[1].mirror_actions() is not None,
            'mirror port has no mirror actions'
            )

    def test_acl_dictionary_valid(self):
        """test acl config is valid when not using 'rule' key"""
        config = """
acls:
    office-vlan-protect:
        -
            dl_type: 0x800
            actions:
                allow: 0
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)

    def test_acls_vlan_valid(self):
        """Test ACLs can be combined on VLAN."""
        config = """
acls:
    access-port-protect:
        - rule:
            udp_src: 80
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv4_src: 10.0.200.0/24
vlans:
    office:
        vid: 100
        acls_in: [access-port-protect, office-vlan-protect]
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)

    def test_acls_port_valid(self):
        """Test ACLs can be combined on a port."""
        config = """
acls:
    access-port-protect:
        - rule:
            udp_src: 80
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv4_src: 10.0.200.0/24
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acls_in: [access-port-protect, office-vlan-protect]
"""
        self.check_config_success(config, cp.dp_parser)

    def test_good_set_fields(self):
        """Test good set_fields."""
        config = """
acls:
    good_acl:
        rules:
            - rule:
                actions:
                    output:
                        set_fields:
                            - eth_dst: "0e:00:00:00:00:01"
vlans:
    guest:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: 100
                acl_in: good_acl
"""
        self.check_config_success(config, cp.dp_parser)

    def test_push_pop_vlans_acl(self):
        """Test push and pop VLAN ACL fields."""
        config = """
acls:
    good_acl:
        rules:
            - rule:
                actions:
                    output:
                        pop_vlans: 1
                        vlan_vids:
                            - { vid: 200, eth_type: 0x8100 }
vlans:
    guest:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: 100
                acl_in: good_acl
"""
        self.check_config_success(config, cp.dp_parser)

    def test_dp_acls(self):
        """Test DP ACLs."""
        config = """
acls:
    good_acl:
        rules:
            - rule:
                actions:
                    output:
                        port: 1
vlans:
    guest:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        dp_acls: [good_acl]
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_success(config, cp.dp_parser)

    def test_force_port_vlan(self):
        """Test push force_port_vlan."""
        config = """
acls:
    good_acl:
        rules:
            - rule:
                actions:
                    allow: 1
                    force_port_vlan: 1
                    output:
                        swap_vid: 101
vlans:
    guest:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                tagged_vlans: [100]
                acl_in: good_acl
"""
        self.check_config_success(config, cp.dp_parser)

    def test_failover_acl(self):
        """Test failover ACL fields."""
        config = """
acls:
    good_acl:
        rules:
            - rule:
                actions:
                    output:
                        failover:
                             group_id: 1
                             ports: [1]
vlans:
    guest:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: 100
                acl_in: good_acl
"""
        self.check_config_success(config, cp.dp_parser)

    def test_unreferenced_acl(self):
        """Test an unresolveable port in an ACL that is not referenced is OK."""
        config = """
acls:
    unreferenced_acl:
        rules:
            - rule:
                actions:
                    output:
                        port: 99
vlans:
    guest:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_success(config, cp.dp_parser)

    def test_multi_bgp(self):
        """Test multiple BGP VLANs can be configured."""
        config = """
vlans:
    routing1:
        vid: 100
        faucet_vips: ["10.0.0.254/24"]
        bgp_server_addresses: ["127.0.0.1"]
        bgp_as: 100
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["127.0.0.1"]
        bgp_neighbor_as: 100
    routing2:
        vid: 200
        faucet_vips: ["10.0.0.253/24"]
        bgp_server_addresses: ["127.0.0.1"]
        bgp_as: 200
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["127.0.0.2"]
        bgp_neighbor_as: 200
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: routing1
            2:
                native_vlan: routing2
"""
        self.check_config_success(config, cp.dp_parser)

    def test_meter_config(self):
        """Test valid meter config."""
        config = """
meters:
    lossymeter:
        meter_id: 1
        entry:
            flags: "KBPS"
            bands:
                [
                    {
                        type: "DROP",
                        rate: 1000
                    }
                ]
acls:
    lossyacl:
        - rule:
            actions:
                meter: lossymeter
                allow: 1
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: 100
                acl_in: lossyacl
"""
        self.check_config_success(config, cp.dp_parser)

    def test_dp_lldp_minimal_valid(self):
        """Test minimal valid DP config."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        lldp_beacon:
            send_interval: 10
            max_per_interval: 10
        interfaces:
            testing:
                number: 1
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)

    def test_port_lldp_minimal_valid(self):
        """Test minimal valid LLDP config."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        lldp_beacon:
            send_interval: 10
            max_per_interval: 10
        interfaces:
            testing:
                number: 1
                native_vlan: office
                lldp_beacon:
                    enable: true
"""
        self.check_config_success(config, cp.dp_parser)

    def test_all_lldp_valid(self):
        """Test a fully specified valid LLDP config."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        lldp_beacon:
            system_name: test_system
            send_interval: 10
            max_per_interval: 10
        interfaces:
            testing:
                number: 1
                native_vlan: office
                lldp_beacon:
                    enable: true
                    system_name: port_system
                    port_descr: port_description
                    org_tlvs:
                        - {oui: 0x12bb, subtype: 2, info: "01406500"}
"""
        self.check_config_success(config, cp.dp_parser)

    def test_interface_ranges_lldp(self):
        """Verify lldp config works when using interface ranges"""
        config = """
vlans:
    office:
        vid: 100
    guest:
        vid: 200
dps:
    sw1:
        dp_id: 0x1
        lldp_beacon:
            send_interval: 10
            max_per_interval: 10
        interface_ranges:
            '1-2':
                lldp_beacon:
                    enable: True
                    system_name: port_system
                    org_tlvs:
                        - {oui: 0x12bb, subtype: 2, info: "01406500"}
        interfaces:
            1:
                native_vlan: office
            2:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)

    def test_multi_acl_dp(self):
        """Test multiple ACLs with multiple DPs, where one ACL does mirroring."""
        config = """
dps:
  SWPRI2:
    dp_id: 0x223d5a07ff
    interfaces:
      11:
        acl_in: non_mirroring_acl
        native_vlan: 197
  SWSEC0B:
    dp_id: 0xe01aea107a69
    interfaces:
      30:
        native_vlan: 197
        acl_in: mirroring_acl
      47:
        native_vlan: 197
vlans:
  197:
acls:
  mirroring_acl:
  - rule:
      actions:
        allow: 1
        mirror: 47
  non_mirroring_acl:
  - rule:
      actions:
        allow: 1
"""
        self.check_config_success(config, cp.dp_parser)

    def test_vlan_route_dictionary_valid(self):
        """Test new vlan route format as dictionary is valid"""
        config = """
vlans:
    office:
        vid: 100
        routes:
            - {ip_gw: '10.0.0.1', ip_dst: '10.99.99.0/24'}
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)

    def test_acl_multi_dp_output_rule(self):
        """Verify that an acl can output to different ports with the same name
        on different DPs'
        """
        config = """
vlans:
    v100:
        vid: 100
        acls_in: [test]
acls:
    test:
        - rule:
            dl_type: 0x800      # ipv4
            actions:
                output:
                    port: 'target'
dps:
    s1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        interfaces:
            1:
                native_vlan: 'v100'
            2:
                name: 'target'
                native_vlan: 'v100'
    s2:
        dp_id: 0x2
        hardware: "Open vSwitch"
        interfaces:
            1:
                native_vlan: 'v100'
            3:
                name: 'target'
                native_vlan: 'v100'
"""
        conf_file = self.create_config_file(config)
        _, dps = cp.dp_parser(conf_file, LOGNAME)
        outputs = {
            's1': 2,
            's2': 3
            }
        for dp in dps:
            v100 = dp.vlans[100]
            for acl in v100.acls_in:
                for rule in acl.rules:
                    port = rule['actions']['output']['port']
                    self.assertEqual(
                        outputs[dp.name],
                        port,
                        msg='acl output port resolved incorrectly'
                        )

    def test_port_range_valid_config(self):
        """Test if port range config applied correctly"""
        config = """
vlans:
    office:
        vid: 100
    guest:
        vid: 200
dps:
    sw1:
        dp_id: 0x1
        interface_ranges:
            1-4,6,port8:
                native_vlan: office
                max_hosts: 2
                permanent_learn: True
            port10-11:
                native_vlan: guest
                max_hosts: 2
        interfaces:
            1:
                max_hosts: 4
                description: "video conf"
"""
        conf_file = self.create_config_file(config)
        _, dps = cp.dp_parser(conf_file, LOGNAME)
        dp = dps[0]
        self.assertEqual(len(dp.ports), 8)
        self.assertTrue(all([p.permanent_learn for p in dp.ports.values() if p.number < 9]))
        self.assertTrue(all([p.max_hosts == 2 for p in dp.ports.values() if p.number > 1]))
        self.assertTrue(dp.ports[1].max_hosts == 4)
        self.assertEqual(dp.ports[1].description, "video conf")

    def test_single_range_valid_config(self):
        """Test if port range with single port config applied correctly"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interface_ranges:
            1:
                native_vlan: office
"""
        conf_file = self.create_config_file(config)
        _, dps = cp.dp_parser(conf_file, LOGNAME)
        dp = dps[0]
        self.assertEqual(len(dp.ports), 1)

    def _check_table_names_numbers(self, dp, tables):
        for table_name, table in dp.tables.items():
            self.assertTrue(
                table_name in tables,
                'Incorrect table configured in dp'
                )
            self.assertEqual(
                tables[table_name],
                table.table_id,
                'Table configured with wrong table_id'
                )
        for table_name in tables:
            self.assertTrue(
                table_name in dp.tables,
                'Table not configured in dp'
                )

    def _check_next_tables(self, table, next_tables):
        for nt in table.next_tables:
            self.assertIn(nt, next_tables, 'incorrect next table configured')
        for nt in next_tables:
            self.assertIn(nt, table.next_tables, 'missing next table')

    def test_pipeline_config_no_acl(self):
        """Test pipelines are generated correctly with different configs"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)
        dp = self._get_dps_as_dict(config)[0x1]
        tables = {
            'vlan': 0,
            'eth_src': 1,
            'eth_dst': 2,
            'flood': 3
            }
        self._check_table_names_numbers(dp, tables)
        self._check_next_tables(dp.tables['vlan'], [1])
        self._check_next_tables(dp.tables['eth_src'], [2, 3])
        self._check_next_tables(dp.tables['eth_dst'], [])
        self._check_next_tables(dp.tables['flood'], [])

    def test_pipeline_config_no_acl_static_ids(self):
        """Test pipelines are generated correctly with different configs"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        hardware: NoviFlow
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)
        dp = self._get_dps_as_dict(config)[0x1]
        tables = {
            'port_acl': 0,
            'vlan': 1,
            'eth_src': 4,
            'eth_dst': 9,
            'flood': 10
            }
        self._check_table_names_numbers(dp, tables)

    def test_pipeline_config_ipv4_no_acl(self):
        """Test pipelines are generated correctly with different configs"""
        config = """
vlans:
    office:
        vid: 100
        faucet_vips: ['10.100.0.254/24']
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)
        dp = self._get_dps_as_dict(config)[0x1]
        tables = {
            'vlan': 0,
            'eth_src': 1,
            'ipv4_fib': 2,
            'vip': 3,
            'eth_dst': 4,
            'flood': 5
            }
        self._check_table_names_numbers(dp, tables)

    def test_pipeline_config_ipv6_4_no_acl(self):
        """Test pipelines are generated correctly with different configs"""
        config = """
vlans:
    office:
        vid: 100
        faucet_vips: ["10.100.0.254/24", "fc00::1:254/112"]
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)
        dp = self._get_dps_as_dict(config)[0x1]
        tables = {
            'vlan': 0,
            'eth_src': 1,
            'ipv4_fib': 2,
            'ipv6_fib': 3,
            'vip': 4,
            'eth_dst': 5,
            'flood': 6
            }
        self._check_table_names_numbers(dp, tables)

    def test_pipeline_config_ipv6_4_vlan_acl(self):
        """Test pipelines are generated correctly with different configs"""
        config = """
vlans:
    office:
        vid: 100
        faucet_vips: ["10.100.0.254/24", "fc00::1:254/112"]
        acls_in: [test]
acls:
    test:
        - rule:
            dl_type: 0x800      # ipv4
            actions:
                allow: 1
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)
        dp = self._get_dps_as_dict(config)[0x1]
        tables = {
            'vlan': 0,
            'vlan_acl': 1,
            'eth_src': 2,
            'ipv4_fib': 3,
            'ipv6_fib': 4,
            'vip': 5,
            'eth_dst': 6,
            'flood': 7
            }
        self._check_table_names_numbers(dp, tables)

    def test_pipeline_full(self):
        """Test pipelines are generated correctly with different configs"""
        config = """
vlans:
    office:
        vid: 100
        faucet_vips: ["10.100.0.254/24", "fc00::1:254/112"]
        acls_in: [test]
acls:
    test:
        - rule:
            dl_type: 0x800      # ipv4
            actions:
                allow: 1
dps:
    sw1:
        dp_id: 0x1
        use_classification: True
        egress_pipeline: True
        interfaces:
            1:
                native_vlan: office
                acls_in: [test]
"""
        self.check_config_success(config, cp.dp_parser)
        dp = self._get_dps_as_dict(config)[0x1]
        tables = {
            'port_acl': 0,
            'vlan': 1,
            'vlan_acl': 2,
            'classification': 3,
            'eth_src': 4,
            'ipv4_fib': 5,
            'ipv6_fib': 6,
            'vip': 7,
            'eth_dst': 8,
            'flood': 9,
            'egress': 10
            }
        self._check_table_names_numbers(dp, tables)
        self._check_next_tables(dp.tables['port_acl'], [1, 7, 8, 9])
        self._check_next_tables(dp.tables['vlan'], [2, 3, 4])
        self._check_next_tables(dp.tables['vlan_acl'], [3, 4, 8, 9])
        self._check_next_tables(dp.tables['classification'], [4, 5, 6, 7, 8, 9])
        self._check_next_tables(dp.tables['eth_src'], [5, 6, 7, 8, 9])
        self._check_next_tables(dp.tables['ipv4_fib'], [7, 8, 9])
        self._check_next_tables(dp.tables['ipv6_fib'], [7, 8, 9])
        self._check_next_tables(dp.tables['vip'], [8, 9])
        self._check_next_tables(dp.tables['eth_dst'], [10])
        self._check_next_tables(dp.tables['flood'], [])
        self._check_next_tables(dp.tables['egress'], [])

    def test_pipeline_config_egress(self):
        """Test pipelines are generated correctly with different configs"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        egress_pipeline: True
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)
        dp = self._get_dps_as_dict(config)[0x1]
        tables = {
            'vlan': 0,
            'eth_src': 1,
            'eth_dst': 2,
            'flood': 3,
            'egress': 4
            }
        self._check_table_names_numbers(dp, tables)


    ###########################################
    # Tests of Configuration Failure Handling #
    ###########################################

    def test_dupe_vid(self):
        """Test that VLANs cannot have same VID."""
        config = """
vlans:
    office:
        vid: 100
    guest:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
            2:
                native_vlan: guest
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_unhashable_key(self):
        config = """
vlans:
?   office:
        vid: 100
    guest:
        vid: 200
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
            2:
                native_vlan: office
            3:
                native_vlan: guest
            4:
                native_vlan: office
            5:
                tagged_vlans: [office]
    sw2:
        dp_id: 0x2
        interfaces:
            1:
                native_vlan: office
            2:
                native_vlan: guest
            24:
                tagged_vlans: [office, guest]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_contains_only_int(self):
        """Test that config is invalid when only an int"""
        config = """5"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_contains_only_float(self):
        """Test that config is invalid when only a float"""
        config = """5.5"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_contains_only_str(self):
        """Test config is invalid when only a string"""
        config = """aaaa"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_only_boolean(self):
        """Test config is invalid when only a boolean"""
        config = """False"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_only_datetime(self):
        """Test that config is invalid when only a datetime object"""
        config = """1967-07-31"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_contains_only_dash(self):
        """Test that config is invalid when only only a -"""
        config = """-"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_contains_only_array(self):
        """Test that config is invalid when only only [2, 2]"""
        config = """[2, 2]"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_only_empty_array(self):
        """Test that config is invalid when only only []"""
        config = """[]"""
        self.check_config_failure(config, cp.dp_parser)

    def test_unconfigured_acl(self):
        """Test that config is invalid when there are unconfigured acls"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                acl_in: access-port-protect
                tagged_vlans: [office]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_unconfigured_vlan_acl(self):
        """Test that config is invalid when only there are unconfigured acls"""
        config = """
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                tagged_vlans: [office]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_routes_are_empty(self):
        """Test that config is invalid when vlan routes are empty"""
        config = """
vlans:
    office:
        vid: 100
        routes:
            - route:
                ip_dst:
                ip_gw:
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            5:
                tagged_vlans: [office]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_routes_not_strings(self):
        """Test config is invalid when vlan routes are not strings"""
        config = """
vlans:
    office:
        vid: 100
        routes:
            - route:
                ip_dst: 5.5
                ip_gw: []
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            5:
                tagged_vlans: [office]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_vips_not_strings(self):
        """Test that config is invalid when faucet_vips does not contain strings"""
        config = """
vlans:
    office:
        vid: 100
        faucet_vips: [False, 5.5, []]
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            5:
                tagged_vlans: [office]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_faucet_invalid_vips(self):
        """Test that config is rejected if faucet_vips does not contain valid ip addresses"""
        config = """
vlans:
    office:
        vid: 100
        faucet_vips: ['aaaaa', '', '123421342']
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            5:
                tagged_vlans: [office]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_vlans_is_empty(self):
        """Test that config is rejected when vlans is empty"""
        config = """
vlans:
dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_dps_is_empty(self):
        """Test that config is rejected when dps is empty"""
        config = """
vlans:
    office:
        vid: 100
dps:
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_including_invalid_files(self):
        """Test that config is rejected when including invalid files"""
        config = """
include: [-, False, 1967-06-07, 5.5, [5], {'5': 5}, testing]
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            5:
                tagged_vlans: [office]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_vlans_on_stack(self):
        """Test that config is rejected vlans on a stack interface."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: office
                stack:
                    dp: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        hardware: "Open vSwitch"
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_stack_islands(self):
        """Test that stack islands don't exist."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    dp: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        hardware: "Open vSwitch"
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
    sw3:
        dp_id: 0x3
        hardware: "Open vSwitch"
        interfaces:
            1:
                stack:
                    dp: sw4
                    port: 1
            2:
                native_vlan: office
    sw4:
        dp_id: 0x4
        hardware: "Open vSwitch"
        interfaces:
            1:
                stack:
                    dp: sw3
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_port_number(self):
        """Test port number is valid."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            testing:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_dp_id_too_big(self):
        """Test DP ID is valid."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0xfffffffffffffffffffffffffffffffff
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_vid(self):
        """Test VID is valid."""
        config = """
vlans:
    office:
        vid: 10000
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_routers_empty(self):
        """Test with empty router config."""
        config = """
routers:
    router-1:
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_mac(self):
        """Test with invalid MAC."""
        config = """
vlans:
    office:
        vid: 100
        faucet_mac: '11:22:33:44:55:66:77:88'
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_empty_mac(self):
        """Test with empty MAC."""
        config = """
vlans:
    office:
        vid: 100
        faucet_mac: ''
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_empty_vid(self):
        """Test empty VID."""
        config = """
vlans:
    office:
        vid:
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_empty_interfaces(self):
        """Test empty interfaces."""
        config = """
vlans:
    office:
        vid:
dps:
    sw1:
        dp_id: 0x1
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_interfaces(self):
        """Test invalid interfaces."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces: {'5': 5}
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_unresolved_mirror_ports(self):
        """Test invalid mirror port name."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: mirror_all
acls:
    mirror_all:
        - rule:
            actions:
                mirror: UNRESOLVED
                allow: 1
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_vlans_on_mirror_ports(self):
        """Test invalid VLANs configured on a mirror port."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
            2:
                native_vlan: office
                mirror: 1
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_unresolved_output_ports(self):
        """Test invalid output port name."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: mirror_all
acls:
    mirror_all:
        - rule:
            actions:
                output:
                    port: UNRESOLVED
                allow: 1
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_unresolved_actions_output_ports(self):
        """Test invalid output port name with actions"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: output_unresolved
acls:
    output_unresolved:
        - rule:
            actions:
                output:
                    set_fields:
                         - eth_dst: '01:00:00:00:00:00'
                    port: UNRESOLVED
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_unknown_output_ports(self):
        """Test invalid mirror ACL port."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: mirror_all
acls:
    mirror_all:
        - rule:
            actions:
                output:
                    port: 2
                allow: 1
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_port_range_invalid_config(self):
        """Test invalid characters used in interface_ranges."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interface_ranges:
            abc:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_no_actions(self):
        """Test ACL with invalid actions section."""
        config = """
acls:
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            actions:
          0     allow: 0
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_invalid_ipv4(self):
        """Test invalid IPv4 address in ACL."""
        config = """
acls:
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv4_src: q0.0.200.0/24
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: access-port-protect
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_invalid_ipv6(self):
        """Test invalid IPv6 address in ACL."""
        config = """
acls:
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv6_src: zyx
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: access-port-protect
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_invalid_mask(self):
        """Test invalid IPv4 mask in ACL."""
        config = """
acls:
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv4_src: 10/0.200.0/24
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: access-port-protect
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_invalid_udp_port(self):
        """Test invalid UDP port in ACL."""
        config = """
acls:
    access-port-protect:
        - rule:
            udp_src: v7
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: access-port-protect
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_invalid_rule_name(self):
        """Test invalid name for rule in ACL."""
        config = """
acls:
    access-port-protect:
        - xrule:
            udp_src: v7
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: access-port-protect
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_and_acls_vlan_invalid(self):
        """Test cannot have acl_in and acls_in together."""
        config = """
acls:
    access-port-protect:
        - rule:
            udp_src: 80
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv4_src: 10.0.200.0/24
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
        acls_in: [access-port-protect]
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_inconsistent_exact_match(self):
        """Test that ACLs have consistent exact_match."""
        config = """
acls:
    acl_a:
        exact_match: False
        rules:
            - rule:
                udp_src: 80
    acl_b:
        exact_match: True
        rules:
            - rule:
                udp_src: 81
vlans:
    office:
        vid: 100
        acls_in: [acl_a, acl_b]
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_and_acls_port_invalid(self):
        config = """
acls:
    access-port-protect:
        - rule:
            udp_src: 80
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv4_src: 10.0.200.0/24
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: office-vlan-protect
                acls_in: [access-port-protect]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_char(self):
        """Test config file with invalid characters."""
        config = b'\x63\xe1'
        self.check_config_failure(config, cp.dp_parser)

    def test_perm_denied(self):
        """Test config file has no read permission."""

        def unreadable():
            """Make config unreadable."""
            os.chmod(self.conf_file_name(), 0)

        config = ''
        self.check_config_failure(config, cp.dp_parser, before_function=unreadable)

    def test_missing_route_config(self):
        """Test missing IP gateway for route."""
        config = """
vlans:
    office:
        vid: 100
        routes:
            - route:
                ip_dst: '192.168.0.0/24'
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""

        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_dp_conf(self):
        """Test invalid DP header config."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                description: "host1 container"
    0           native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_duplicate_keys_conf(self):
        """Test duplicate top level keys."""
        config = """
vlans:
    office:
        vid: 100
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            testing:
                number: 1
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_dp_id_not_a_string(self):
        """Test dp_id is not a string"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: &x1
        interfaces:
            1:
                native_vlan: office        
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_key(self):
        """Test invalid key"""
        config = """
acls:
 ?  office-vlan-protect:
        - rule:
            actions:
                allow: 1
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_acl_formation(self):
        """Test missing ACL name."""
        config = """
acls:
#   office-vlan-protect:
        - rule:
            actions:
                allow: 1
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_route_value(self):
        """Test routes value forming a dictionary"""
        config = """
vlans:
    office:
        vid: 100
        routes:
        -   - route:
                ip_dst: '192.168.0.0/24'
                ip_gw: '10.0.100.2'
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_mirror_port(self):
        """Test referencing invalid mirror port"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                mirror: 1"
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_include_values(self):
        """Test include directive contains invalid values"""
        config = """
include:
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_ipv4_src_is_empty(self):
        """Test acl ipv4_src is empty"""
        config = """
acls:
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv4_src: 
            actions:
                allow: 0
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_empty_eth_dst(self):
        """Test eth_dst/dl_dst is empty"""
        config = """
vlans:
    100:
acls:
    101:
        - rule:
            dl_dst:
            actions:
                output:
                    port: 1
dps:
    switch1:
        dp_id: 0xcafef00d
        interfaces:
            1:
                native_vlan: 100
                acl_in: 101     
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_router_vlan_invalid_type(self):
        """Test when router vlans forms a dict"""
        config = """
vlans:
    100:
acls:
    101:
        - rule:
            dl_dst: "0e:00:00:00:02:02"
            actions:
               mirror: 
                    port: 1
dps:
    switch1:
        dp_id: 0xcafef00d
        interfaces:
            1:
                native_vlan: 100
                acl_in: 101
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_mirror_port_invalid_type(self):
        """Test when mirror port forms a dict"""
        config = """
vlans:
    100:
acls:
    101:
        - rule:
            dl_dst: "0e:00:00:00:02:02"
            actions:
               mirror: 
                    port: 1
dps:
    switch1:
        dp_id: 0xcafef00d
        interfaces:
            1:
                native_vlan: 100
                acl_in: 101
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_referencing_unconfigured_dp_in_stack(self):
        """Test when referencing a nonexistent dp in a stack"""
        config = """
vlans:
    office:
        vid: 100
dps:
    3w1:
        dp_id: 0x1
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    dp: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_referencing_unconfigured_port_in_stack(self):
        """Test when referencing a nonexistent port for dp in a stack"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        stack:
            priority: 1
        interfaces:
            9:
                stack:
                    dp: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_not_referencing_a_port_in_the_stack(self):
        """Test when not referencing a port in a stack"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    dp: sw2
                    0ort: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_not_referencing_a_dp_in_the_stack(self):
        """Test when not referencing a dp in a stack"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    $p: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_no_rules_in_acl(self):
        """Test when no rules are present in acl"""
        config = """
acls:
    mirror_destination: {}
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_empty_ipv6_src(self):
        """Test when ipv6_src is empty"""
        config = """
acls:
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv6_src: 
            actions:
                allow: 0
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_port_number_is_wrong_type(self):
        """Test when port number is a dict"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        stack:
            priority: 1
        interfaces:
            1:
               number:
                    dp: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_date_time_object(self):
        """Test when config is just an invalid datetime object"""
        config = """
1976-87-04
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_is_only_bad_float(self):
        """Test when config is this specific case of characters"""
        config = """
._
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_stack_port_is_list(self):
        """Test when stack port is a list"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    dp: sw2
                    port: []#           2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_bad_vlan_reference(self):
        """Test when tagged vlans is a dict"""
        config = """
vlans:
    office:
        vid: 100
    guest:
        vid: 200
dps:
    sw2:
        dp_id: 0x2
        interfaces:
            24:
                tagged_vlans: [office: guest]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_bad_set_fields(self):
        """Test unknown set_field."""
        config = """
acls:
    bad_acl:
        rules:
            - rule:
                actions:
                    output:
                        set_fields:
                            - nosuchfield: "xyz"
vlans:
    guest:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: 100
                acl_in: bad_acl
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_bad_match_fields(self):
        """Test bad match fields."""
        config = """
acls:
    bad_acl:
        rules:
            - rule:
                notsuch: "match"
                actions:
                    output:
                        set_fields:
                            - eth_dst: "0e:00:00:00:00:01"
vlans:
    guest:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: 100
                acl_in: bad_acl
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_bad_cookie(self):
        """Test bad cookie value."""
        config = """
acls:
    bad_cookie_acl:
        rules:
            - rule:
                cookie: 999999
                actions:
                    output:
                        port: 1
vlans:
    guest:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: 100
                acl_in: bad_cookie_acl
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_routers_unreferenced(self):
        """Test with unreferenced router config."""
        config = """
routers:
    router-1:
        vlans: [office, guest]
vlans:
    office:
        vid: 100
    guest:
        vid: 200
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_routers_overlapping_vips(self):
        """Test with unreferenced router config."""
        config = """
routers:
    router-1:
        vlans: [office, guest]
vlans:
    office:
        vid: 100
        faucet_vips: ["10.0.0.1/24"]
    guest:
        vid: 200
        faucet_vips: ["10.0.0.2/24"]
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
            2:
                native_vlan: guest
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_same_vlan_tagged_untagged(self):
        """Test cannot have the same VLAN tagged and untagged on same port."""
        config = """
vlans:
    guest:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: 100
                tagged_vlans: [100]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_share_bgp_routing_VLAN(self):
        """Test cannot share VLAN with BGP across DPs."""
        config = """
vlans:
    routing:
        vid: 100
        faucet_vips: ["10.0.0.254/24"]
        bgp_server_addresses: ["127.0.0.1"]
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["127.0.0.1"]
        bgp_neighbor_as: 2
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: routing
    sw2:
        dp_id: 0x2
        interfaces:
            1:
                native_vlan: routing
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_bgp_server_invalid(self):
        """Test invalid BGP server address."""
        bgp_config = """
vlans:
    100:
        description: "100"
        bgp_port: 9179
        bgp_server_addresses: ['256.0.0.1']
        bgp_as: 1
        bgp_routerid: '1.1.1.1'
        bgp_neighbor_addresses: ['127.0.0.1']
        bgp_neighbor_as: 2
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_failure(bgp_config, cp.dp_parser)

    def test_bgp_neighbor_invalid(self):
        """Test invalid BGP server address."""
        bgp_config = """
vlans:
    100:
        description: "100"
        bgp_port: 9179
        bgp_server_addresses: ['127.0.0.1']
        bgp_as: 1
        bgp_routerid: '1.1.1.1'
        bgp_neighbor_addresses: ['256.0.0.1']
        bgp_neighbor_as: 2
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_failure(bgp_config, cp.dp_parser)

    def test_unknown_vlan_key(self):
        """Test unknown VLAN key."""
        config = """
vlans:
    unknown_key:
        name: office
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_unknown_dp_key(self):
        """Test unknown DP key."""
        config = """
dps:
    unknown_key:
        name: sw1
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_unknown_port_key(self):
        """Test unknown port key."""
        config = """
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            unknown_key:
                name: port1
                number: 3
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_dp_lldp_minimal_invalid(self):
        """Test minimal invalid DP config."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        lldp_beacon:
            system_name: test_system
        interfaces:
            testing:
                number: 1
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_vlan_route_missing_value_invalid(self):
        """Test new vlan route format fails when missing value"""
        config = """
vlans:
    office:
        vid: 100
        routes:
            - {}
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_vlan_route_values_invalid(self):
        """Test new vlan route format fails when values are invalid"""
        config = """
vlans:
    office:
        vid: 100
        routes:
            - {ip_gw: [],ip_gw: 5.5}
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_dot1x_config_valid(self):
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        dot1x:
            nfv_intf: lo
            nfv_sw_port: 2
            radius_ip: ::1
            radius_port: 123
            radius_secret: SECRET
        interfaces:
            1:
                native_vlan: office
                dot1x: True
            2:
                output_only: True
"""
        self.check_config_success(config, cp.dp_parser)

    def test_rule_acl_parse(self):
        config = """
dps:
  sw1:
    dp_id: 1
    hardware: Open vSwitch
    interfaces:
      1:
        native_vlan: 100
        acl_in: acl1
acls:
  acl1:
    - rule:
      actions:
        allow: 1
"""
        self.check_config_success(config, cp.dp_parser)

    def test_stack_priority_value_invalid(self):
        """Test config fails when stack priority invalid type"""
        config = """
acls:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        stack:
            priority: !
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_conf_type_invalid(self):
        """Test config fails when conf invalid type"""
        config = """
acls:
    office-vlan-protect:
        - rule: []
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr
