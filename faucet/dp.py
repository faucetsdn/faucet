"""Configuration for a datapath."""

# pylint: disable=protected-access
# pylint: disable=too-many-lines

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import defaultdict
from collections.abc import Iterable
import copy
import random
import math
import netaddr

from faucet import faucet_pipeline
from faucet import valve_of
from faucet import valve_packet
from faucet.acl import PORT_ACL_8021X, MAB_ACL_8021X
from faucet.vlan import VLAN
from faucet.conf import Conf, test_config_condition
from faucet.faucet_pipeline import ValveTableConfig
from faucet.valve import SUPPORTED_HARDWARE
from faucet.valve_table import ValveTable, ValveGroupTable
from faucet.stack import Stack


# Documentation generated using documentation_generator.py
# For attributues to be included in documentation they must
# have a default value, and their descriptor must come
# immediately after being set. See below for example.
class DP(Conf):
    """Stores state related to a datapath controlled by Faucet, including
configuration.
"""
    DEFAULT_LLDP_SEND_INTERVAL = 5
    DEFAULT_LLDP_MAX_PER_INTERVAL = 5
    mutable_attrs = frozenset(['vlans'])

    # Values that are set to None will be set using set_defaults
    # they are included here for testing and informational purposes
    defaults = {
        'dp_id': None,
        # Name for this dp, used for stats reporting and configuration
        'name': None,
        'interfaces': {},
        'interface_ranges': {},
        # How much to offset default priority by
        'priority_offset': 0,
        # Some priority values
        'lowest_priority': None,
        'low_priority': None,
        'high_priority': None,
        'highest_priority': None,
        'cookie': 1524372928,
        # Identification cookie value to allow for multiple controllers to control the same datapath
        'timeout': 300,
        # inactive MAC timeout
        'description': None,
        # description, strictly informational
        'hardware': 'Open vSwitch',
        # The hardware maker (for chosing an openflow driver)
        'arp_neighbor_timeout': 30,
        # ARP neighbor timeout (seconds)
        'nd_neighbor_timeout': 30,
        # IPv6 ND neighbor timeout (seconds)
        'ofchannel_log': None,
        # OF channel log
        'stack': None,
        # stacking config, when cross connecting multiple DPs
        'ignore_learn_ins': 10,
        # Ignore every approx nth packet for learning.
        # 2 will ignore 1 out of 2 packets; 3 will ignore 1 out of 3 packets.
        # This limits control plane activity when learning new hosts rapidly.
        # Flooding will still be done by the dataplane even with a packet
        # is ignored for learning purposes.
        'drop_broadcast_source_address': True,
        # By default drop packets with a broadcast source address
        'drop_spoofed_faucet_mac': True,
        # By default drop packets on datapath spoofing the FAUCET_MAC
        'group_table': False,
        # Use GROUP tables for VLAN flooding
        'max_hosts_per_resolve_cycle': 5,
        # Max hosts to try to resolve per gateway resolution cycle.
        'max_host_fib_retry_count': 10,
        # Max number of times to retry resolution of a host FIB route.
        'max_resolve_backoff_time': 64,
        # Max number of seconds to back off to when resolving nexthops.
        'packetin_pps': None,
        # Ask switch to rate limit packetin pps. TODO: Not supported by OVS in 2.7.0
        'slowpath_pps': None,
        # Ask switch to rate limit slowpath pps. TODO: Not supported by OVS in 2.7.0
        'learn_jitter': 0,
        # Jitter learn timeouts by up to this many seconds
        'learn_ban_timeout': 0,
        # When banning/limiting learning, wait this many seconds before learning can be retried
        'advertise_interval': 30,
        # How often to slow advertise (eg. IPv6 RAs)
        'fast_advertise_interval': 5,
        # How often to fast advertise (eg. LACP)
        'proactive_learn_v4': True,
        # whether proactive learning is enabled for IPv4 nexthops
        'proactive_learn_v6': True,
        # whether proactive learning is enabled for IPv6 nexthops
        'use_idle_timeout': False,
        # Turn on/off the use of idle timeout for src_table, default OFF.
        'lldp_beacon': {},
        # Config for LLDP beacon service.
        'metrics_rate_limit_sec': 0,
        # Rate limit metric updates if last update was less than this many seconds ago.
        'faucet_dp_mac': valve_packet.FAUCET_MAC,
        # MAC address of packets sent by FAUCET, not associated with any VLAN.
        'combinatorial_port_flood': False,
        # if True, use a seperate output flow for each input port on this VLAN.
        'lacp_timeout': 30,
        # Number of seconds without a LACP message when we consider a LACP group down.
        'dp_acls': None,
        # List of dataplane ACLs (overriding per port ACLs).
        'dot1x': {},
        # Experimental dot1x configuration.
        'table_sizes': {},
        # Table sizes for TFM switches.
        'min_wildcard_table_size': 32,
        # Minimum table size for wildcard tables.
        'max_wildcard_table_size': 1024 + 256,
        # Maximum table size for wildcard tables.
        'port_table_scale_factor': 1.0,
        # Amount to scale port scaled table sizes by.
        'global_vlan': 0,
        # Reserved VID for internal global router VLAN.
        'cache_update_guard_time': 0,
        # Don't update L2 cache if port didn't change within this many seconds (default timeout/2).
        'use_classification': False,
        # Don't update L2 cache if port didn't change within this many seconds.
        'egress_pipeline': False,
        # Experimental inclusion of an egress pipeline
        'strict_packet_in_cookie': True,
        # Apply strict packet in checking to all packet ins.
        'multi_out': True,
        # Have OFA copy packet outs to multiple ports.
        'idle_dst': True,
        # If False, workaround for flow idle timer not reset on flow refresh.
    }

    defaults_types = {
        'dp_id': int,
        'name': str,
        'interfaces': dict,
        'interface_ranges': dict,
        'priority_offset': int,
        'lowest_priority': int,
        'low_priority': int,
        'high_priority': int,
        'highest_priority': int,
        'cookie': int,
        'timeout': int,
        'description': str,
        'hardware': str,
        'arp_neighbor_timeout': int,
        'nd_neighbor_timeout': int,
        'ofchannel_log': str,
        'stack': dict,
        'ignore_learn_ins': int,
        'drop_broadcast_source_address': bool,
        'drop_spoofed_faucet_mac': bool,
        'group_table': bool,
        'max_hosts_per_resolve_cycle': int,
        'max_host_fib_retry_count': int,
        'max_resolve_backoff_time': int,
        'packetin_pps': int,
        'slowpath_pps': int,
        'learn_jitter': int,
        'learn_ban_timeout': int,
        'advertise_interval': int,
        'fast_advertise_interval': int,
        'proactive_learn_v4': bool,
        'proactive_learn_v6': bool,
        'use_idle_timeout': bool,
        'lldp_beacon': dict,
        'metrics_rate_limit_sec': int,
        'faucet_dp_mac': str,
        'combinatorial_port_flood': bool,
        'dp_acls': list,
        'dot1x': dict,
        'table_sizes': dict,
        'min_wildcard_table_size': int,
        'max_wildcard_table_size': int,
        'port_table_scale_factor': float,
        'global_vlan': int,
        'cache_update_guard_time': int,
        'use_classification': bool,
        'egress_pipeline': bool,
        'strict_packet_in_cookie': bool,
        'multi_out': bool,
        'lacp_timeout': int,
        'idle_dst': bool,
    }

    default_table_sizes_types = {
        'port_acl': int,
        'vlan': int,
        'vlan_acl': int,
        'classification': int,
        'eth_src': int,
        'ipv4_fib': int,
        'ipv6_fib': int,
        'vip': int,
        'eth_dst_hairpin': int,
        'eth_dst': int,
        'flood': int,
    }

    lldp_beacon_defaults_types = {
        'send_interval': int,
        'max_per_interval': int,
        'system_name': str,
    }

    dot1x_defaults_types = {
        'nfv_intf': str,
        'nfv_sw_port': int,
        'radius_ip': str,
        'radius_port': int,
        'radius_secret': str,
        'auth_acl': str,
        'noauth_acl': str,
    }

    def __init__(self, _id, dp_id, conf):
        """Constructs a new DP object"""
        self.acls = None
        self.acls_in = None
        self.advertise_interval = None
        self.fast_advertise_interval = None
        self.arp_neighbor_timeout = None
        self.nd_neighbor_timeout = None
        self.combinatorial_port_flood = None
        self.configured = False
        self.cookie = None
        self.description = None
        self.dot1x = {}
        self.dp_acls = None
        self.dp_id = None
        self.drop_broadcast_source_address = None
        self.drop_spoofed_faucet_mac = None
        self.dyn_last_coldstart_time = None
        self.dyn_running = False
        self.dyn_up_port_nos = None
        self.egress_pipeline = None
        self.faucet_dp_mac = None
        self.global_vlan = None
        self.groups = None
        self.group_table = False
        self.hardware = None
        self.high_priority = None
        self.highest_priority = None
        self.ignore_learn_ins = None
        self.interface_ranges = None
        self.interfaces = None
        self.lacp_timeout = None
        self.learn_ban_timeout = None
        self.learn_jitter = None
        self.lldp_beacon = None
        self.low_priority = None
        self.lowest_priority = None
        self.max_host_fib_retry_count = None
        self.max_hosts_per_resolve_cycle = None
        self.max_resolve_backoff_time = None
        self.meters = None
        self.all_meters = None
        self.metrics_rate_limit_sec = None
        self.name = None
        self.ofchannel_log = None
        self.output_only_ports = None
        self.packetin_pps = None
        self.slowpath_pps = None
        self.ports = None
        self.priority_offset = None
        self.proactive_learn_v4 = None
        self.proactive_learn_v6 = None
        self.proactive_nd_limit = None
        self.routers = None
        self.stack = None
        self.tables = None
        self.timeout = None
        self.unicast_flood = None
        self.use_idle_timeout = None
        self.vlans = None
        self.min_wildcard_table_size = None
        self.max_wildcard_table_size = None
        self.port_table_scale_factor = None
        self.cache_update_guard_time = None
        self.use_classification = None
        self.strict_packet_in_cookie = None
        self.multi_out = None
        self.idle_dst = None
        self.has_acls = None

        self.acls = {}
        self.vlans = {}
        self.ports = {}
        self.routers = {}
        self.hairpin_ports = []
        self.output_only_ports = []
        self.lldp_beacon_ports = []
        self.lacp_active_ports = []
        self.tables = {}
        self.meters = {}
        self.all_meters = {}
        self.lldp_beacon = {}
        self.table_sizes = {}
        self.dyn_up_port_nos = set()
        self.has_externals = None
        self.tunnel_acls = []

        super().__init__(_id, dp_id, conf)

    def __str__(self):
        return str(self.name)

    def clone_dyn_state(self, prev_dp, dps=None):
        """Clone dynamic state for this dp"""
        self.dyn_running = prev_dp.dyn_running
        self.dyn_up_port_nos = set(prev_dp.dyn_up_port_nos)
        self.dyn_last_coldstart_time = prev_dp.dyn_last_coldstart_time
        for number in self.ports:
            self.ports[number].clone_dyn_state(prev_dp.ports.get(number))
        if self.stack:
            self.stack.clone_dyn_state(prev_dp.stack, dps)

    def cold_start(self, now):
        """Update to reflect a cold start"""
        self.dyn_last_coldstart_time = now
        self.dyn_running = True
        for vlan in self.vlans.values():
            vlan.reset_caches()

    def check_config(self):
        """Check configuration of this dp"""
        super().check_config()
        test_config_condition(not isinstance(self.dp_id, int), (
            f'dp_id must be {int} not {type(self.dp_id)}'))
        test_config_condition(self.dp_id < 0 or self.dp_id > 2**64 - 1, (
            f'DP ID {self.dp_id} not in valid range'))
        test_config_condition(not netaddr.valid_mac(self.faucet_dp_mac), (
            f'invalid MAC address {self.faucet_dp_mac}'))
        test_config_condition(not (self.interfaces or self.interface_ranges), (
            f'DP {self} must have at least one interface'))
        test_config_condition(self.timeout < 15, 'timeout must be > 15')
        test_config_condition(self.timeout > 65535, 'timeout cannot be > than 65335')
        # To prevent L2 learning from timing out before L3 can refresh
        test_config_condition(not (self.arp_neighbor_timeout < (self.timeout / 2)), (
            'L2 timeout must be > ARP timeout * 2'))
        test_config_condition(
            self.arp_neighbor_timeout > 65535, 'arp_neighbor_timeout cannot be > 65535')
        test_config_condition(not (self.nd_neighbor_timeout < (self.timeout / 2)), (
            'L2 timeout must be > ND timeout * 2'))
        test_config_condition(
            self.nd_neighbor_timeout > 65535, 'nd_neighbor_timeout cannot be > 65535')
        test_config_condition(self.combinatorial_port_flood and self.group_table, (
            'combinatorial_port_flood and group_table mutually exclusive'))
        if self.cache_update_guard_time == 0:
            self.cache_update_guard_time = int(self.timeout / 2)
        if self.learn_jitter == 0:
            self.learn_jitter = int(max(math.sqrt(self.timeout) * 3, 1))
        if self.learn_ban_timeout == 0:
            self.learn_ban_timeout = self.learn_jitter
        if self.lldp_beacon:
            self._lldp_defaults()
        if self.dot1x:
            self._check_conf_types(self.dot1x, self.dot1x_defaults_types)
        self._check_conf_types(self.table_sizes, self.default_table_sizes_types)
        self.stack = Stack('stack', self.dp_id, self.name,
                           self.canonical_port_order, self.lacp_down_ports, self.lacp_ports,
                           self.stack)

    def _lldp_defaults(self):
        self._check_conf_types(self.lldp_beacon, self.lldp_beacon_defaults_types)
        if 'send_interval' not in self.lldp_beacon:
            self.lldp_beacon['send_interval'] = self.DEFAULT_LLDP_SEND_INTERVAL
        test_config_condition(self.lldp_beacon['send_interval'] < 1, (
            f'DP ID {self.dp_id} LLDP beacon send_interval not in valid range'))
        if 'max_per_interval' not in self.lldp_beacon:
            self.lldp_beacon['max_per_interval'] = self.DEFAULT_LLDP_MAX_PER_INTERVAL
        self.lldp_beacon = self._set_unknown_conf(
            self.lldp_beacon, self.lldp_beacon_defaults_types)
        if self.lldp_beacon.get('system_name', None) is None:
            self.lldp_beacon['system_name'] = self.name

    def _generate_acl_tables(self):
        all_acls = {}
        if self.dot1x:
            # NOTE: All acl's are added to the acl list and then referred to later by ports
            acls = [PORT_ACL_8021X, MAB_ACL_8021X,
                    self.acls.get(self.dot1x.get('auth_acl'), None),
                    self.acls.get(self.dot1x.get('noauth_acl'), None)]

            acls.extend([acl for acl_name, acl in self.acls.items() if acl.dot1x_assigned])
            all_acls['port_acl'] = [acl for acl in acls if acl is not None]

        for vlan in self.vlans.values():
            if vlan.acls_in:
                all_acls.setdefault('vlan_acl', [])
                all_acls['vlan_acl'].extend(vlan.acls_in)
            if vlan.acls_out:
                all_acls.setdefault('egress_acl', [])
                all_acls['egress_acl'].extend(vlan.acls_out)
                self.egress_pipeline = True
        if self.dp_acls:
            test_config_condition(self.dot1x, (
                'DP ACLs and 802.1x cannot be configured together'))
            all_acls.setdefault('port_acl', [])
            all_acls['port_acl'].extend(self.dp_acls)
        else:
            for port in self.ports.values():
                if port.acls_in:
                    test_config_condition(port.dot1x, (
                        'port ACLs and 802.1x cannot be configured together'))
                    all_acls.setdefault('port_acl', [])
                    all_acls['port_acl'].extend(port.acls_in)
                if self.dot1x and port.number == self.dot1x['nfv_sw_port']:
                    test_config_condition(not port.output_only, (
                        'NFV Ports must have output_only set to True.'
                    ))
        if self.tunnel_acls:
            all_acls.setdefault('port_acl', [])
            all_acls['port_acl'].extend(self.tunnel_acls)
        table_config = {}
        for table_name, acls in all_acls.items():
            matches = {}
            set_fields = set()
            meter = False
            exact_match = False
            default = faucet_pipeline.DEFAULT_CONFIGS[table_name]
            for acl in acls:
                for field, has_mask in acl.matches.items():
                    if has_mask or field not in matches:
                        matches[field] = has_mask
                set_fields.update(acl.set_fields)
                meter = meter or acl.meter
                exact_match = acl.exact_match
            table_config[table_name] = ValveTableConfig(
                table_name,
                default.table_id,
                exact_match=exact_match,
                meter=meter,
                output=True,
                match_types=tuple(sorted(matches.items())),
                set_fields=tuple(sorted(set_fields)),
                next_tables=default.next_tables)
        # TODO: dynamically configure output attribute
        return table_config

    def pipeline_str(self):
        """Text description of pipeline."""
        table_configs = sorted([
            (table.table_id, str(table.table_config))
            for table in self.tables.values()])
        return '\n'.join([
            f'table ID {table_id} {table_config}'
            for table_id, table_config in table_configs])

    def pipeline_tableids(self):
        """Return pipeline table IDs."""
        return {table.table_id for table in self.tables.values()}

    def _configure_tables(self):
        """Configure FAUCET pipeline with tables."""
        valve_cl = SUPPORTED_HARDWARE.get(self.hardware, None)
        test_config_condition(
            not valve_cl, f'hardware {self.hardware} must be in {list(SUPPORTED_HARDWARE)}')
        if valve_cl is None:
            return

        tables = {}
        self.groups = ValveGroupTable()
        relative_table_id = 0
        included_tables = copy.deepcopy(faucet_pipeline.MINIMUM_FAUCET_PIPELINE_TABLES)
        acl_tables = self._generate_acl_tables()
        if acl_tables:
            included_tables.update(set(acl_tables.keys()))
            self.has_acls = True
        # Only configure IP routing tables if enabled.
        for vlan in self.vlans.values():
            for ipv in vlan.ipvs():
                included_tables.add(f'ipv{ipv}_fib')
                included_tables.add('vip')
        if valve_cl.STATIC_TABLE_IDS:
            included_tables.add('port_acl')
            self.has_acls = True
        if self.hairpin_ports:
            included_tables.add('eth_dst_hairpin')
        if self.use_classification:
            included_tables.add('classification')
        if self.egress_pipeline:
            included_tables.add('egress')
        if self.coprocessor_ports():
            included_tables.add('copro')
        canonical_configs = [
            config for config in faucet_pipeline.FAUCET_PIPELINE
            if config.name in included_tables]
        table_configs = {}
        for relative_table_id, canonical_table_config in enumerate(canonical_configs, start=0):
            name = canonical_table_config.name
            table_config = acl_tables.get(
                name, copy.deepcopy(canonical_table_config))
            if not self.egress_pipeline:
                table_config.metadata_write = 0
                table_config.metadata_match = 0
            if not valve_cl.STATIC_TABLE_IDS:
                table_config.table_id = relative_table_id
            table_configs[name] = table_config

        # Stacking with external ports, so need external forwarding request field.
        if self.has_externals:
            for table_name in ('vlan', 'eth_dst', 'flood'):
                table = table_configs[table_name]
                table.match_types += ((valve_of.EXTERNAL_FORWARDING_FIELD, False),)
                if table.set_fields is not None:
                    table.set_fields += (valve_of.EXTERNAL_FORWARDING_FIELD,)
                else:
                    table.set_fields = (valve_of.EXTERNAL_FORWARDING_FIELD,)

        if self.restricted_bcast_arpnd_ports():
            table_configs['flood'].match_types += (('eth_type', False),)

        if 'egress_acl' in included_tables:
            table_configs['eth_dst'].miss_goto = 'egress_acl'

        oxm_fields = set(valve_of.MATCH_FIELDS.keys())

        for table_name, table_config in table_configs.items():
            if table_config.set_fields:
                set_fields = set(table_config.set_fields)
                test_config_condition(
                    not set_fields.issubset(oxm_fields),
                    f'set_fields not all OpenFlow OXM fields {set_fields - oxm_fields}')
            if table_config.match_types:
                matches = set(match for match, _ in table_config.match_types)
                test_config_condition(
                    not matches.issubset(oxm_fields),
                    f'matches not all OpenFlow OXM fields {matches - oxm_fields}')

            scale_factor = 1.0
            # Need flows for internal/external.
            if self.has_externals:
                scale_factor *= 2

            # Table scales with number of VLANs only.
            if table_config.vlan_scale:
                scale_factor *= (len(self.vlans) * table_config.vlan_scale)

            # Table scales with number of ports and VLANs.
            elif table_config.vlan_port_scale:
                scale_factor *= (len(self.vlans) * len(self.ports) * table_config.vlan_port_scale)
                scale_factor *= self.port_table_scale_factor

                if table_config.name == 'flood':
                    # We need flows for all ports when using combinatorial port flood.
                    if self.combinatorial_port_flood:
                        scale_factor *= len(self.ports)
                    # We need more flows for more broadcast rules.
                    if self.restricted_bcast_arpnd_ports():
                        scale_factor *= 2

            # Always multiple of min_wildcard_table_size
            table_size_multiple = int(scale_factor / self.min_wildcard_table_size) + 1
            size = table_size_multiple * self.min_wildcard_table_size

            if not table_config.exact_match:
                size = max(size, self.min_wildcard_table_size)
                size = min(size, self.max_wildcard_table_size)

            # Hard override for size if present.
            size = self.table_sizes.get(table_name, size)

            table_config.size = size
            table_config.next_tables = [
                tbl_name for tbl_name in table_config.next_tables
                if tbl_name in table_configs]
            next_table_ids = [
                table_configs[tbl_name].table_id for tbl_name in table_config.next_tables]
            tables[table_name] = ValveTable(
                table_name, table_config, self.cookie,
                notify_flow_removed=self.use_idle_timeout,
                next_tables=next_table_ids
            )
        self.tables = tables

    def set_defaults(self):
        super().set_defaults()
        self._set_default('dp_id', self._id)
        self._set_default('name', str(self._id))
        self._set_default('lowest_priority', self.priority_offset)
        self._set_default('low_priority', self.priority_offset + 9000)
        self._set_default('high_priority', self.low_priority + 1)
        self._set_default('highest_priority', self.high_priority + 98)
        self._set_default('description', self.name)

    def table_by_id(self, table_id):
        """Gets first table with table id"""
        tables = [table for table in self.tables.values() if table_id == table.table_id]
        if tables:
            return tables[0]
        return None

    def port_no_valid(self, port_no):
        """Return True if supplied port number valid on this datapath."""
        return not valve_of.ignore_port(port_no) and port_no in self.ports

    def base_prom_labels(self):
        """Return base Prometheus labels for this DP."""
        return dict(dp_id=hex(self.dp_id), dp_name=self.name)

    def port_labels(self, port_no):
        """Return port name and description labels for a port number."""
        port_name = str(port_no)
        port_description = None
        if port_no in self.ports:
            port = self.ports[port_no]
            port_name = port.name
            port_description = port.description
        elif port_no == valve_of.ofp.OFPP_CONTROLLER:
            port_name = 'CONTROLLER'
        elif port_no == valve_of.ofp.OFPP_LOCAL:
            port_name = 'LOCAL'
        if port_description is None:
            port_description = port_name
        return dict(self.base_prom_labels(), port=port_name, port_description=port_description)

    def classification_table(self):
        """Returns classification table"""
        if self.use_classification:
            return self.tables['classification']
        return self.tables['eth_src']

    def output_tables(self):
        """Return tables that cause a packet to be forwarded."""
        if self.hairpin_ports:
            return (self.tables['eth_dst_hairpin'], self.tables['eth_dst'])
        return (self.tables['eth_dst'],)

    def output_table(self):
        """Returns first output table"""
        return self.output_tables()[0]

    def match_tables(self, match_type):
        """Return list of tables with matches of a specific match type."""
        return [
            table for table in self.tables.values()
            if table.match_types is None or match_type in table.match_types]

    def non_vlan_ports(self):
        """Ports that don't have VLANs on them."""
        ports = set()
        for non_vlan in (self.output_only_ports, self.stack_ports(), self.coprocessor_ports()):
            ports.update(set(non_vlan))
        return ports

    def stack_ports(self):
        """Return list of stack ports"""
        if self.stack:
            return tuple(self.stack.ports)
        return []

    def coprocessor_ports(self):
        """Return list of coprocessor ports."""
        return tuple(port for port in self.ports.values() if port.coprocessor)

    def restricted_bcast_arpnd_ports(self):
        """Return ports that have restricted broadcast set."""
        return tuple(port for port in self.ports.values() if port.restricted_bcast_arpnd)

    def lacp_ports(self):
        """Return ports that have LACP."""
        return tuple(port for port in self.ports.values() if port.lacp)

    def lacp_up_ports(self):
        """Return ports that have LACP up."""
        return tuple(port for port in self.lacp_ports() if port.is_actor_up())

    def lacp_down_ports(self):
        """Return ports that have LACP not UP"""
        return tuple(port for port in self.lacp_ports() if not port.is_actor_up())

    def lacp_nosync_ports(self):
        """Return ports that have LACP status NO_SYNC."""
        return tuple(port for port in self.lacp_ports() if port.is_actor_nosync())

    def lags(self):
        """Return dict of LAGs mapped to member ports."""
        lags = defaultdict(list)
        for port in self.lacp_ports():
            lags[port.lacp].append(port)
        return lags

    def lags_up(self):
        """Return dict of LAGs mapped to member ports that have LACP up."""
        lags = defaultdict(list)
        for port in self.lacp_up_ports():
            lags[port.lacp].append(port)
        return lags

    def lags_nosync(self):
        """Return dict of LAGs mapped to member ports that have LACP in NO SYNC."""
        lags = defaultdict(list)
        for port in self.lacp_nosync_ports():
            lags[port.lacp].append(port)
        return lags

    def all_lags_up(self):
        """Return True if all LAGs have at least one port up."""
        return set(self.lags()) == set(self.lags_up())

    def add_acl(self, acl_ident, acl):
        """Add an ACL to this DP."""
        self.acls[acl_ident] = acl

    def add_router(self, router_ident, router):
        """Add a router to this DP."""
        self.routers[router_ident] = router

    def add_port(self, port):
        """Add a port to this DP."""
        port_num = port.number
        self.ports[port_num] = port
        if port.output_only:
            self.output_only_ports.append(port)
        if port.stack:
            self.stack.add_port(port)
        if port.lldp_beacon_enabled():
            self.lldp_beacon_ports.append(port)
        if port.hairpin or port.hairpin_unicast:
            self.hairpin_ports.append(port)
        if port.lacp and port.lacp_active:
            self.lacp_active_ports.append(port)

    def lldp_beacon_send_ports(self, now):
        """Return list of ports to send LLDP packets; stacked ports always send LLDP."""
        send_ports = []
        if self.lldp_beacon:
            priority_ports = {
                port for port in self.stack_ports()
                if port.running() and port.lldp_beacon_enabled()}
            cutoff_beacon_time = now - self.lldp_beacon['send_interval']
            nonpriority_ports = {
                port for port in self.lldp_beacon_ports
                if port.running() and (
                    port.dyn_last_lldp_beacon_time is None
                    or port.dyn_last_lldp_beacon_time < cutoff_beacon_time)}
            nonpriority_ports -= priority_ports
            send_ports.extend(list(priority_ports))
            nonpriority_ports = list(nonpriority_ports)
            random.shuffle(nonpriority_ports)
            nonpriority_ports = nonpriority_ports[:self.lldp_beacon['max_per_interval']]
            send_ports.extend(nonpriority_ports)
        return send_ports

    def resolve_stack_topology(self, dps, meta_dp_state):
        """Resolve inter-DP config for stacking"""
        if self.stack:
            self.stack.resolve_topology(dps, meta_dp_state)
            for dp in dps:
                # Must set externals flag for entire stack.
                if dp.stack and dp.has_externals:
                    self.has_externals = True
                    break
            self.finalize_tunnel_acls(dps)

    def finalize_tunnel_acls(self, dps):
        """Resolve each tunnels sources"""
        # Find all tunnel ACLs that are in `self.tunnel_acls` that are have a configured source
        if self.tunnel_acls:
            # TODO: A Tunnel ACL can contain multiple different tunnel IDs
            tunnel_ids = {tunnel_acl._id: tunnel_acl for tunnel_acl in self.tunnel_acls}
            referenced_acls = set()
            for dp in dps:
                if dp.dp_acls:
                    for acl in dp.dp_acls:
                        tunnel_acl = tunnel_ids.get(acl._id)
                        if tunnel_acl:
                            # ACL is configured on a DP
                            tunnel_acl.add_tunnel_source(dp.name, None)
                            referenced_acls.add(tunnel_acl._id)
                else:
                    for port in dp.ports.values():
                        if port.acls_in:
                            for acl in port.acls_in:
                                tunnel_acl = tunnel_ids.get(acl._id)
                                if tunnel_acl:
                                    tunnel_acl.add_tunnel_source(dp.name, port.number)
                                    referenced_acls.add(tunnel_acl._id)
            # Any tunnel ACL that has not been resolved should be ignored
            for tunnel_id, tunnel_acl in tunnel_ids.items():
                if tunnel_id not in referenced_acls:
                    self.tunnel_acls.remove(tunnel_acl)

    @staticmethod
    def canonical_port_order(ports):
        """Return iterable of ports in consistent order."""
        return sorted(ports, key=lambda x: x.number)

    def reset_refs(self, vlans=None):
        """Resets VLAN references."""

        if vlans is None:
            vlans = self.vlans
            router_vlans = {vlan._id for router in self.routers.values() for vlan in router.vlans}
        else:
            router_vlans = {vlan for router in self.routers.values() for vlan in router.vlans}

        vlan_ports = defaultdict(set)
        for port in self.ports.values():
            for vlan in port.vlans():
                vlan_ports[vlan].add(port)

        if self.stack_ports or self.stack.is_root():
            new_vlans = list(vlans.values())
        else:
            new_vlans = []
            for vlan in vlans.values():
                if (vlan_ports[vlan] or vlan.reserved_internal_vlan
                        or vlan.dot1x_assigned or vlan._id in router_vlans):
                    new_vlans.append(vlan)

        self.vlans = {}
        for vlan in new_vlans:
            vlan.reset_ports(vlan_ports[vlan])
            self.vlans[vlan.vid] = vlan

    def resolve_port(self, port_name):
        """Resolve a port by number or name."""
        if isinstance(port_name, int):
            if port_name in self.ports:
                return self.ports[port_name]
        elif isinstance(port_name, str):
            resolved_ports = [port for port in self.ports.values() if port_name == port.name]
            if resolved_ports:
                return resolved_ports[0]
        return None

    def finalize_config(self, dps):
        """Perform consistency checks after initial config parsing."""

        dp_by_name = {}
        vlan_by_name = {}
        acl_meters = set()

        def first_unused_vlan_id(vid):
            """Returns the first unused VID from the starting vid"""
            used_vids = sorted([vlan.vid for vlan in self.vlans.values()])
            while vid in used_vids:
                vid += 1
            return vid

        def create_vlan(vid):
            """Creates a VLAN object with the VID"""
            test_config_condition(vid in self.vlans, (
                'Attempting to dynamically create a VLAN with ID that already exists'))
            vlan = VLAN(vid, self.dp_id, None)
            self.vlans[vlan.vid] = vlan
            return vlan

        def resolve_ports(port_names):
            """Resolve list of ports, by port by name or number."""
            resolved_ports = []
            for port_name in port_names:
                port = self.resolve_port(port_name)
                if port is not None:
                    resolved_ports.append(port)
            return resolved_ports

        def resolve_vlan(vlan_name):
            """Resolve VLAN by name or VID."""
            test_config_condition(not isinstance(vlan_name, (str, int)), (
                f'VLAN must be type {str} or {int} not {type(vlan_name)}'))
            if vlan_name in vlan_by_name:
                return vlan_by_name[vlan_name]
            if vlan_name in self.vlans:
                return self.vlans[vlan_name]
            return None

        def resolve_vlans(vlan_names):
            """Resolve a list of VLAN names."""
            vlans = []
            for vlan_name in vlan_names:
                vlan = resolve_vlan(vlan_name)
                if vlan:
                    vlans.append(vlan)
            return vlans

        def resolve_stack_dps():
            """Resolve DP references in stacking config."""
            if self.stack_ports():
                port_stack_dp = {}
                for port in self.stack_ports():
                    stack_dp = port.stack['dp']
                    test_config_condition(stack_dp not in dp_by_name, (
                        f'stack DP {stack_dp} not defined'))
                    port_stack_dp[port] = dp_by_name[stack_dp]
                for port, dp in port_stack_dp.items():
                    port.stack['dp'] = dp
                    stack_port = dp.resolve_port(port.stack['port'])
                    test_config_condition(stack_port is None, (
                        f'stack port {port.stack["port"]} not defined in DP{dp.name}'))
                    port.stack['port'] = stack_port

        def resolve_mirror_destinations():
            """Resolve mirror port references and destinations."""
            mirror_from_port = defaultdict(list)
            for mirror_port in self.ports.values():
                if mirror_port.mirror is not None:
                    mirrored_ports = resolve_ports(mirror_port.mirror)
                    test_config_condition(len(mirrored_ports) != len(mirror_port.mirror), (
                        f'port mirror not defined in DP {self.name}'))
                    for mirrored_port in mirrored_ports:
                        mirror_from_port[mirrored_port].append(mirror_port)

            # TODO: confusingly, mirror at config time means what ports to mirror from.
            #   But internally we use as a list of ports to mirror to.
            for mirrored_port, mirror_ports in mirror_from_port.items():
                mirrored_port.mirror = []
                for mirror_port in mirror_ports:
                    mirrored_port.mirror.append(mirror_port.number)
                    if not mirror_port.coprocessor:
                        mirror_port.output_only = True

        def resolve_acl(acl_in, vid=None, port_num=None):
            """
            Resolve an individual ACL
            Args:
                acl_in (str): ACL name to find reference in the acl list
                vid (int): VID of the VLAN the ACL is being applied to
                port_num (int): The number of the port the ACl is being applied to
            Returns:
                matches, set_fields, meter (3-Tuple): ACL matches, set fields and meter values
            """
            test_config_condition(acl_in not in self.acls, (
                f'missing ACL {acl_in} in DP:{self.name}'))
            acl = self.acls[acl_in]
            tunnel_dsts_to_vlan = {}

            def resolve_port_cb(port_name):
                """Resolve port"""
                port = self.resolve_port(port_name)
                if port:
                    return port.number
                return port

            def get_tunnel_vlan(tunnel_id_name, resolved_dst):
                """
                Obtain the VLAN that is configured for a tunnel.
                If the tunnel VLAN exists, ensure it has the correct properties and is not used.
                If the VLAN does not exist, then create one.

                Args:
                    tunnel_id_name (str/int/None): Reference to VLAN object that the tunnel will use
                    resolved_dst (tuple): DP, port destination tuple
                Returns:
                    VLAN: VLAN object used by the tunnel
                """
                if not tunnel_id_name:
                    if resolved_dst in tunnel_dsts_to_vlan:
                        tunnel_vlan = tunnel_dsts_to_vlan[resolved_dst]
                    else:
                        # Create a VLAN using the first unused VLAN ID
                        # Get highest non-reserved VLAN
                        vlan_offset = max([
                            vlan.vid for vlan in self.vlans.values()
                            if not vlan.reserved_internal_vlan])
                        # Also need to account for the potential number of tunnels
                        ordered_acls = sorted(self.acls)
                        index = ordered_acls.index(acl_in) + 1
                        acl_tunnels = [self.acls[name].get_num_tunnels() for name in ordered_acls]
                        tunnel_offset = sum(acl_tunnels[:index])
                        start_pos = vlan_offset + tunnel_offset
                        tunnel_vid = first_unused_vlan_id(start_pos)
                        tunnel_vlan = create_vlan(tunnel_vid)
                        tunnel_vlan.reserved_internal_vlan = True
                else:
                    # Tunnel ID has been specified, so search for the VLAN
                    tunnel_vlan = resolve_vlan(tunnel_id_name)
                    if tunnel_vlan:
                        # VLAN exists, i.e: user specified the VLAN so check if it is reserved
                        test_config_condition(not tunnel_vlan.reserved_internal_vlan, (
                            f'VLAN {tunnel_vlan.name} is required for use by'
                            f' tunnel {tunnel_id_name} but is not reserved'))
                    else:
                        # VLAN does not exist, so the ID should be the VID the user wants
                        test_config_condition(isinstance(tunnel_id_name, str), (
                            f'Tunnel VLAN ({tunnel_id_name}) does not exist'))
                        # Create the tunnel VLAN object
                        tunnel_vlan = create_vlan(tunnel_id_name)
                        tunnel_vlan.reserved_internal_vlan = True
                    existing_tunnel_vlan = tunnel_dsts_to_vlan.get(resolved_dst, None)
                    if existing_tunnel_vlan is not None:
                        test_config_condition(
                            existing_tunnel_vlan == tunnel_vlan.vid,
                            f'Cannot have multiple tunnel IDs ({existing_tunnel_vlan.vid},'
                            f' {tunnel_vlan.vid}) to same destination {resolved_dst}')
                return tunnel_vlan

            def resolve_tunnel_objects(dst_dp_name, dst_port_name, tunnel_id_name):
                """
                Resolves the names of the tunnel src and dst (DP & port) pairs into the correct \
                    objects
                Args:
                    dst_dp (str): DP of the tunnel's destination port
                    dst_port (int/None): Destination port of the tunnel
                    tunnel_id_name (int/str/None): Tunnel identification number or VLAN reference
                Returns:
                    dst_dp name, dst_port name and tunnel id
                """
                # VLAN tunnel ACL
                test_config_condition(vid is not None, 'Tunnels do not support VLAN-ACLs')
                # Port & DP tunnel ACL
                test_config_condition(dst_dp_name not in dp_by_name, (
                    f'Could not find referenced destination DP ({dst_dp_name}) for tunnel ACL {acl_in}'))
                dst_dp = dp_by_name[dst_dp_name]
                dst_port = None
                if dst_port_name:
                    dst_port = dst_dp.resolve_port(dst_port_name)
                    test_config_condition(dst_port is None, (
                        f'Could not find referenced destination port ({dst_port_name}) for tunnel ACL {acl_in}'))
                    test_config_condition(dst_port.stack is None, (
                        f'destination port {dst_port_name} for tunnel ACL {acl_in} cannot be a stack port'))
                    dst_port = dst_port.number
                dst_dp = dst_dp.name
                resolved_dst = (dst_dp, dst_port)
                tunnel_vlan = get_tunnel_vlan(tunnel_id_name, resolved_dst)
                # Sources will be resolved later on
                self.tunnel_acls.append(self.acls[acl_in])
                tunnel_dsts_to_vlan[resolved_dst] = tunnel_vlan
                tunnel_id = tunnel_vlan.vid
                return (dst_dp, dst_port, tunnel_id)

            acl.resolve_ports(resolve_port_cb, resolve_tunnel_objects)
            for meter_name in acl.get_meters():
                test_config_condition(meter_name not in self.meters, (
                    f'meter {meter_name} is not configured'))
                acl_meters.add(meter_name)
            for port_no in acl.get_mirror_destinations():
                port = self.ports[port_no]
                port.output_only = True
            return acl.build(self.meters, vid, port_num)

        def verify_acl_exact_match(acls):
            """Verify ACLs have equal exact matches"""
            for acl in acls:
                test_config_condition(acl.exact_match != acls[0].exact_match, (
                    'ACLs when used together must have consistent exact_match'))

        def resolve_acls():
            """Resolve config references in ACLs."""
            for vlan in self.vlans.values():
                if vlan.acls_in:
                    acls = []
                    for acl in vlan.acls_in:
                        resolve_acl(acl, vid=vlan.vid)
                        acls.append(self.acls[acl])
                    vlan.acls_in = acls
                    verify_acl_exact_match(acls)
                if vlan.acls_out:
                    acls = []
                    for acl in vlan.acls_out:
                        resolve_acl(acl, vid=vlan.vid)
                        acls.append(self.acls[acl])
                    vlan.acls_out = acls
                    verify_acl_exact_match(acls)
            for port in self.ports.values():
                if port.acls_in:
                    acls = []
                    test_config_condition(self.dp_acls, (
                        'dataplane ACLs cannot be used with port ACLs.'))
                    for acl in port.acls_in:
                        resolve_acl(acl, port_num=port.number)
                        acls.append(self.acls[acl])
                    port.acls_in = acls
                    verify_acl_exact_match(acls)

                if port.dot1x_dyn_acl:
                    acl_names = [acl_name for acl_name, acl in self.acls.items()
                                 if acl.dot1x_assigned]

                    for acl_name in acl_names:
                        resolve_acl(acl_name, port_num=port.number)

                if port.dot1x_acl:
                    acl_names = [self.dot1x.get('auth_acl'),
                                 self.dot1x.get('noauth_acl')]

                    for acl_name in acl_names:
                        if self.acls.get(acl_name, None):
                            resolve_acl(acl_name, port_num=port.number)

            if self.dp_acls:
                acls = []
                for acl in self.dp_acls:
                    resolve_acl(acl)
                    acls.append(self.acls[acl])
                self.dp_acls = acls
            # Build unbuilt tunnel ACL rules (DP is not the source of the tunnel)
            for acl in self.acls:
                if self.acls[acl].is_tunnel_acl():
                    resolve_acl(acl, None)
            if self.tunnel_acls:
                for tunnel_acl in self.tunnel_acls:
                    tunnel_acl.verify_tunnel_rules()
            self.all_meters = copy.copy(self.meters)
            for unused_meter in set(self.meters.keys()) - acl_meters:
                del self.meters[unused_meter]

        def resolve_routers():
            """Resolve VLAN references in routers."""
            dp_routers = {}
            for router_name, router in self.routers.items():
                if router.bgp_vlan():
                    router.set_bgp_vlan(resolve_vlan(router.bgp_vlan()))
                vlans = resolve_vlans(router.vlans)
                if vlans or router.bgp_vlan():
                    dp_router = copy.copy(router)
                    dp_router.vlans = vlans
                    dp_routers[router_name] = dp_router
            self.routers = dp_routers

            if self.global_vlan:
                vids = {vlan.vid for vlan in self.vlans.values()}
                test_config_condition(
                    self.global_vlan in vids,
                    f'global_vlan VID {self.global_vlan} conflicts with existing VLAN')

            # Check for overlapping VIP subnets or VLANs.
            all_router_vlans = set()
            for router_name, router in self.routers.items():
                vips = set()
                if router.vlans and len(router.vlans) == 1:
                    lone_vlan = router.vlans[0]
                    test_config_condition(
                        lone_vlan in all_router_vlans,
                        f'single VLAN {lone_vlan} in more than one router')
                for vlan in router.vlans:
                    vips.update({vip for vip in vlan.faucet_vips if not vip.ip.is_link_local})
                all_router_vlans.update(router.vlans)
                for vip in vips:
                    for other_vip in vips - set([vip]):
                        test_config_condition(
                            vip.ip in other_vip.network,
                            f'VIPs {vip} and {other_vip} overlap in router {router_name}')
            bgp_routers = self.bgp_routers()
            if bgp_routers:
                for bgp_router in bgp_routers:
                    bgp_vlan = bgp_router.bgp_vlan()
                    vlan_dp_ids = [str(dp.dp_id) for dp in dps if bgp_vlan.vid in dp.vlans]
                    test_config_condition(len(vlan_dp_ids) != 1, (
                        f'DPs ({", ".join(vlan_dp_ids)}) sharing a BGP speaker VLAN ({bgp_vlan.vid}) is unsupported'))
                    test_config_condition(bgp_router.bgp_server_addresses() != (
                        bgp_routers[0].bgp_server_addresses()), (
                            'BGP server addresses must all be the same'))
                router_ids = {bgp_router.bgp_routerid() for bgp_router in bgp_routers}
                test_config_condition(
                    len(router_ids) != 1, f'BGP router IDs must all be the same: {router_ids}')
                bgp_ports = {bgp_router.bgp_port() for bgp_router in bgp_routers}
                test_config_condition(
                    len(bgp_ports) != 1, f'BGP ports must all be the same: {bgp_ports}')

        if not self.stack_ports():
            # Revert back to None if there are no stack ports
            self.stack = None
        if self.stack:
            # Set LLDP defaults for when stacking is configured
            self._lldp_defaults()

        test_config_condition(
            not self.vlans and not self.non_vlan_ports(),
            f'no VLANs referenced by interfaces in {self.name}')
        dp_by_name = {dp.name: dp for dp in dps}
        vlan_by_name = {vlan.name: vlan for vlan in self.vlans.values()}
        loop_protect_external_ports = {
            port for port in self.ports.values() if port.loop_protect_external}
        self.has_externals = bool(loop_protect_external_ports)

        # Populate port.lacp_port_id if it wasn't set in config
        for port in self.ports.values():
            if port.lacp and port.lacp_port_id == -1:
                dp_index = dps.index(self)
                port.lacp_port_id = dp_index * 100 + port.number

        resolve_stack_dps()
        resolve_mirror_destinations()
        resolve_acls()
        resolve_routers()

        for port in self.ports.values():
            port.finalize()
        for vlan in self.vlans.values():
            vlan.finalize()
        for acl in self.acls.values():
            acl.finalize()
        for router in self.routers.values():
            router.finalize()

    def finalize(self):
        """Need to configure OF tables as very last step."""
        self._configure_tables()
        super().finalize()

    def get_native_vlan(self, port_num):
        """Return native VLAN for a port by number, or None."""
        try:
            return self.ports[port_num].native_vlan
        except KeyError:
            return None

    def bgp_routers(self):
        """Return list of routers with BGP enabled."""
        return tuple(
            router for router in self.routers.values() if router.bgp_as() and router.bgp_vlan())

    def dot1x_ports(self):
        """Return list of ports with 802.1x enabled."""
        return tuple(port for port in self.ports.values() if port.dot1x)

    @staticmethod
    def _get_conf_changes(logger, conf_name, subconf, new_subconf, diff=False, ignore_keys=None):
        """Generic detection of config changes between DPs, with merge of unchanged instances."""
        if not ignore_keys:
            ignore_keys = []
        ignore_keys = frozenset(ignore_keys)
        curr_confs = frozenset(subconf.keys())
        new_confs = frozenset(new_subconf.keys())
        deleted_confs = set(curr_confs - new_confs)
        added_confs = set()
        changed_confs = set()
        same_confs = set()
        description_only_confs = set()

        for conf_id, new_conf in new_subconf.items():
            old_conf = subconf.get(conf_id, None)
            if old_conf:
                if old_conf.ignore_subconf(
                        new_conf, ignore_keys=ignore_keys):
                    same_confs.add(conf_id)
                elif old_conf.ignore_subconf(
                        new_conf, ignore_keys=(ignore_keys.union(['description']))):
                    same_confs.add(conf_id)
                    description_only_confs.add(conf_id)
                    logger.info(f'{conf_name} {conf_id} description only changed')
                else:
                    changed_confs.add(conf_id)
                    if diff:
                        logger.info(f'{conf_name} {conf_id} changed: {old_conf.conf_diff(new_conf)}')
                    else:
                        logger.info(f'{conf_name} {conf_id} changed')
            else:
                added_confs.add(conf_id)
                logger.info(f'{conf_name} {conf_id} added')

        for conf_id in same_confs:
            old_conf = subconf[conf_id]
            new_subconf[conf_id].merge_dyn(old_conf)

        changes = deleted_confs or added_confs or changed_confs
        if changes:
            if deleted_confs:
                logger.info(f'{conf_name}s deleted: {deleted_confs}')
            if added_confs:
                logger.info(f'{conf_name}s added: {added_confs}')
            if changed_confs:
                logger.info(f'{conf_name}s changed: {changed_confs}')
        else:
            logger.info(f'no {conf_name} changes')


        return (
            changes, deleted_confs, added_confs, changed_confs, same_confs, description_only_confs)

    def _get_acl_config_changes(self, logger, new_dp):
        """Detect any config changes to ACLs.

        Args:
            logger (ValveLogger): logger instance.
            new_dp (DP): new dataplane configuration.
        Returns:
            changed_acls (set): changed/added ACLs.
        """
        _, _, added_acls, changed_acls, _, _ = self._get_conf_changes(
            logger, 'ACL', self.acls, new_dp.acls, diff=True)
        return added_acls.union(changed_acls)

    def _get_vlan_config_changes(self, logger, new_dp):
        """Detect any config changes to VLANs.

        Args:
            logger (ValveLogger): logger instance.
            new_dp (DP): new dataplane configuration.
        Returns:
            changes (tuple) of:
                deleted_vlans (set): deleted VLAN IDs.
                changed_vlans (set): changed/added VLAN IDs.
        """
        _, deleted_vlans, added_vlans, changed_vlans, _, _ = self._get_conf_changes(
            logger, 'VLAN', self.vlans, new_dp.vlans)
        return (deleted_vlans, added_vlans.union(changed_vlans))

    def _get_port_config_changes(self, logger, new_dp, changed_vlans, deleted_vlans, changed_acls):
        """Detect any config changes to ports.

        Args:
            logger (ValveLogger): logger instance.
            new_dp (DP): new dataplane configuration.
            changed_vlans (set): changed/added VLAN IDs.
            deleted_vlans (set): deleted VLAN IDs.
            changed_acls (set): changed/added ACL IDs.
        Returns:
            changes (tuple) of:
                all_ports_changed (bool): True if all ports changed.
                deleted_ports (set): deleted port numbers.
                changed_ports (set): changed port numbers.
                added_ports (set): added port numbers.
                changed_acl_ports (set): changed ACL only port numbers.
                changed_vlans (set): changed/added VLAN IDs.
        """
        _, deleted_ports, added_ports, changed_ports, same_ports, _ = self._get_conf_changes(
            logger, 'port', self.ports, new_dp.ports,
            diff=True, ignore_keys=frozenset(['acls_in']))

        changed_acl_ports = set()
        all_ports_changed = False

        topology_changed = False
        if self.stack:
            topology_changed = bool(self.stack.hash() != new_dp.stack.hash())
        if topology_changed:
            # Topology changed so restart stack ports just to be safe
            stack_ports = [
                port.number for port in new_dp.stack_ports()
                if port.number not in deleted_ports
                and port.number not in added_ports]
            changed_ports.update(set(stack_ports))
            logger.info('Stack topology change detected, restarting stack ports')
            same_ports -= changed_ports

        if not same_ports:
            all_ports_changed = True
        # TODO: optimize case where only VLAN ACL changed.
        elif changed_vlans:
            all_ports = frozenset(new_dp.ports.keys())
            new_changed_vlans = {
                vlan for vlan in new_dp.vlans.values() if vlan.vid in changed_vlans}
            for vlan in new_changed_vlans:
                changed_port_nums = {port.number for port in vlan.get_ports()}
                changed_ports.update(changed_port_nums)
            all_ports_changed = changed_ports == all_ports

        # Detect changes to VLANs and ACLs based on port changes.
        if not all_ports_changed:
            def get_vids(vlans):
                if not vlans:
                    return set()
                if isinstance(vlans, Iterable):
                    return {vlan.vid for vlan in vlans}
                return {vlans.vid}

            def _add_changed_vlan_port(port, port_dp):
                changed_vlans.update(get_vids(port.vlans()))
                if port.stack:
                    changed_vlans.update(get_vids(port_dp.vlans.values()))

            def _add_changed_vlans(old_port, new_port):
                if old_port.vlans() != new_port.vlans():
                    old_vids = get_vids(old_port.vlans())
                    new_vids = get_vids(new_port.vlans())
                    changed_vlans.update(old_vids.symmetric_difference(new_vids))
                # stacking dis/enabled on a port.
                if bool(old_port.stack) != bool(new_port.stack):
                    changed_vlans.update(get_vids(new_dp.vlans.values()))

            for port_no in changed_ports:
                if port_no not in self.ports:
                    continue
                old_port = self.ports[port_no]
                new_port = new_dp.ports[port_no]
                _add_changed_vlans(old_port, new_port)
            for port_no in deleted_ports:
                port = self.ports[port_no]
                _add_changed_vlan_port(port, self)
            for port_no in added_ports:
                port = new_dp.ports[port_no]
                _add_changed_vlan_port(port, new_dp)
            for port_no in same_ports:
                old_port = self.ports[port_no]
                new_port = new_dp.ports[port_no]
                if old_port.mirror != new_port.mirror:
                    logger.info(f'port {port_no} mirror options changed: {new_port.mirror}')
                    changed_ports.add(port_no)
                # ACL changes
                new_acl_ids = new_port.acls_in
                port_acls_changed = set()
                if new_acl_ids:
                    new_acl_ids = [acl._id for acl in new_acl_ids]
                    port_acls_changed = set(new_acl_ids).intersection(changed_acls)
                old_acl_ids = old_port.acls_in
                if old_acl_ids:
                    old_acl_ids = [acl._id for acl in old_acl_ids]
                if port_acls_changed:
                    changed_acl_ports.add(port_no)
                    logger.info(f'port {port_no} ACL changed (ACL {port_acls_changed} content changed)')
                elif (old_acl_ids or new_acl_ids) and old_acl_ids != new_acl_ids:
                    changed_acl_ports.add(port_no)
                    logger.info(f'port {port_no} ACL changed (ACL {old_acl_ids} to {new_acl_ids})')

            if changed_acl_ports:
                same_ports -= changed_acl_ports
                logger.info(f'ports where ACL only changed: {changed_acl_ports}')

        same_ports -= changed_ports
        changed_vlans -= deleted_vlans
        # TODO: limit scope to only routers that have affected VLANs.
        changed_vlans_with_vips = []
        for vid in changed_vlans:
            vlan = new_dp.vlans[vid]
            if vlan.faucet_vips:
                changed_vlans_with_vips.append(vlan)
        if changed_vlans_with_vips:
            logger.info(f'forcing cold start because {changed_vlans_with_vips} has routing')
            all_ports_changed = True

        return (all_ports_changed, deleted_ports,
                changed_ports, added_ports, changed_acl_ports,
                changed_vlans)

    def _get_meter_config_changes(self, logger, new_dp):
        """Detect any config changes to meters.
        Args:
            logger (ValveLogger): logger instance.
            new_dp (DP): new dataplane configuration.
        Returns:
            changes (tuple) of:
                deleted_meters (set): deleted Meter IDs.
                changed_meters (set): changed/added Meter IDs.
        """
        (all_meters_changed, deleted_meters,
         added_meters, changed_meters, _, _) = self._get_conf_changes(
             logger, 'METERS', self.meters, new_dp.meters)

        return (all_meters_changed, deleted_meters, added_meters, changed_meters)

    def get_config_changes(self, logger, new_dp):
        """Detect any config changes.

        Args:
            logger (ValveLogger): logger instance
            new_dp (DP): new dataplane configuration.
        Returns:
            (tuple): changes tuple containing:

                deleted_ports (set): deleted port numbers.
                changed_ports (set): changed port numbers.
                added_ports (set): added port numbers.
                changed_acl_ports (set): changed ACL only port numbers.
                deleted_vlans (set): deleted VLAN IDs.
                changed_vlans (set): changed/added VLAN IDs.
                all_ports_changed (bool): True if all ports changed.
                all_meters_changed (bool): True if all meters changed
                deleted_meters (set): deleted meter numbers
                added_meters (set): Added meter numbers
                changed_meters (set): changed/added meter numbers
        """
        if new_dp.stack and self.stack and new_dp.stack.root_name != self.stack.root_name:
            logger.info('Stack root change - requires cold start')
        elif new_dp.routers != self.routers:
            logger.info('DP routers config changed - requires cold start')
        elif not self.ignore_subconf(
                new_dp, ignore_keys=['interfaces', 'interface_ranges', 'routers']):
            logger.info(f'DP config changed - requires cold start: {self.conf_diff(new_dp)}')
        else:
            changed_acls = self._get_acl_config_changes(logger, new_dp)
            deleted_vlans, changed_vlans = self._get_vlan_config_changes(logger, new_dp)
            (all_meters_changed, deleted_meters,
             added_meters, changed_meters) = self._get_meter_config_changes(logger, new_dp)
            (all_ports_changed, deleted_ports, changed_ports, added_ports,
             changed_acl_ports, changed_vlans) = self._get_port_config_changes(
                 logger, new_dp, changed_vlans, deleted_vlans, changed_acls)
            return (deleted_ports, changed_ports, added_ports, changed_acl_ports,
                    deleted_vlans, changed_vlans, all_ports_changed,
                    all_meters_changed, deleted_meters,
                    added_meters, changed_meters)
        # default cold start
        return (set(), set(), set(), set(), set(), set(), True, True, set(), set(), set())

    def get_tables(self):
        """Return tables as dict for API call."""
        return {
            table_name: table.table_id for table_name, table in self.tables.items()}

    def get_config_dict(self):
        """Return DP config as a dict for API call."""
        return {
            'dps': {self.name: self.to_conf()},
            'vlans': {vlan.name: vlan.to_conf() for vlan in self.vlans.values()},
            'acls': {acl_id: acl.to_conf() for acl_id, acl in self.acls.items()}}
