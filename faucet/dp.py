"""Configuration for a datapath."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
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

import copy
from collections import defaultdict
import random
import netaddr

from datadiff import diff
import networkx

from faucet import faucet_pipeline
from faucet import valve_of
from faucet.conf import Conf, test_config_condition
from faucet.valve import SUPPORTED_HARDWARE
from faucet.faucet_pipeline import ValveTableConfig
from faucet.valve_table import ValveTable, ValveGroupTable
from faucet import valve_packet

# Documentation generated using documentation_generator.py
# For attributues to be included in documentation they must
# have a default value, and their descriptor must come
# immediately after being set. See below for example.
class DP(Conf):
    """Stores state related to a datapath controlled by Faucet, including
configuration.
"""

    mutable_attrs = frozenset(['stack', 'vlans'])

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
        'arp_neighbor_timeout': 250,
        # ARP and neighbor timeout (seconds)
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
        'max_resolve_backoff_time': 32,
        # Max number of seconds to back off to when resolving nexthops.
        'packetin_pps': None,
        # Ask switch to rate limit packet pps. TODO: Not supported by OVS in 2.7.0
        'learn_jitter': 10,
        # Jitter learn timeouts by up to this many seconds
        'learn_ban_timeout': 10,
        # When banning/limiting learning, wait this many seconds before learning can be retried
        'advertise_interval': 30,
        # How often to advertise (eg. IPv6 RAs)
        'proactive_learn_v4': True,
        # whether proactive learning is enabled for IPv4 nexthops
        'proactive_learn_v6': True,
        # whether proactive learning is enabled for IPv6 nexthops
        'use_idle_timeout': False,
        # Turn on/off the use of idle timeout for src_table, default OFF.
        'lldp_beacon': {},
        # Config for LLDP beacon service.
        'metrics_rate_limit_sec': 0,
        # Rate limit metric updates - don't update metrics if last update was less than this many seconds ago.
        'faucet_dp_mac': valve_packet.FAUCET_MAC,
        # MAC address of packets sent by FAUCET, not associated with any VLAN.
        'combinatorial_port_flood': False,
        # if True, use a seperate output flow for each input port on this VLAN.
        'lacp_timeout': 30,
        # Number of seconds without a LACP message when we consider a LACP group down.
        'dp_acls': None,
        # List of dataplane ACLs (overriding per port ACLs).
        'dot1x': None,
        # Experimental dot1x configuration.
        'table_sizes': {},
        # Table sizes for TFM switches.
        'min_wildcard_table_size': 32,
        # Minimum table size for wildcard tables.
        'max_wildcard_table_size': 1024 + 256,
        # Maximum table size for wildcard tables.
        'global_vlan': 0,
        # Reserved VID for internal global router VLAN.
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
        'ofchannel_log': str,
        'stack': dict,
        'ignore_learn_ins': int,
        'drop_broadcast_source_address': bool,
        'drop_spoofed_faucet_mac': bool,
        'drop_bpdu': bool,
        'drop_lldp': bool,
        'group_table': bool,
        'max_hosts_per_resolve_cycle': int,
        'max_host_fib_retry_count': int,
        'max_resolve_backoff_time': int,
        'packetin_pps': int,
        'learn_jitter': int,
        'learn_ban_timeout': int,
        'advertise_interval': int,
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
        'global_vlan': int,
    }

    default_table_sizes_types = {
        'port_acl': int,
        'vlan': int,
        'vlan_acl': int,
        'eth_src': int,
        'ipv4_fib': int,
        'ipv6_fib': int,
        'vip': int,
        'eth_dst': int,
        'flood': int,
    }

    stack_defaults_types = {
        'priority': int,
    }

    lldp_beacon_defaults_types = {
        'send_interval': int,
        'max_per_interval': int,
        'system_name': str,
    }

    dot1x_defaults_types = {
        'nfv_intf': str,
    }


    def __init__(self, _id, dp_id, conf):
        """Constructs a new DP object"""
        self.acls = None
        self.acls_in = None
        self.advertise_interval = None
        self.arp_neighbor_timeout = None
        self.bgp_local_address = None
        self.bgp_neighbor_as = None
        self.bgp_routerid = None
        self.combinatorial_port_flood = None
        self.configured = False
        self.cookie = None
        self.description = None
        self.dot1x = None
        self.dp_acls = None
        self.dp_id = None
        self.drop_broadcast_source_address = None
        self.drop_spoofed_faucet_mac = None
        self.dyn_last_coldstart_time = None
        self.dyn_running = False
        self.dyn_up_ports = None
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
        self.metrics_rate_limit_sec = None
        self.name = None
        self.ofchannel_log = None
        self.output_only_ports = None
        self.packetin_pps = None
        self.ports = None
        self.priority_offset = None
        self.proactive_learn_v4 = None
        self.proactive_learn_v6 = None
        self.proactive_nd_limit = None
        self.routers = None
        self.stack = None
        self.stack_ports = None
        self.tables = None
        self.timeout = None
        self.unicast_flood = None
        self.use_idle_timeout = None
        self.vlans = None
        self.min_wildcard_table_size = None
        self.max_wildcard_table_size = None

        self.acls = {}
        self.vlans = {}
        self.ports = {}
        self.routers = {}
        self.stack_ports = []
        self.output_only_ports = []
        self.lldp_beacon_ports = []
        self.tables = {}
        self.meters = {}
        self.lldp_beacon = {}
        self.table_sizes = {}
        self.dyn_up_ports = set()
        super(DP, self).__init__(_id, dp_id, conf)

    def __str__(self):
        return self.name

    def check_config(self):
        super(DP, self).check_config()
        test_config_condition(not isinstance(self.dp_id, int), (
            'dp_id must be %s not %s' % (int, type(self.dp_id))))
        test_config_condition(self.dp_id < 0 or self.dp_id > 2**64-1, (
            'DP ID %s not in valid range' % self.dp_id))
        test_config_condition(not netaddr.valid_mac(self.faucet_dp_mac), (
            'invalid MAC address %s' % self.faucet_dp_mac))
        test_config_condition(not (self.interfaces or self.interface_ranges), (
            'DP %s must have at least one interface' % self))
        # To prevent L2 learning from timing out before L3 can refresh
        test_config_condition(self.timeout < self.arp_neighbor_timeout, (
            'L2 timeout must be >= L3 timeout'))
        if self.lldp_beacon:
            self._check_conf_types(self.lldp_beacon, self.lldp_beacon_defaults_types)
            test_config_condition('send_interval' not in self.lldp_beacon, (
                'lldp_beacon send_interval not set'))
            test_config_condition('max_per_interval' not in self.lldp_beacon, (
                'lldp_beacon max_per_interval not set'))
            self.lldp_beacon = self._set_unknown_conf(
                self.lldp_beacon, self.lldp_beacon_defaults_types)
            if self.lldp_beacon['system_name'] is None:
                self.lldp_beacon['system_name'] = self.name
        if self.stack:
            self._check_conf_types(self.stack, self.stack_defaults_types)
        if self.dot1x:
            self._check_conf_types(self.dot1x, self.dot1x_defaults_types)
        self._check_conf_types(self.table_sizes, self.default_table_sizes_types)

    def _configure_tables(self, override_table_config, valve_cl, vlan_port_factor):
        """Configure FAUCET pipeline with tables."""
        tables = {}
        self.groups = ValveGroupTable()
        relative_table_id = 0
        for table_id, table_config in enumerate(faucet_pipeline.FAUCET_PIPELINE):
            table_name = table_config.name
            if table_name in override_table_config:
                table_config = override_table_config[table_name]
            size = self.table_sizes.get(table_name, self.min_wildcard_table_size)
            if table_config.vlan_port_scale:
                size = max(size, int(vlan_port_factor * float(table_config.vlan_port_scale)))
            if not table_config.exact_match:
                size = min(size, self.max_wildcard_table_size)
                size = int(size / self.min_wildcard_table_size) * self.min_wildcard_table_size
            table_config.size = size
            if table_config.match_types:
                if not valve_cl.STATIC_TABLE_IDS:
                    table_id = relative_table_id
                tables[table_name] = ValveTable(
                    table_id, table_name, table_config, self.cookie,
                    notify_flow_removed=self.use_idle_timeout)
                relative_table_id += 1
        self.tables = tables

    def set_defaults(self):
        super(DP, self).set_defaults()
        self._set_default('dp_id', self._id)
        self._set_default('name', str(self._id))
        self._set_default('lowest_priority', self.priority_offset)
        self._set_default('low_priority', self.priority_offset + 9000)
        self._set_default('high_priority', self.low_priority + 1)
        self._set_default('highest_priority', self.high_priority + 98)
        self._set_default('description', self.name)

    def table_by_id(self, table_id):
        tables = [table for table in list(self.tables.values()) if table_id == table.table_id]
        if tables:
            return tables[0]
        return None

    def match_tables(self, match_type):
        """Return list of tables with matches of a specific match type."""
        match_tables = []
        for table in list(self.tables.values()):
            if table.match_types is not None:
                if match_type in table.match_types:
                    match_tables.append(table)
            else:
                match_tables.append(table)
        return match_tables

    def in_port_tables(self):
        """Return list of tables that specify in_port as a match."""
        return self.match_tables('in_port')

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
        elif port.stack is not None:
            self.stack_ports.append(port)
        if port.lldp_beacon_enabled():
            self.lldp_beacon_ports.append(port)

    def lldp_beacon_send_ports(self, now):
        """Return list of ports to send LLDP packets; stacked ports always send LLDP."""
        send_ports = []
        if self.lldp_beacon:
            priority_ports = {
                port for port in self.stack_ports
                if port.running() and port.lldp_beacon_enabled()}
            cutoff_beacon_time = now - self.lldp_beacon['send_interval']
            nonpriority_ports = {
                port for port in self.lldp_beacon_ports
                if port.running() and (
                    port.dyn_last_lldp_beacon_time is None or
                    port.dyn_last_lldp_beacon_time < cutoff_beacon_time)}
            nonpriority_ports -= priority_ports
            send_ports.extend(list(priority_ports))
            send_ports.extend(list(nonpriority_ports)[:self.lldp_beacon['max_per_interval']])
            random.shuffle(send_ports)
        return send_ports

    @staticmethod
    def modify_stack_topology(graph, dp, port, add=True):
        """Add/remove an edge to the stack graph which originates from this dp and port."""

        def canonical_edge(dp, port):
            peer_dp = port.stack['dp']
            peer_port = port.stack['port']
            sort_edge_a = (
                dp.name, port.name, dp, port)
            sort_edge_z = (
                peer_dp.name, peer_port.name, peer_dp, peer_port)
            sorted_edge = sorted((sort_edge_a, sort_edge_z))
            edge_a, edge_b = sorted_edge[0][2:], sorted_edge[1][2:]
            return edge_a, edge_b

        def make_edge_name(edge_a, edge_z):
            edge_a_dp, edge_a_port = edge_a
            edge_z_dp, edge_z_port = edge_z
            return '%s:%s-%s:%s' % (
                edge_a_dp.name, edge_a_port.name,
                edge_z_dp.name, edge_z_port.name)

        def make_edge_attr(edge_a, edge_z):
            edge_a_dp, edge_a_port = edge_a
            edge_z_dp, edge_z_port = edge_z
            return {
                'dp_a': edge_a_dp, 'port_a': edge_a_port,
                'dp_z': edge_z_dp, 'port_z': edge_z_port}

        edge = canonical_edge(dp, port)
        edge_a, edge_z = edge
        edge_name = make_edge_name(edge_a, edge_z)
        edge_attr = make_edge_attr(edge_a, edge_z)
        edge_a_dp, _ = edge_a
        edge_z_dp, _ = edge_z
        if add:
            graph.add_edge(
                edge_a_dp.name, edge_z_dp.name,
                key=edge_name, port_map=edge_attr)
        elif (edge_a_dp.name, edge_z_dp.name, edge_name) in graph.edges:
            graph.remove_edge(edge_a_dp.name, edge_z_dp.name, edge_name)

        return edge_name

    @classmethod
    def add_stack_link(cls, graph, dp, port):
        """Add a stack link to the stack graph."""
        return cls.modify_stack_topology(graph, dp, port)

    @classmethod
    def remove_stack_link(cls, graph, dp, port):
        """Remove a stack link to the stack graph."""
        return cls.modify_stack_topology(graph, dp, port, False)

    def resolve_stack_topology(self, dps):
        """Resolve inter-DP config for stacking."""
        root_dp = None
        stack_dps = []
        for dp in dps:
            if dp.stack is not None:
                stack_dps.append(dp)
                if 'priority' in dp.stack:
                    test_config_condition(dp.stack['priority'] <= 0, (
                        'stack priority must be > 0'))
                    test_config_condition(root_dp is not None, 'cannot have multiple stack roots')
                    root_dp = dp
                    for vlan in list(dp.vlans.values()):
                        test_config_condition(vlan.faucet_vips, (
                            'routing + stacking not supported'))

        if root_dp is None:
            test_config_condition(stack_dps, 'stacking enabled but no root_dp')
            return

        edge_count = {}

        graph = networkx.MultiGraph()
        for dp in dps:
            if dp.stack_ports:
                graph.add_node(dp.name)
                for port in dp.stack_ports:
                    edge_name = self.add_stack_link(graph, dp, port)
                    if edge_name not in edge_count:
                        edge_count[edge_name] = 0
                    edge_count[edge_name] += 1
        if graph.size():
            for edge_name, count in list(edge_count.items()):
                test_config_condition(count != 2, '%s defined only in one direction' % edge_name)
            if self.name in graph:
                if self.stack is None:
                    self.stack = {}
                self.stack['root_dp'] = root_dp
                self.stack['graph'] = graph
                longest_path_to_root_len = 0
                for dp in graph.nodes():
                    path_to_root_len = len(self.shortest_path(root_dp.name, src_dp=dp))
                    test_config_condition(
                        path_to_root_len == 0, '%s not connected to stack' % dp)
                    longest_path_to_root_len = max(
                        path_to_root_len, longest_path_to_root_len)
                self.stack['longest_path_to_root_len'] = longest_path_to_root_len

    def shortest_path(self, dest_dp, src_dp=None):
        """Return shortest path to a DP, as a list of DPs."""
        if src_dp is None:
            src_dp = self.name
        if self.stack is not None and 'root_dp' in self.stack:
            try:
                return networkx.shortest_path(
                    self.stack['graph'], src_dp, dest_dp)
            except networkx.exception.NetworkXNoPath:
                pass
        return []

    def shortest_path_to_root(self):
        """Return shortest path to root DP, as list of DPs."""
        # TODO: root_dp will be None, if stacking is enabled but the root DP is down.
        if self.stack is not None and 'root_dp' in self.stack:
            root_dp = self.stack['root_dp']
            if root_dp is not None and root_dp != self:
                return self.shortest_path(root_dp.name)
        return []

    def is_stack_root(self):
        """Return True if this DP is the root of the stack."""
        return 'priority' in self.stack

    def is_stack_edge(self):
        """Return True if this DP is a stack edge."""
        if self.stack and 'longest_path_to_root_len' in self.stack:
            return self.stack['longest_path_to_root_len'] == len(self.shortest_path_to_root())
        return False

    def peer_stack_up_ports(self, peer_dp):
        """Return list of stack ports that are up towards a peer."""
        return [port for port in self.stack_ports if port.running() and (
            port.stack['dp'].name == peer_dp)]

    def shortest_path_port(self, dest_dp):
        """Return first port on our DP, that is the shortest path towards dest DP."""
        shortest_path = self.shortest_path(dest_dp)
        if len(shortest_path) > 1:
            peer_dp = shortest_path[1]
            peer_dp_ports = self.peer_stack_up_ports(peer_dp)
            if peer_dp_ports:
                return peer_dp_ports[0]
        return None

    def reset_refs(self, vlans=None):
        if vlans is None:
            vlans = self.vlans
        self.vlans = {}
        for vlan in list(vlans.values()):
            vlan.reset_ports(list(self.ports.values()))
            if vlan.get_ports():
                self.vlans[vlan.vid] = vlan

    def resolve_port(self, port_name):
        """Resolve a port by number or name."""
        if isinstance(port_name, int):
            if port_name in self.ports:
                return self.ports[port_name]
        elif isinstance(port_name, str):
            resolved_ports = [port for port in list(self.ports.values()) if port_name == port.name]
            if resolved_ports:
                return resolved_ports[0]
        return None

    def finalize_config(self, dps):
        """Perform consistency checks after initial config parsing."""

        dp_by_name = {}
        vlan_by_name = {}

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
                'VLAN must be type %s or %s not %s' % (str, int, type(vlan_name))))
            if vlan_name in vlan_by_name:
                return vlan_by_name[vlan_name]
            if vlan_name in self.vlans:
                return self.vlans[vlan_name]
            return None

        def resolve_stack_dps():
            """Resolve DP references in stacking config."""
            port_stack_dp = {}
            for port in self.stack_ports:
                stack_dp = port.stack['dp']
                test_config_condition(stack_dp not in dp_by_name, (
                    'stack DP %s not defined' % stack_dp))
                port_stack_dp[port] = dp_by_name[stack_dp]
            for port, dp in list(port_stack_dp.items()):
                port.stack['dp'] = dp
                stack_port = dp.resolve_port(port.stack['port'])
                test_config_condition(stack_port is None, (
                    'stack port %s not defined in DP %s' % (port.stack['port'], dp.name)))
                port.stack['port'] = stack_port

        def resolve_mirror_destinations():
            """Resolve mirror port references and destinations."""
            mirror_from_port = defaultdict(list)
            for mirror_port in list(self.ports.values()):
                if mirror_port.mirror is not None:
                    mirrored_ports = resolve_ports(mirror_port.mirror)
                    test_config_condition(len(mirrored_ports) != len(mirror_port.mirror), (
                        'port mirror not defined in DP %s' % self.name))
                    for mirrored_port in mirrored_ports:
                        mirror_from_port[mirrored_port].append(mirror_port)

            # TODO: confusingly, mirror at config time means what ports to mirror from.
            # But internally we use as a list of ports to mirror to.
            for mirrored_port, mirror_ports in list(mirror_from_port.items()):
                mirrored_port.mirror = []
                for mirror_port in mirror_ports:
                    mirrored_port.mirror.append(mirror_port.number)
                    mirror_port.output_only = True

        def resolve_override_output_ports():
            """Resolve override output ports."""
            for port_no, port in list(self.ports.items()):
                if port.override_output_port:
                    port.override_output_port = self.resolve_port(port.override_output_port)
                    test_config_condition(not port.override_output_port, (
                        'override_output_port port not defined'))
                    self.ports[port_no] = port

        def resolve_acl(acl_in, vid):
            """Resolve an individual ACL."""
            test_config_condition(acl_in not in self.acls, (
                'missing ACL %s in DP: %s' % (acl_in, self.name)))
            acl = self.acls[acl_in]
            def resolve_port_cb(port_name):
                port = self.resolve_port(port_name)
                if port:
                    return port.number
                return port

            acl.resolve_ports(resolve_port_cb)

            for meter_name in acl.get_meters():
                test_config_condition(meter_name not in self.meters, (
                    'meter %s is not configured' % meter_name))
            for port_no in acl.get_mirror_destinations():
                port = self.ports[port_no]
                port.output_only = True
            return acl.build(vid, self.meters)

        def verify_acl_exact_match(acls):
            for acl in acls:
                test_config_condition(acl.exact_match != acls[0].exact_match, (
                    'ACLs when used together must have consistent exact_match'))
            return acls[0].exact_match

        def resolve_acls(valve_cl):
            """Resolve config references in ACLs."""
            # TODO: move this config validation to ACL object.
            port_acl_enabled = valve_cl.STATIC_TABLE_IDS
            port_acl_matches = {}
            port_acl_set_fields = set()
            port_acl_exact_match = False
            port_acl_meter = False
            vlan_acl_matches = {}
            vlan_acl_exact_match = False
            vlan_acl_set_fields = set()
            vlan_acl_meter = False

            def merge_matches(matches, new_matches):
                for field, has_mask in list(new_matches.items()):
                    if has_mask or field not in matches:
                        matches[field] = has_mask

            for vlan in list(self.vlans.values()):
                if vlan.acls_in:
                    acls = []
                    for acl in vlan.acls_in:
                        matches, set_fields, meter = resolve_acl(acl, vlan.vid)
                        merge_matches(vlan_acl_matches, matches)
                        vlan_acl_set_fields = vlan_acl_set_fields.union(set_fields)
                        if meter:
                            vlan_acl_meter = True
                        acls.append(self.acls[acl])
                    vlan.acls_in = acls
                    vlan_acl_exact_match = verify_acl_exact_match(acls)
            for port in list(self.ports.values()):
                if port.acls_in:
                    test_config_condition(self.dp_acls, (
                        'dataplane ACLs cannot be used with port ACLs.'))
                    acls = []
                    for acl in port.acls_in:
                        matches, set_fields, meter = resolve_acl(acl, None)
                        merge_matches(port_acl_matches, matches)
                        port_acl_set_fields = port_acl_set_fields.union(set_fields)
                        if meter:
                            port_acl_meter = True
                        acls.append(self.acls[acl])
                    port.acls_in = acls
                    port_acl_exact_match = verify_acl_exact_match(acls)
                    port_acl_enabled = True
            if self.dp_acls:
                acls = []
                for acl in self.acls:
                    matches, set_fields, meter = resolve_acl(acl, None)
                    merge_matches(port_acl_matches, matches)
                    port_acl_set_fields = port_acl_set_fields.union(set_fields)
                    if meter:
                        port_acl_meter = True
                    acls.append(self.acls[acl])
                self.dp_acls = acls
                port_acl_enabled = True
            if port_acl_enabled:
                port_acl_matches.update({'in_port': False})
            port_acl_matches = {(field, mask) for field, mask in list(port_acl_matches.items())}
            vlan_acl_matches = {(field, mask) for field, mask in list(vlan_acl_matches.items())}

            # TODO: skip port_acl table if not configured.
            # TODO: dynamically configure output attribue
            override_table_config = {
                'port_acl': ValveTableConfig(
                    'port_acl',
                    exact_match=port_acl_exact_match,
                    meter=port_acl_meter,
                    output=True,
                    match_types=port_acl_matches,
                    set_fields=tuple(port_acl_set_fields)),
                'vlan_acl': ValveTableConfig(
                    'vlan_acl',
                    exact_match=vlan_acl_exact_match,
                    meter=vlan_acl_meter,
                    output=True,
                    match_types=vlan_acl_matches,
                    set_fields=tuple(vlan_acl_set_fields)),
            }
            return override_table_config

        def resolve_vlan_names_in_routers():
            """Resolve VLAN references in routers."""
            dp_routers = {}
            for router_name, router in list(self.routers.items()):
                vlans = []
                for vlan_name in router.vlans:
                    vlan = resolve_vlan(vlan_name)
                    if vlan is not None:
                        vlans.append(vlan)
                if len(vlans) > 1:
                    dp_router = copy.copy(router)
                    dp_router.vlans = vlans
                    dp_routers[router_name] = dp_router
                vips = set()
                for vlan in vlans:
                    for vip in vlan.faucet_vips:
                        if vip.ip.is_link_local:
                            continue
                        vips.add(vip)
                for vip in vips:
                    for other_vip in vips - set([vip]):
                        test_config_condition(
                            vip.ip in other_vip.network,
                            'VIPs %s and %s overlap in router %s' % (
                                vip, other_vip, router_name))
            self.routers = dp_routers

        test_config_condition(not self.vlans, 'no VLANs referenced by interfaces in %s' % self.name)
        valve_cl = SUPPORTED_HARDWARE.get(self.hardware, None)
        test_config_condition(
            not valve_cl, 'hardware %s must be in %s' % (
                self.hardware, list(SUPPORTED_HARDWARE.keys())))

        for dp in dps:
            dp_by_name[dp.name] = dp
        for vlan in list(self.vlans.values()):
            vlan_by_name[vlan.name] = vlan
            if self.global_vlan:
                test_config_condition(
                    self.global_vlan == vlan.vid, 'VLAN %u is reserved by global_vlan' % vlan.vid)

        resolve_stack_dps()
        resolve_mirror_destinations()
        resolve_override_output_ports()
        resolve_vlan_names_in_routers()
        override_table_config = resolve_acls(valve_cl)

        # Only configure IP routing tables if enabled.
        ipvs = set()
        for vlan in list(self.vlans.values()):
            ipvs = ipvs.union(vlan.ipvs())
        for ipv in (4, 6):
            if ipv not in ipvs:
                table_name = 'ipv%u_fib' % ipv
                override_table_config[table_name] = ValveTableConfig(table_name)
        if not ipvs:
            override_table_config['vip'] = ValveTableConfig('vip')

        vlan_port_factor = len(self.vlans) * len(self.ports)
        self._configure_tables(override_table_config, valve_cl, vlan_port_factor)

        bgp_vlans = self.bgp_vlans()
        if bgp_vlans:
            for vlan in bgp_vlans:
                vlan_dps = [dp for dp in dps if vlan.vid in dp.vlans]
                test_config_condition(len(vlan_dps) != 1, (
                    'DPs %s sharing a BGP speaker VLAN is unsupported'))
            router_ids = {vlan.bgp_routerid for vlan in bgp_vlans}
            test_config_condition(len(router_ids) != 1, 'BGP router IDs must all be the same')
            bgp_ports = {vlan.bgp_port for vlan in bgp_vlans}
            test_config_condition(len(bgp_ports) != 1, 'BGP ports must all be the same')
            for vlan in bgp_vlans:
                test_config_condition(vlan.bgp_server_addresses != (
                    bgp_vlans[0].bgp_server_addresses), (
                        'BGP server addresses must all be the same'))

        for port in list(self.ports.values()):
            port.finalize()
        for vlan in list(self.vlans.values()):
            vlan.finalize()
        for acl in list(self.acls.values()):
            acl.finalize()
        for router in list(self.routers.values()):
            router.finalize()
        self.finalize()

    def get_native_vlan(self, port_num):
        """Return native VLAN for a port by number, or None."""
        if port_num in self.ports:
            return self.ports[port_num].native_vlan
        return None

    def bgp_vlans(self):
        """Return list of VLANs with BGP enabled."""
        return tuple([vlan for vlan in list(self.vlans.values()) if vlan.bgp_as])

    def dot1x_ports(self):
        """Return list of ports with 802.1x enabled."""
        return tuple([port for port in list(self.ports.values()) if port.dot1x])

    def to_conf(self):
        """Return DP config as dict."""
        result = super(DP, self).to_conf()
        if result is not None:
            if 'stack' in result:
                if result['stack'] is not None:
                    result['stack'] = {
                        'root_dp': str(self.stack['root_dp'])
                    }
            interface_dict = {}
            for port in list(self.ports.values()):
                interface_dict[port.name] = port.to_conf()
            result['interfaces'] = interface_dict
        return result

    def get_tables(self):
        """Return tables as dict for API call."""
        result = {}
        for table_name, table in list(self.tables.items()):
            result[table_name] = table.table_id
        return result

    def get_config_dict(self):
        """Return DP config as a dict for API call."""
        vlans_dict = {}
        for vlan in list(self.vlans.values()):
            vlans_dict[vlan.name] = vlan.to_conf()
        acls_dict = {}
        for acl_id, acl in list(self.acls.items()):
            acls_dict[acl_id] = acl.to_conf()
        return {
            'dps': {self.name: self.to_conf()},
            'vlans': vlans_dict,
            'acls': acls_dict}

    def _get_acl_config_changes(self, logger, new_dp):
        """Detect any config changes to ACLs.

        Args:
            logger (ValveLogger): logger instance.
            new_dp (DP): new dataplane configuration.
        Returns:
            changed_acls (dict): ACL ID map to new/changed ACLs.
        """
        changed_acls = {}
        for acl_id, new_acl in list(new_dp.acls.items()):
            if acl_id not in self.acls:
                changed_acls[acl_id] = new_acl
                logger.info('ACL %s new' % acl_id)
            else:
                if new_acl != self.acls[acl_id]:
                    changed_acls[acl_id] = new_acl
                    logger.info('ACL %s changed' % acl_id)
        return changed_acls

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
        deleted_vlans = set([])
        for vid in list(self.vlans.keys()):
            if vid not in new_dp.vlans:
                deleted_vlans.add(vid)

        changed_vlans = set([])
        for vid, new_vlan in list(new_dp.vlans.items()):
            if vid not in self.vlans:
                changed_vlans.add(vid)
                logger.info('VLAN %s added' % vid)
            else:
                old_vlan = self.vlans[vid]
                if old_vlan != new_vlan:
                    if not old_vlan.ignore_subconf(new_vlan):
                        changed_vlans.add(vid)
                        logger.info('VLAN %s config changed' % vid)
                else:
                    # Preserve current VLAN including current
                    # dynamic state like caches, if VLAN and ports
                    # did not change at all.
                    new_dp.vlans[vid].merge_dyn(old_vlan)

        if not deleted_vlans and not changed_vlans:
            logger.info('no VLAN config changes')

        return (deleted_vlans, changed_vlans)

    def _get_port_config_changes(self, logger, new_dp, changed_vlans, changed_acls):
        """Detect any config changes to ports.

        Args:
            logger (ValveLogger): logger instance.
            new_dp (DP): new dataplane configuration.
            changed_vlans (set): changed/added VLAN IDs.
            changed_acls (dict): ACL ID map to new/changed ACLs.
        Returns:
            changes (tuple) of:
                all_ports_changed (bool): True if all ports changed.
                deleted_ports (set): deleted port numbers.
                changed_ports (set): changed/added port numbers.
                changed_acl_ports (set): changed ACL only port numbers.
        """
        all_ports_changed = False
        changed_ports = set([])
        changed_acl_ports = set([])

        for port_no, new_port in list(new_dp.ports.items()):
            if port_no not in self.ports:
                # Detected a newly configured port
                changed_ports.add(port_no)
                logger.info('port %s added' % port_no)
            else:
                old_port = self.ports[port_no]
                # An existing port has configs changed
                if new_port != old_port:
                    # ACL optimization - did the ACL, and only the ACL change.
                    if old_port.ignore_subconf(new_port, ignore_keys=set(['acls_in'])):
                        if old_port.acls_in != new_port.acls_in:
                            changed_acl_ports.add(port_no)
                            old_acl_ids = old_port.acls_in
                            if old_acl_ids:
                                old_acl_ids = [acl._id for acl in old_acl_ids]
                            new_acl_ids = new_port.acls_in
                            if new_acl_ids:
                                new_acl_ids = [acl._id for acl in new_acl_ids]
                            logger.info('port %s ACL changed (ACL %s to %s)' % (
                                port_no, old_acl_ids, new_acl_ids))
                    else:
                        changed_ports.add(port_no)
                        logger.info('port %s reconfigured (%s)' % (
                            port_no, diff(old_port.to_conf(), new_port.to_conf(), context=1)))
                elif new_port.acls_in:
                    port_acls_changed = [acl for acl in new_port.acls_in if acl in changed_acls]
                    if port_acls_changed:
                        changed_acl_ports.add(port_no)
                        logger.info('port %s ACL changed (ACL %s content changed)' % (
                            port_no, port_acls_changed))

        # TODO: optimize case where only VLAN ACL changed.
        for vid in changed_vlans:
            for port in new_dp.vlans[vid].get_ports():
                changed_ports.add(port.number)

        deleted_ports = set(list(self.ports.keys())) - set(list(new_dp.ports.keys()))
        if deleted_ports:
            logger.info('deleted ports: %s' % deleted_ports)

        if changed_ports == set(new_dp.ports.keys()):
            all_ports_changed = True
        elif (not changed_ports and
              not deleted_ports and
              not changed_acl_ports):
            logger.info('no port config changes')

        return (all_ports_changed, deleted_ports,
                changed_ports, changed_acl_ports)

    def get_config_changes(self, logger, new_dp):
        """Detect any config changes.

        Args:
            logger (ValveLogger): logger instance
            new_dp (DP): new dataplane configuration.
        Returns:
            (tuple): changes tuple containing:

                deleted_ports (set): deleted port numbers.
                changed_ports (set): changed/added port numbers.
                changed_acl_ports (set): changed ACL only port numbers.
                deleted_vlans (set): deleted VLAN IDs.
                changed_vlans (set): changed/added VLAN IDs.
                all_ports_changed (bool): True if all ports changed.
        """
        def _table_configs(dp):
            return frozenset([
                table.table_config for table in list(dp.tables.values())])

        if self.ignore_subconf(new_dp):
            logger.info('DP base level config changed - requires cold start')
        elif _table_configs(self) != _table_configs(new_dp):
            logger.info('pipeline table config change - requires cold start')
        elif new_dp.routers != self.routers:
            logger.info('DP routers config changed - requires cold start')
        else:
            changed_acls = self._get_acl_config_changes(logger, new_dp)
            deleted_vlans, changed_vlans = self._get_vlan_config_changes(logger, new_dp)
            (all_ports_changed, deleted_ports,
             changed_ports, changed_acl_ports) = self._get_port_config_changes(
                 logger, new_dp, changed_vlans, changed_acls)
            return (deleted_ports, changed_ports, changed_acl_ports,
                    deleted_vlans, changed_vlans, all_ports_changed)
        # default cold start
        return (set(), set(), set(), set(), set(), True)
