"""Configuration for a datapath."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
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
import netaddr

from collections import namedtuple, defaultdict
from datadiff import diff
from netaddr.core import AddrFormatError
import networkx

from faucet import faucet_pipeline
from faucet import valve_acl
from faucet import valve_of
from faucet.conf import Conf, InvalidConfigError
from faucet.valve_table import ValveTable, ValveGroupTable
from faucet.valve_util import get_setting
from faucet.valve_packet import FAUCET_MAC


# Documentation generated using documentation_generator.py
# For attributues to be included in documentation they must
# have a default value, and their descriptor must come
# immediately after being set. See below for example.
class DP(Conf):
    """Stores state related to a datapath controlled by Faucet, including
configuration.
"""

    acls = None
    vlans = None
    interfaces = None # config
    interface_ranges = None
    ports = None
    routers = None
    running = False
    name = None
    dp_id = None
    cookie = None
    configured = False
    priority_offset = None
    low_priority = None
    high_priority = None
    stack = None
    stack_ports = None
    output_only_ports = None
    ignore_learn_ins = None
    drop_broadcast_source_address = None
    drop_spoofed_faucet_mac = None
    drop_bpdu = None
    drop_lldp = None
    groups = None
    group_table = False
    group_table_routing = False
    max_hosts_per_resolve_cycle = None
    max_host_fib_retry_count = None
    max_resolve_backoff_time = None
    packetin_pps = None
    learn_jitter = None
    learn_ban_timeout = None
    advertise_interval = None
    proactive_learn = None
    pipeline_config_dir = None
    use_idle_timeout = None
    tables = {} # type: dict
    tables_by_id = {} # type: dict
    meters = {} # type: dict
    timeout = None
    arp_neighbor_timeout = None
    lldp_beacon = {} # type: dict
    metrics_rate_limit_sec = None
    faucet_dp_mac = None
    combinatorial_port_flood = None

    dyn_last_coldstart_time = None

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
        'drop_bpdu': True,
        # By default drop STP BPDU frames
        'drop_lldp': True,
        # By default, drop LLDP. Set to False, to enable NFV offload of LLDP.
        'group_table': False,
        # Use GROUP tables for VLAN flooding
        'group_table_routing': False,
        # Use GROUP tables for routing (nexthops)
        'max_hosts_per_resolve_cycle': 5,
        # Max hosts to try to resolve per gateway resolution cycle.
        'max_host_fib_retry_count': 10,
        # Max number of times to retry resolution of a host FIB route.
        'max_resolve_backoff_time': 32,
        # Max number of seconds to back off to when resolving nexthops.
        'packetin_pps': 0,
        # Ask switch to rate limit packet pps. TODO: Not supported by OVS in 2.7.0
        'learn_jitter': 10,
        # Jitter learn timeouts by up to this many seconds
        'learn_ban_timeout': 10,
        # When banning/limiting learning, wait this many seconds before learning can be retried
        'advertise_interval': 30,
        # How often to advertise (eg. IPv6 RAs)
        'proactive_learn': True,
        # whether proactive learning is enabled for IP nexthops
        'pipeline_config_dir': get_setting('FAUCET_PIPELINE_DIR', True),
        # where config files for pipeline are stored (if any).
        'use_idle_timeout': False,
        # Turn on/off the use of idle timeout for src_table, default OFF.
        'lldp_beacon': {},
        # Config for LLDP beacon service.
        'metrics_rate_limit_sec': 0,
        # Rate limit metric updates - don't update metrics if last update was less than this many seconds ago.
        'faucet_dp_mac': FAUCET_MAC,
        # MAC address of packets sent by FAUCET, not associated with any VLAN.
        'combinatorial_port_flood': False,
        # if True, use a seperate output flow for each input port on this VLAN.
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
        'group_table_routing': bool,
        'max_hosts_per_resolve_cycle': int,
        'max_host_fib_retry_count': int,
        'max_resolve_backoff_time': int,
        'packetin_pps': int,
        'learn_jitter': int,
        'learn_ban_timeout': int,
        'advertise_interval': int,
        'proactive_learn': bool,
        'pipeline_config_dir': str,
        'use_idle_timeout': bool,
        'lldp_beacon': dict,
        'metrics_rate_limit_sec': int,
        'faucet_dp_mac': str,
        'combinatorial_port_flood': bool,
    }

    stack_defaults_types = {
        'priority': int,
    }

    lldp_beacon_defaults_types = {
        'send_interval': int,
        'max_per_interval': int,
        'system_name': str,
    }

    wildcard_table = ValveTable(
        valve_of.ofp.OFPTT_ALL, 'all', None, flow_cookie=0)


    def __init__(self, _id, dp_id, conf):
        """Constructs a new DP object"""
        super(DP, self).__init__(_id, dp_id, conf)
        self.acls = {}
        self.vlans = {}
        self.ports = {}
        self.routers = {}
        self.stack_ports = []
        self.output_only_ports = []
        self.lldp_beacon_ports = []

    def __str__(self):
        return self.name

    def check_config(self):
        assert isinstance(self.dp_id, int), 'dp_id must be %s not %s' % (int, type(self.dp_id))
        assert self.dp_id > 0 and self.dp_id <= 2**64-1, 'DP ID %s not in valid range' % self.dp_id
        assert netaddr.valid_mac(self.faucet_dp_mac), 'invalid MAC address %s' % self.faucet_dp_mac
        assert not (self.group_table and self.group_table_routing), (
            'groups for routing and other functions simultaneously not supported')
        assert (self.interfaces or self.interface_ranges), (
            'DP %s must have at least one interface' % self)
        # To prevent L2 learning from timing out before L3 can refresh
        assert self.timeout >= self.arp_neighbor_timeout, 'L2 timeout must be >= L3 timeout'
        if self.lldp_beacon:
            self._check_conf_types(self.lldp_beacon, self.lldp_beacon_defaults_types)
            assert 'send_interval' in self.lldp_beacon, (
                'lldp_beacon send_interval not set')
            assert 'max_per_interval' in self.lldp_beacon, (
                'lldp_beacon max_per_interval not set')
            self.lldp_beacon = self._set_unknown_conf(
                self.lldp_beacon, self.lldp_beacon_defaults_types)
            if self.lldp_beacon['system_name'] is None:
                self.lldp_beacon['system_name'] = self.name
        if self.stack:
            self._check_conf_types(self.stack, self.stack_defaults_types)

    def _configure_tables(self):
        """Configure FAUCET pipeline of tables with matches."""
        self.groups = ValveGroupTable()
        for table_id, table_config in enumerate(faucet_pipeline.FAUCET_PIPELINE):
            table_name, restricted_match_types = table_config
            self.tables[table_name] = ValveTable(
                table_id, table_name, restricted_match_types,
                self.cookie, notify_flow_removed=self.use_idle_timeout)
            self.tables_by_id[table_id] = self.tables[table_name]

    def set_defaults(self):
        super(DP, self).set_defaults()
        self._set_default('dp_id', self._id)
        self._set_default('name', str(self._id))
        self._set_default('lowest_priority', self.priority_offset)
        self._set_default('low_priority', self.priority_offset + 9000)
        self._set_default('high_priority', self.low_priority + 1)
        self._set_default('highest_priority', self.high_priority + 98)
        self._set_default('description', self.name)
        self._configure_tables()

    def match_tables(self, match_type):
        """Return list of tables with matches of a specific match type."""
        match_tables = []
        for table in list(self.tables_by_id.values()):
            if table.restricted_match_types is not None:
                if match_type in table.restricted_match_types:
                    match_tables.append(table)
            else:
                match_tables.append(table)
        return match_tables

    def in_port_tables(self):
        """Return list of tables that specify in_port as a match."""
        return self.match_tables('in_port')

    def vlan_match_tables(self):
        """Return list of tables that specify vlan_vid as a match."""
        return self.match_tables('vlan_vid')

    def all_valve_tables(self):
        """Return list of all Valve tables."""
        return list(self.tables_by_id.values())

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

    def resolve_stack_topology(self, dps):
        """Resolve inter-DP config for stacking."""

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

        root_dp = None
        stack_dps = []
        for dp in dps:
            if dp.stack is not None:
                stack_dps.append(dp)
                if 'priority' in dp.stack:
                    assert dp.stack['priority'] > 0, 'stack priority must be > 0'
                    assert root_dp is None, 'cannot have multiple stack roots'
                    root_dp = dp
                    for vlan in list(dp.vlans.values()):
                        assert vlan.faucet_vips == [], 'routing + stacking not supported'

        if root_dp is None:
            assert not stack_dps, 'stacking enabled but no root_dp'
            return

        edge_count = {}

        graph = networkx.MultiGraph()
        for dp in dps:
            if dp.stack_ports:
                graph.add_node(dp.name)
                for port in dp.stack_ports:
                    edge = canonical_edge(dp, port)
                    edge_a, edge_z = edge
                    edge_name = make_edge_name(edge_a, edge_z)
                    edge_attr = make_edge_attr(edge_a, edge_z)
                    edge_a_dp, _ = edge_a
                    edge_z_dp, _ = edge_z
                    if edge_name not in edge_count:
                        edge_count[edge_name] = 0
                    edge_count[edge_name] += 1
                    graph.add_edge(
                        edge_a_dp.name, edge_z_dp.name,
                        key=edge_name, port_map=edge_attr)
        if graph.size():
            for edge_name, count in list(edge_count.items()):
                assert count == 2, '%s defined only in one direction' % edge_name
            if self.name in graph:
                if self.stack is None:
                    self.stack = {}
                self.stack['root_dp'] = root_dp
                self.stack['graph'] = graph

    def shortest_path(self, dest_dp):
        """Return shortest path to a DP, as a list of DPs."""
        if self.stack is None:
            return None
        return networkx.shortest_path(
            self.stack['graph'], self.name, dest_dp)

    def shortest_path_to_root(self):
        """Return shortest path to root DP, as list of DPs."""
        if self.stack is not None:
            root_dp = self.stack['root_dp']
            if root_dp != self:
                return self.shortest_path(root_dp.name)
        return []

    def peer_stack_up_ports(self, peer_dp):
        """Return list of stack ports that are up towards a peer."""
        return [port for port in self.stack_ports if port.running() and port.stack['dp'].name == peer_dp]

    def shortest_path_port(self, dest_dp):
        """Return first port on our DP, that is the shortest path towards dest DP."""
        shortest_path = self.shortest_path(dest_dp)
        if shortest_path is not None:
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

    def finalize_config(self, dps):
        """Perform consistency checks after initial config parsing."""

        port_by_name = {}
        dp_by_name = {}
        vlan_by_name = {}

        def resolve_port(port_name):
            """Resolve port by name or number."""
            assert isinstance(port_name, (str, int)), (
                'Port must be type %s or %s not %s' % (str, int, type(port_name)))
            if port_name in port_by_name:
                return port_by_name[port_name]
            elif port_name in self.ports:
                return self.ports[port_name]
            return None

        def resolve_ports(port_names):
            """Resolve list of ports, by port by name or number."""
            resolved_ports = []
            for port_name in port_names:
                port = resolve_port(port_name)
                if port is not None:
                    resolved_ports.append(port)
            return resolved_ports

        def resolve_port_numbers(port_names):
            """Resolve list of ports to numbers, by port by name or number."""
            return [port.number for port in resolve_ports(port_names)]

        def resolve_vlan(vlan_name):
            """Resolve VLAN by name or VID."""
            assert isinstance(vlan_name, (str, int)), (
                'VLAN must be type %s or %s not %s' % (str, int, type(vlan_name)))
            if vlan_name in vlan_by_name:
                return vlan_by_name[vlan_name]
            elif vlan_name in self.vlans:
                return self.vlans[vlan_name]
            return None

        def resolve_stack_dps():
            """Resolve DP references in stacking config."""
            port_stack_dp = {}
            for port in self.stack_ports:
                stack_dp = port.stack['dp']
                assert stack_dp in dp_by_name, 'stack DP %s not defined' % stack_dp
                port_stack_dp[port] = dp_by_name[stack_dp]
            for port, dp in list(port_stack_dp.items()):
                port.stack['dp'] = dp
                stack_port_name = port.stack['port']
                assert stack_port_name in dp.ports, 'stack port %s not defined in DP %s' % (
                    stack_port_name, dp.name)
                port.stack['port'] = dp.ports[stack_port_name]

        def resolve_mirror_destinations():
            """Resolve mirror port references and destinations."""
            mirror_from_port = defaultdict(list)
            for mirror_port in list(self.ports.values()):
                if mirror_port.mirror is not None:
                    mirrored_ports = resolve_ports(mirror_port.mirror)
                    assert len(mirrored_ports) == len(mirror_port.mirror), (
                        'port mirror not defined in DP %s' % self.name)
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
                    port.override_output_port = resolve_port(port.override_output_port)
                    assert port.override_output_port, (
                        'override_output_port port not defined')
                    self.ports[port_no] = port

        def resolve_acl(acl_in):
            """Resolve an individual ACL."""
            assert acl_in in self.acls, (
                'missing ACL %s on %s' % (self.name, acl_in))
            acl = self.acls[acl_in]
            mirror_destinations = set()

            def resolve_meter(_acl, action_conf):
                meter_name = action_conf
                assert meter_name in self.meters, (
                    'meter %s is not configured' % meter_name)
                return action_conf

            def resolve_mirror(acl, action_conf):
                port_name = action_conf
                port = resolve_port(port_name)
                # If this DP does not have this port, do nothing.
                if port is not None:
                    action_conf = port.number
                    mirror_destinations.add(port.number)
                    return action_conf
                return None

            def resolve_output(_acl, action_conf):
                resolved_action_conf = {}
                assert isinstance(action_conf, dict)
                for output_action, output_action_values in list(action_conf.items()):
                    if output_action == 'port':
                        port_name = output_action_values
                        port = resolve_port(port_name)
                        # If this DP does not have this port, do not output.
                        if port is not None:
                            resolved_action_conf[output_action] = port.number
                    elif output_action == 'ports':
                        resolved_action_conf[output_action] = resolve_port_numbers(
                            output_action_values)
                    elif output_action == 'failover':
                        failover = output_action_values
                        assert isinstance(failover, dict)
                        resolved_action_conf[output_action] = {}
                        for failover_name, failover_values in list(failover.items()):
                            if failover_name == 'ports':
                                failover_values = resolve_port_numbers(failover_values)
                            resolved_action_conf[output_action][failover_name] = failover_values
                    else:
                        resolved_action_conf[output_action] = output_action_values
                if resolved_action_conf:
                    return resolved_action_conf
                return None

            def resolve_noop(_acl, action_conf):
                return action_conf

            action_resolvers = {
                'meter': resolve_meter,
                'mirror': resolve_mirror,
                'output': resolve_output,
                'allow': resolve_noop,
                'force_port_vlan': resolve_noop,
            }

            def build_acl(acl, vid=None):
                """Check that ACL can be built from config and mark mirror destinations."""
                if acl.rules:
                    null_dp = namedtuple('null_dp', 'ofproto')
                    null_dp.ofproto = valve_of.ofp
                    try:
                        ofmsgs = valve_acl.build_acl_ofmsgs(
                            [acl], self.wildcard_table,
                            valve_of.goto_table(self.wildcard_table),
                            valve_of.goto_table(self.wildcard_table),
                            2**16-1, self.meters, acl.exact_match,
                            vlan_vid=vid)
                        assert ofmsgs
                        for ofmsg in ofmsgs:
                            ofmsg.datapath = null_dp
                            ofmsg.set_xid(0)
                            ofmsg.serialize()
                    except (AddrFormatError, KeyError, ValueError) as err:
                        raise InvalidConfigError(err)
                    for port_no in mirror_destinations:
                        port = self.ports[port_no]
                        port.output_only = True

            for rule_conf in acl.rules:
                for attrib, attrib_value in list(rule_conf.items()):
                    if attrib == 'actions':
                        resolved_actions = {}
                        assert isinstance(attrib_value, dict)
                        for action_name, action_conf in list(attrib_value.items()):
                            resolved_action_conf = action_resolvers[action_name](
                                acl, action_conf)
                            assert resolved_action_conf is not None, (
                                'cannot resolve ACL rule %s' % rule_conf)
                            resolved_actions[action_name] = resolved_action_conf
                        rule_conf[attrib] = resolved_actions

            build_acl(acl, vid=1)

        def verify_acl_exact_match(acls):
            for acl in acls:
                assert acl.exact_match == acls[0].exact_match, (
                    'ACLs when used together must have consistent exact_match')

        def resolve_acls():
            """Resolve config references in ACLs."""
            # TODO: move this config validation to ACL object.

            for vlan in list(self.vlans.values()):
                if vlan.acls_in:
                    acls = []
                    for acl in vlan.acls_in:
                        resolve_acl(acl)
                        acls.append(self.acls[acl])
                    vlan.acls_in = acls
                    verify_acl_exact_match(acls)
            for port in list(self.ports.values()):
                if port.acls_in:
                    acls = []
                    for acl in port.acls_in:
                        resolve_acl(acl)
                        acls.append(self.acls[acl])
                    port.acls_in = acls
                    verify_acl_exact_match(acls)

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
            self.routers = dp_routers

        assert self.vlans, 'no VLANs referenced by interfaces in %s' % self.name

        for port in list(self.ports.values()):
            port_by_name[port.name] = port
        for dp in dps:
            dp_by_name[dp.name] = dp
        for vlan in list(self.vlans.values()):
            vlan_by_name[vlan.name] = vlan

        resolve_stack_dps()
        resolve_mirror_destinations()
        resolve_override_output_ports()
        resolve_vlan_names_in_routers()
        resolve_acls()

        bgp_vlans = self.bgp_vlans()
        if bgp_vlans:
            for vlan in bgp_vlans:
                vlan_dps = [dp for dp in dps if vlan.vid in dp.vlans]
                assert len(vlan_dps) == 1, (
                    'DPs %s sharing a BGP speaker VLAN is unsupported')
            router_ids = set([vlan.bgp_routerid for vlan in bgp_vlans])
            assert len(router_ids) == 1, 'BGP router IDs must all be the same'
            bgp_ports = set([vlan.bgp_port for vlan in bgp_vlans])
            assert len(bgp_ports) == 1, 'BGP ports must all be the same'
            for vlan in bgp_vlans:
                assert vlan.bgp_server_addresses == bgp_vlans[0].bgp_server_addresses, (
                    'BGP server addresses must all be the same')

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
        return [vlan for vlan in list(self.vlans.values()) if vlan.bgp_as]

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
        if self.name:
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
        return {}

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
        if self.ignore_subconf(new_dp):
            logger.info('DP base level config changed - requires cold start')
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
