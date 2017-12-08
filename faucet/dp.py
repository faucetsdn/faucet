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

from datadiff import diff
from netaddr.core import AddrFormatError
import networkx

from faucet.conf import Conf, InvalidConfigError
from faucet.valve_table import ValveTable, ValveGroupTable
from faucet.valve_util import get_setting
from faucet import valve_acl
from faucet import valve_of


# Documentation generated using documentation_generator.py
# For attributues to be included in documentation they must
# have a default value, and their descriptor must come
# immediately after being set. See below for example.
class DP(Conf):
    """Stores state related to a datapath controlled by Faucet, including
configuration.

Datapath Configuration

DP configuration is entered in the 'dps' configuration block. The 'dps'
configuration contains a dictionary of configuration blocks each
containing the configuration for one datapath. The keys can either be
string names given to the datapath, or the OFP datapath id.

The following elements can be configured for each datapath (at the
dps/<name or dp_id>/ level of the configuration file):

 * dp_id (int): the OFP datapath-id of this datapath. Defaults to the
    configuration key
 * name (string): a name to reference the datapath by. Defaults to the
    configuration key
 * hardware (string): the hardware model of the datapath. Defaults to "Open
    vSwitch". Other options can be seen in the documentation for valve.py
 * ignore_learn_ins (int): Ignore every approx nth packet for learning.
    2 will ignore 1 out of 2 packets; 3 will ignore 1 out of 3 packets.  This
    limits control plane activity when learning new hosts rapidly.  Flooding
    will still be done by the dataplane even with a packet is ignored for
    learning purposes. Defaults to 3.
 * drop_broadcast_source_address (bool): If True, Faucet will drop any packet
    from a broadcast source address: Defaults to True.
 * drop_bpdu (bool): If True, Faucet will drop all STP BPDUs arriving at
    the datapath. NB: Faucet does not handle BPDUs itself, if you disable this
    then you either need to configure an ACL to catch BDPUs or Faucet will
    forward them as though they were normal traffic. Defaults to True.
 * drop_spoofed_faucet_mac (bool): If True, Faucet will drop any packet
    it receives with an ethernet source address equal to a MAC address that
    Faucet is using. Defaults to True.
 * drop_lldp (bool): If True, Faucet will drop all LLDP traffic arriving at
    the datapath. NB: Faucet does not handle LLDP itself, if you disable this
    then you either need to configure an ACL to handle LLDP packets or Faucet
    will forward them as though they were normal traffic. Defaults to True.
 * group_table (bool): If True, Faucet will use the OpenFlow Group tables to
    flood packets. This is an experimental feature that is not fully supported
    by all devices and may not interoperate with all features of faucet.
    Defaults to False
 * group_table_routing (bool): If True, Faucet will use the OpenFlow Group
    tables to combine the actions for each next hop.
 * max_hosts_per_resolve_cycle (int): Limit the number of hosts resolved per
    cycle. Defaults to 5.
 * max_host_fib_retry_count (int): Limit the number of times Faucet will
    attempt to resolve a next-hop's l2 address. Defaults to 10.
 * max_resolve_backoff_time (int): When resolving next hop l2 addresses, Faucet
    will back off exponentially until it reaches this value. Defaults to 32.
 * learn_jitter (int): In order to reduce load on the controller Faucet will
    randomly vary the timeout for learnt mac addresses by up to this number of
    seconds. Defaults to 10.
 * learn_ban_timeout (int): When a host is rapidly moving between ports Faucet
    will stop learning mac addresses on one of the ports for this number of
    seconds. Defaults to 10.
 * advertise_interval (int): Interval between sending IPv6 Router
    Advertisements. Defaults to 30.
 * proactive_learn (bool): When False directly connected hosts are added to the
    list of targets to resolve whenever Faucet sees a packet from them (eg a
    neighbour solicitation or for l2 learning etc.). When
    proactive_learn is True Faucet will forward all packets to unknown IPv6
    addresses in directly connected subnets to the controller and then attempt
    to resolve the destination addresses. This causes more controller traffic
    and could be a DOS vector, but causes fewer lost packets when resolving
    addresses. Defaults to True.
 * pipeline_config_dir (str): the location of the faucet pipeline file. By
    default it will attempt to read from FAUCET_PIPELINE_DIR environment
    variable.

Further sublevels of configuration can be configured as follows:

 * interfaces: contains the config block for Port configuration
    (documented in port.py)
 * interface_ranges: contains the config blocks for sets of multiple
    interfaces. The configuration entered here will be used as the defaults for
    these interfaces. This can be overwritten by configuring those interfaces
    directly. The format for the configuration key is a comma separated string.
    The elements can either be the name or number of an interface or a range of
    port numbers eg: "1-6,8,port9".
 * stack: Contains the configuration block for stacking. Stacking is an
    experimental approach to loop prevention that is still under development.
    This can be configured as follows:

    * priority (int): currently setting any value for stack priority indicates
        that this datapath should be the root for the stacking topology.
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
    tables = {}
    tables_by_id = {}
    meters = {}
    timeout = None
    arp_neighbor_timeout = None

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
        'ignore_learn_ins': 3,
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
        'pipeline_config_dir': get_setting('FAUCET_PIPELINE_DIR'),
        # where config files for pipeline are stored (if any).
        'use_idle_timeout': False,
        # Turn on/off the use of idle timeout for src_table, default OFF.
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

    def __str__(self):
        return self.name

    def check_config(self):
        assert self.dp_id > 0 and self.dp_id <= 2**64-1, 'DP ID %s not in valid range' % self.dp_id
        assert not (self.group_table and self.group_table_routing), (
            'groups for routing and other functions simultaneously not supported')
        assert (self.interfaces or self.interface_ranges), (
            'DP %s must have at least one interface' % self)
        # To prevent L2 learning from timing out before L3 can refresh
        assert self.timeout >= self.arp_neighbor_timeout, 'L2 timeout must be >= L3 timeout'

    def _configure_tables(self):
        """Configure FAUCET pipeline of tables with matches."""
        self.groups = ValveGroupTable()
        for table_id, table_config in enumerate((
                ('port_acl', None),
                ('vlan', ('eth_dst', 'eth_type', 'in_port', 'vlan_vid')),
                ('vlan_acl', None),
                ('eth_src', ('eth_dst', 'eth_src', 'eth_type', 'in_port', 'vlan_vid')),
                ('ipv4_fib', ('eth_type', 'ipv4_dst', 'vlan_vid')),
                ('ipv6_fib', ('eth_type', 'ipv6_dst', 'vlan_vid')),
                ('vip', ('arp_tpa', 'eth_dst', 'eth_type', 'icmpv6_type', 'ip_proto')),
                ('eth_dst', ('eth_dst', 'in_port', 'vlan_vid')),
                ('flood', ('eth_dst', 'in_port', 'vlan_vid')))):
            table_name, restricted_match_types = table_config
            self.tables[table_name] = ValveTable(
                table_id, table_name, restricted_match_types,
                self.cookie, notify_flow_removed=self.use_idle_timeout)
            self.tables_by_id[table_id] = self.tables[table_name]

    def set_defaults(self):
        super(DP, self).set_defaults()
        self._set_default('dp_id', self._id)
        self._set_default('name', str(self._id))
        self._set_default('lowest_priority', self.priority_offset) # pytype: disable=none-attr
        self._set_default('low_priority', self.priority_offset + 9000) # pytype: disable=none-attr
        self._set_default('high_priority', self.low_priority + 1) # pytype: disable=none-attr
        self._set_default('highest_priority', self.high_priority + 98) # pytype: disable=none-attr
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
        if port.mirror is not None:
            # other configuration entries ignored
            return
        if port.stack is not None:
            self.stack_ports.append(port)

    def add_vlan(self, vlan):
        """Add a VLAN to this datapath."""
        self.vlans[vlan.vid] = vlan

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

    def finalize_config(self, dps):
        """Perform consistency checks after initial config parsing."""

        def resolve_port_no(port_name):
            """Resolve port by name or number."""
            if port_name in port_by_name:
                return port_by_name[port_name].number
            elif port_name in self.ports:
                return port_name
            return None

        def resolve_vlan(vlan_name):
            """Resolve VLAN by name or VID."""
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
                port_stack_dp[port] = dp_by_name[stack_dp]
            for port, dp in list(port_stack_dp.items()):
                port.stack['dp'] = dp
                stack_port_name = port.stack['port']
                port.stack['port'] = dp.ports[stack_port_name]

        def resolve_mirror_destinations():
            """Resolve mirror port references and destinations."""
            mirror_from_port = {}
            for port in list(self.ports.values()):
                if port.mirror is not None:
                    if port.mirror in port_by_name:
                        mirror_from_port[port] = port_by_name[port.mirror]
                    else:
                        mirror_from_port[self.ports[port.mirror]] = port
            for port, mirror_destination_port in list(mirror_from_port.items()):
                port.mirror = mirror_destination_port.number
                mirror_destination_port.mirror_destination = True

        def resolve_names_in_acls():
            """Resolve config references in ACLs."""
            # TODO: move this config validation to ACL object.

            def resolve_meter(_acl, action_conf):
                meter_name = action_conf
                assert meter_name in self.meters, (
                    'meter %s is not configured' % meter_name)
                return action_conf

            def resolve_mirror(acl, action_conf):
                port_name = action_conf
                port_no = resolve_port_no(port_name)
                # If this DP does not have this port, do nothing.
                if port_no is not None:
                    action_conf = port_no
                    acl.mirror_destinations.add(port_no)
                    return action_conf
                return None

            def resolve_output(_acl, action_conf):
                resolved_action_conf = {}
                assert isinstance(action_conf, dict)
                for output_action, output_action_values in list(action_conf.items()):
                    if output_action == 'port':
                        port_name = output_action_values
                        port_no = resolve_port_no(port_name)
                        # If this DP does not have this port, do not output.
                        if port_no is not None:
                            resolved_action_conf[output_action] = port_no
                    elif output_action == 'failover':
                        failover = output_action_values
                        assert isinstance(failover, dict)
                        resolved_action_conf[output_action] = {}
                        for failover_name, failover_values in list(failover.items()):
                            if failover_name == 'ports':
                                resolved_ports = []
                                for port_name in failover_values:
                                    port_no = resolve_port_no(port_name)
                                    if port_no is not None:
                                        resolved_ports.append(port_no)
                                resolved_action_conf[output_action][failover_name] = resolved_ports
                            else:
                                resolved_action_conf[output_action][failover_name] = failover_values
                    elif output_action in ('dl_dst', 'pop_vlans', 'swap_vid', 'vlan_vid', 'vlan_vids'):
                        resolved_action_conf[output_action] = output_action_values
                    else:
                        assert False, 'unknown ACL output action: %s' % output_action
                if resolved_action_conf:
                    return resolved_action_conf
                return None

            def resolve_allow(_acl, action_conf):
                return action_conf

            action_resolvers = {
                'meter': resolve_meter,
                'mirror': resolve_mirror,
                'output': resolve_output,
                'allow': resolve_allow,
            }

            for acl in list(self.acls.values()):
                for rule_conf in acl.rules:
                    for attrib, attrib_value in list(rule_conf.items()):
                        if attrib == 'actions':
                            resolved_actions = {}
                            assert isinstance(attrib_value, dict)
                            for action_name, action_conf in list(attrib_value.items()):
                                assert action_name in action_resolvers, (
                                    'unknown ACL action %s' % action_name)
                                resolved_action_conf = action_resolvers[action_name](
                                    acl, action_conf)
                                assert resolved_action_conf is not None, (
                                    'cannot resolve ACL rule %s' % rule_conf)
                                resolved_actions[action_name] = resolved_action_conf
                            rule_conf[attrib] = resolved_actions

        def resolve_acls():
            """Resolve ACL references in config."""

            def build_acl(acl, vid=None):
                """Check that ACL can be built from config and mark mirror destinations."""
                if acl.rules:
                    try:
                        assert valve_acl.build_acl_ofmsgs(
                            [acl], self.wildcard_table,
                            valve_of.goto_table(self.wildcard_table),
                            2**16, self.meters, acl.exact_match,
                            vlan_vid=vid)
                    except (AddrFormatError, ValueError) as err:
                        raise InvalidConfigError(err)
                    for port_no in acl.mirror_destinations:
                        port = self.ports[port_no]
                        port.mirror_destination = True

            for vlan in list(self.vlans.values()):
                if vlan.acl_in:
                    assert vlan.acl_in in self.acls, (
                        'missing ACL %s on %s' % (self.name, vlan))
                    vlan.acl_in = self.acls[vlan.acl_in]
                    build_acl(vlan.acl_in, vid=1)
            for port in list(self.ports.values()):
                if port.acl_in:
                    assert port.acl_in in self.acls, (
                        'missing ACL %s on %s' % (self.name, port))
                    port.acl_in = self.acls[port.acl_in]
                    build_acl(port.acl_in, vid=1)

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

        port_by_name = {}
        for port in list(self.ports.values()):
            port_by_name[port.name] = port
        dp_by_name = {}
        for dp in dps:
            dp_by_name[dp.name] = dp
        vlan_by_name = {}
        for vlan in list(self.vlans.values()):
            vlan_by_name[vlan.name] = vlan

        resolve_stack_dps()
        resolve_mirror_destinations()
        resolve_vlan_names_in_routers()
        resolve_names_in_acls()
        resolve_acls()

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
                    if old_port.ignore_subconf(new_port, ignore_keys=set(['acl_in'])):
                        if old_port.acl_in != new_port.acl_in:
                            changed_acl_ports.add(port_no)
                            old_acl_id = old_port.acl_in
                            if old_acl_id:
                                old_acl_id = old_acl_id._id
                            new_acl_id = new_port.acl_in
                            if new_acl_id:
                                new_acl_id = new_acl_id._id
                            logger.info('port %s ACL changed (ACL %s to %s)' % (
                                port_no, old_acl_id, new_acl_id))
                    else:
                        changed_ports.add(port_no)
                        logger.info('port %s reconfigured (%s)' % (
                            port_no, diff(old_port.to_conf(), new_port.to_conf(), context=1)))
                elif new_port.acl_in in changed_acls:
                    # If the port has ACL changed.
                    changed_acl_ports.add(port_no)
                    logger.info('port %s ACL changed (ACL %s content changed)' % (
                        port_no, new_port.acl_in._id))

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
            changes (tuple) of:
                deleted_ports (set): deleted port numbers.
                changed_ports (set): changed/added port numbers.
                changed_acl_ports (set): changed ACL only port numbers.
                deleted_vlans (set): deleted VLAN IDs.
                changed_vlans (set): changed/added VLAN IDs.
                all_ports_changed (bool): True if all ports changed.
        """
        if self.ignore_subconf(new_dp):
            logger.info('DP base level config changed - requires cold start')
            return (set(), set(), set(), set(), set(), True)
        changed_acls = self._get_acl_config_changes(logger, new_dp)
        deleted_vlans, changed_vlans = self._get_vlan_config_changes(logger, new_dp)
        (all_ports_changed, deleted_ports,
         changed_ports, changed_acl_ports) = self._get_port_config_changes(
             logger, new_dp, changed_vlans, changed_acls)
        return (deleted_ports, changed_ports, changed_acl_ports,
                deleted_vlans, changed_vlans, all_ports_changed)
