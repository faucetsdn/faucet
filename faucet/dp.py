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

import networkx

try:
    from conf import Conf
    from vlan import VLAN
    from port import Port
    from acl import ACL
except ImportError:
    from faucet.acl import ACL
    from faucet.conf import Conf
    from faucet.port import Port
    from faucet.vlan import VLAN


# Documentation generated using documentation_generator.py
# For attributues to be included in documentation they must
# have a default value, and their descriptor must come
# immediately after being set. See below for example.
class DP(Conf):
    """Implement FAUCET configuration for a datapath."""

    acls = None
    vlans = None
    ports = None
    routers = None
    running = False
    name = None
    dp_id = None
    configured = False
    table_offset = None
    port_acl_table = None
    vlan_table = None
    vlan_acl_table = None
    eth_src_table = None
    ipv4_fib_table = None
    ipv6_fib_table = None
    vip_table = None
    eth_dst_table = None
    flood_table = None
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
    meters = {}

    # Values that are set to None will be set using set_defaults
    # they are included here for testing and informational purposes
    defaults = {
        'dp_id': None,
        # Name for this dp, used for stats reporting and configuration
        'name': None,
        'interfaces': {},
        'table_offset': 0,
        'port_acl_table': None,
        # The table for internally associating vlans
        'vlan_table': None,
        'vlan_acl_table': None,
        'eth_src_table': None,
        'ipv4_fib_table': None,
        'ipv6_fib_table': None,
        'vip_table': None,
        'eth_dst_table': None,
        'flood_table': None,
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
        'arp_neighbor_timeout': 500,
        # ARP and neighbor timeout (seconds)
        'ofchannel_log': None,
        # OF channel log
        'stack': None,
        # stacking config, when cross connecting multiple DPs
        'ignore_learn_ins': 3,
        # Ignore every approx nth packet for learning.
        #2 will ignore 1 out of 2 packets; 3 will ignore 1 out of 3 packets.
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
        'pipeline_config_dir': '/etc/ryu/faucet',
        # where config files for pipeline are stored (if any).
        'use_idle_timeout': False,
        #Turn on/off the use of idle timeout for src_table, default OFF.
        }

    defaults_types = {
        'dp_id': int,
        'name': str,
        'interfaces': dict,
        'table_offset': int,
        'port_acl_table': int,
        'vlan_table': int,
        'vlan_acl_table': int,
        'eth_src_table': int,
        'ipv4_fib_table': int,
        'ipv6_fib_table': int,
        'vip_table': int,
        'eth_dst_table': int,
        'flood_table': int,
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


    def __init__(self, _id, conf):
        """Constructs a new DP object"""
        super(DP, self).__init__(_id, conf)
        self.acls = {}
        self.vlans = {}
        self.ports = {}
        self.routers = {}
        self.stack_ports = []
        self.port_acl_in = {}
        self.vlan_acl_in = {}

    def sanity_check(self):
        # TODO: this shouldnt use asserts
        assert 'dp_id' in self.__dict__
        assert str(self.dp_id).isdigit()
        for vlan in list(self.vlans.values()):
            assert isinstance(vlan, VLAN)
            assert all(isinstance(p, Port) for p in vlan.get_ports())
        for port in list(self.ports.values()):
            assert isinstance(port, Port)
        for acl in list(self.acls.values()):
            assert isinstance(acl, ACL)

    def set_defaults(self):
        super(DP, self).set_defaults()
        # fix special cases
        self._set_default('dp_id', self._id)
        self._set_default('name', str(self._id))
        self._set_default('lowest_priority', self.priority_offset) # pytype: disable=none-attr
        self._set_default('low_priority', self.priority_offset + 9000) # pytype: disable=none-attr
        self._set_default('high_priority', self.low_priority + 1) # pytype: disable=none-attr
        self._set_default('highest_priority', self.high_priority + 98) # pytype: disable=none-attr
        self._set_default('description', self.name)
        table_id = self.table_offset
        for table_name in (
                'port_acl_table',
                'vlan_table',
                'vlan_acl_table',
                'eth_src_table',
                'ipv4_fib_table',
                'ipv6_fib_table',
                'vip_table',
                'eth_dst_table',
                'flood_table'):
            self._set_default(table_name, table_id)
            table_id += 1 # pytype: disable=none-attr

    def add_acl(self, acl_ident, acl):
        self.acls[acl_ident] = acl

    def add_router(self, router_ident, router):
        self.routers[router_ident] = router

    def add_port(self, port):
        port_num = port.number
        self.ports[port_num] = port
        if port.mirror is not None:
            # other configuration entries ignored
            return
        if port.acl_in is not None:
            self.port_acl_in[port_num] = port.acl_in
        if port.stack is not None:
            self.stack_ports.append(port)

    def add_vlan(self, vlan):
        self.vlans[vlan.vid] = vlan
        if vlan.acl_in is not None:
            self.vlan_acl_in[vlan.vid] = vlan.acl_in

    def resolve_stack_topology(self, dps):

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
        for dp in dps:
            if dp.stack is not None:
                if 'priority' in dp.stack:
                    assert root_dp is None, 'multiple stack roots'
                    root_dp = dp

        if root_dp is None:
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
                    edge_a_dp.name, edge_z_dp.name, edge_name, edge_attr)
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

    def shortest_path_port(self, dest_dp):
        """Return port on our DP, that is the shortest path towards dest DP."""
        shortest_path = self.shortest_path(dest_dp)
        if shortest_path is not None:
            peer_dp = shortest_path[1]
            peer_dp_ports = []
            for port in self.stack_ports:
                if port.stack['dp'].name == peer_dp:
                    peer_dp_ports.append(port)
            return peer_dp_ports[0]
        return None

    def finalize_config(self, dps):

        def resolve_port_no(port_name):
            if port_name in port_by_name:
                return port_by_name[port_name].number
            elif port_name in self.ports:
                return port_name
            return None

        def resolve_vlan(vlan_name):
            if vlan_name in vlan_by_name:
                return vlan_by_name[vlan_name]
            elif vlan_name in self.vlans:
                return self.vlans[vlan_name]
            return None

        def resolve_stack_dps():
            port_stack_dp = {}
            for port in self.stack_ports:
                stack_dp = port.stack['dp']
                port_stack_dp[port] = dp_by_name[stack_dp]
            for port, dp in list(port_stack_dp.items()):
                port.stack['dp'] = dp
                stack_port_name = port.stack['port']
                port.stack['port'] = dp.ports[stack_port_name]

        def resolve_mirror_destinations():
            # Associate mirrored ports, with their destinations.
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

        def resolve_names_in_acl_actions(attrib_value):
            if 'meter' in attrib_value:
                meter_name = attrib_value['meter']
                assert meter_name in self.meters
            if 'mirror' in attrib_value:
                port_name = attrib_value['mirror']
                port_no = resolve_port_no(port_name)
                # in V2 config, we might have an ACL that does
                # not apply to a DP.
                if port_no is not None:
                    attrib_value['mirror'] = port_no
                    port = self.ports[port_no]
                    port.mirror_destination = True
                if 'output' in attrib_value:
                    output_values = attrib_value['output']
                    if 'port' in output_values:
                        port_name = output_values['port']
                        port_no = resolve_port_no(port_name)
                        if port_no is not None:
                            output_values['port'] = port_no

        def resolve_names_in_acls():
            for acl in list(self.acls.values()):
                for rule_conf in acl.rules:
                    for attrib, attrib_value in list(rule_conf.items()):
                        if attrib == 'actions':
                            resolve_names_in_acl_actions(attrib_value)

        def resolve_vlan_names_in_routers():
            for router_name in list(self.routers.keys()):
                router = self.routers[router_name]
                vlans = []
                for vlan_name in router.vlans:
                    vlan = resolve_vlan(vlan_name)
                    if vlan is not None:
                        vlans.append(vlan)
                self.routers[router_name].vlans = vlans

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
        resolve_names_in_acls()
        resolve_vlan_names_in_routers()

    def get_native_vlan(self, port_num):
        if port_num not in self.ports:
            return None

        port = self.ports[port_num]

        for vlan in list(self.vlans.values()):
            if port in vlan.untagged:
                return vlan

        return None

    def get_tables(self):
        result = {}
        for k in self.defaults:
            if k.endswith('table'):
                result[k] = self.__dict__[k]
        return result

    def to_conf(self):
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

    def __str__(self):
        return self.name
