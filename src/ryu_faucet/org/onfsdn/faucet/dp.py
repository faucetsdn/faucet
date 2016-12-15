# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
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

from conf import Conf
from vlan import VLAN
from port import Port
from valve_acl import ACL

import networkx


class DP(Conf):
    """Object to hold the configuration for a faucet controlled datapath."""

    acls = None
    vlans = None
    ports = None
    running = False
    influxdb_stats = False
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
    eth_dst_table = None
    flood_table = None
    priority_offset = None
    low_priority = None
    high_priority = None
    stack = None
    ignore_learn_ins = None

    # Values that are set to None will be set using set_defaults
    # they are included here for testing and informational purposes
    defaults = {
        'dp_id': None,
        # Name for this dp, used for stats reporting and configuration
        'name': None,
        'table_offset': 0,
        'port_acl_table': None,
        # The table for internally associating vlans
        'vlan_table': None,
        'vlan_acl_table': None,
        'eth_src_table': None,
        'ipv4_fib_table': None,
        'ipv6_fib_table': None,
        'eth_dst_table': None,
        'flood_table': None,
        # How much to offset default priority by
        'priority_offset': 0,
        # Some priority values
        'lowest_priority': None,
        'low_priority': None,
        'high_priority': None,
        'highest_priority': None,
        # Identification cookie value to allow for multiple controllers to
        # control the same datapath
        'cookie': 1524372928,
        # inactive MAC timeout
        'timeout': 300,
        # description, strictly informational
        'description': None,
        # The hardware maker (for chosing an openflow driver)
        'hardware': 'Open vSwitch',
        # ARP and neighbor timeout (seconds)
        'arp_neighbor_timeout': 500,
        # OF channel log
        'ofchannel_log': None,
        # stacking config, when cross connecting multiple DPs
        'stack': None,
        # Ignore every approx nth packet for learning.
        # 2 will ignore 1 out of 2 packets; 3 will ignore 1 out of 3 packets.
        # This limits control plane activity when learning new hosts rapidly.
        # Flooding will still be done by the dataplane even with a packet
        # is ignored for learning purposes.
        'ignore_learn_ins': 3,
        }

    def __init__(self, _id, conf):
        self._id = _id
        self.update(conf)
        self.set_defaults()
        self.acls = {}
        self.vlans = {}
        self.ports = {}
        self.port_acl_in = {}
        self.vlan_acl_in = {}

    def sanity_check(self):
        # TODO: this shouldnt use asserts
        assert 'dp_id' in self.__dict__
        assert isinstance(self.dp_id, (int, long))
        for vid, vlan in self.vlans.iteritems():
            assert isinstance(vid, int)
            assert isinstance(vlan, VLAN)
            assert all(isinstance(p, Port) for p in vlan.get_ports())
        for portnum, port in self.ports.iteritems():
            assert isinstance(portnum, int)
            assert isinstance(port, Port)

    def set_defaults(self):
        for key, value in self.defaults.iteritems():
            self._set_default(key, value)
        # fix special cases
        self._set_default('dp_id', self._id)
        self._set_default('name', str(self._id))
        self._set_default('port_acl_table', self.table_offset)
        self._set_default('vlan_table', self.port_acl_table + 1)
        self._set_default('vlan_acl_table', self.vlan_table + 1)
        self._set_default('eth_src_table', self.vlan_acl_table + 1)
        self._set_default('ipv4_fib_table', self.eth_src_table + 1)
        self._set_default('ipv6_fib_table', self.ipv4_fib_table + 1)
        self._set_default('eth_dst_table', self.ipv6_fib_table + 1)
        self._set_default('flood_table', self.eth_dst_table + 1)
        self._set_default('lowest_priority', self.priority_offset)
        self._set_default('low_priority', self.priority_offset + 9000)
        self._set_default('high_priority', self.low_priority + 1)
        self._set_default('highest_priority', self.high_priority + 98)
        self._set_default('description', self.name)

    def add_acl(self, acl_ident, acl_conf=None):
        if acl_conf is not None:
            self.acls[acl_ident] = ACL(acl_ident, acl_conf)

    def add_port(self, port):
        port_num = port.number
        self.ports[port_num] = port
        if port.mirror is not None:
            # other configuration entries ignored
            return
        if port.acl_in is not None:
            self.port_acl_in[port_num] = port.acl_in

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
            for port in dp.ports.itervalues():
                if port.stack is not None:
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
        if len(graph.edges()):
            for edge_name, count in edge_count.iteritems():
                assert count == 2, '%s defined only in one direction' % edge_name
            if self.stack is None:
                self.stack = {}
            self.stack['root_dp'] = root_dp
            self.stack['graph'] = graph

    def shortest_path(self, dest_dp):
        if self.stack is None:
            return None
        else:
            return networkx.shortest_path(
                self.stack['graph'], self.name, dest_dp)

    def shortest_path_port(self, dest_dp):
        """Return port on our DP, that is the shortest path towards dest DP."""
        shortest_path = self.shortest_path(dest_dp)
        if shortest_path is not None:
            peer_dp = shortest_path[1]
            peer_dp_ports = []
            for port in self.ports.itervalues():
                if port.stack is not None:
                    if port.stack['dp'].name == peer_dp:
                        peer_dp_ports.append(port)
            return peer_dp_ports[0]
        return None

    def shortest_path_to_root(self):
        if self.stack is not None:
            root_dp = self.stack['root_dp']
            if root_dp != self:
                return self.shortest_path(root_dp.name)
        return []

    def finalize_config(self, dps):

        def resolve_port_no(port_name):
            if port_name in port_by_name:
                return port_by_name[port_name].number
            elif port_name in self.ports:
                return port_name
            return None

        def resolve_stack_dps():
            port_stack_dp = {}
            for port in self.ports.itervalues():
                if port.stack is not None:
                    stack_dp = port.stack['dp']
                    port_stack_dp[port] = dp_by_name[stack_dp]
            for port, dp in port_stack_dp.iteritems():
                port.stack['dp'] = dp
                stack_port_name = port.stack['port']
                port.stack['port'] = dp.ports[stack_port_name]

        def resolve_mirror_destinations():
            # Associate mirrored ports, with their destinations.
            mirror_from_port = {}
            for port in self.ports.itervalues():
                if port.mirror is not None:
                    if port.mirror in port_by_name:
                        mirror_from_port[port] = port_by_name[port.mirror]
                    else:
                        mirror_from_port[self.ports[port.mirror]] = port
            for port, mirror_destination_port in mirror_from_port.iteritems():
                port.mirror = mirror_destination_port.number
                mirror_destination_port.mirror_destination = True

        def resolve_port_names_in_acls():
            for acl in self.acls.itervalues():
                for rule_conf in acl.rules:
                    for attrib, attrib_value in rule_conf.iteritems():
                        if attrib == 'actions':
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
                                port_name = attrib_value['output']['port']
                                port_no = resolve_port_no(port_name)
                                if port_no is not None:
                                    attrib_value['output']['port'] = port_no

        port_by_name = {}
        for port in self.ports.itervalues():
            port_by_name[port.name] = port
        dp_by_name = {}
        for dp in dps:
            dp_by_name[dp.name] = dp

        resolve_stack_dps()
        resolve_mirror_destinations()
        resolve_port_names_in_acls()


    def get_native_vlan(self, port_num):
        if port_num not in self.ports:
            return None

        port = self.ports[port_num]

        for vlan in self.vlans.values():
            if port in vlan.untagged:
                return vlan

        return None


    def __str__(self):
        return self.name
