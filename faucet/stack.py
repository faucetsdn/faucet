
"""Configuration for a stack."""

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

from collections import defaultdict, Counter
import networkx

from faucet.conf import Conf, test_config_condition

class Stack(Conf):
    """Stores state related to DP stack information"""

    defaults = {
        'priority': None,
        # Sets the root priority value of the current DP with stacking
    }

    defaults_types = {
        'priority': int,
    }

    def __init__(self, _id, dp_id, name, canonical_port_order, conf):
        """
        Constructs a new stack object

        Args:
            _id (str): Name of the configuration key
            dp_id (int): DP ID of the DP that holds this stack instance
            name (str): Name of the DP that holds this stack instance
            canonical_port_order (func): Function to order ports in a standardized way
            conf (dict): Stack configuration
        """
        self.name = name

        # Function to order ports in a standardized way
        self.canonical_port_order = canonical_port_order

        # Priority value for the stack root of the dp_id
        self.priority = None

        # Ports that have stacking configured
        self.ports = []

        # Stack graph containing all the DPs & ports in the stacking topology
        self.graph = None

        # Additional stacking information
        self.root_name = None
        self.roots_names = None
        self.route_learning = None
        self.root_flood_reflection = None

        super(Stack, self).__init__(_id, dp_id, conf)

    @staticmethod
    def modify_topology(graph, dp, port, add=True):  # pylint: disable=invalid-name
        """Add/remove an edge to the stack graph which originates from this dp and port."""

        def canonical_edge(dp, port):  # pylint: disable=invalid-name
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
    def add_link(cls, graph, dp, port):  # pylint: disable=invalid-name
        """Add a stack link to the stack graph."""
        return cls.modify_topology(graph, dp, port)

    @classmethod
    def remove_link(cls, graph, dp, port):  # pylint: disable=invalid-name
        """Remove a stack link to the stack graph."""
        return cls.modify_topology(graph, dp, port, False)

    def hash(self):
        """Return hash of a topology graph"""
        # Using the degree of the topology is a quick way to get an estimate on
        #   whether a graph is isomorphic which is what we would really want when comparing
        #   two graphs.
        return hash(tuple(sorted(self.graph.degree())))

    def add_port(self, port):
        """Add a port to this stack"""
        self.ports.append(port)

    def resolve_topology(self, dps, meta_dp_state):
        """Resolve inter-DP config for stacking."""
        stack_dps = [dp for dp in dps if dp.stack is not None]
        stack_priority_dps = [dp for dp in stack_dps if dp.stack.priority]
        stack_port_dps = [dp for dp in dps if dp.stack_ports()]

        if not stack_priority_dps:
            test_config_condition(stack_dps, 'stacking enabled but no root DP')
            return

        if not self.ports:
            return

        for dp in stack_priority_dps:  # pylint: disable=invalid-name
            test_config_condition(not isinstance(dp.stack.priority, int), (
                'stack priority must be type %s not %s' % (
                    int, type(dp.stack.priority))))
            test_config_condition(dp.stack.priority <= 0, (
                'stack priority must be > 0'))
        stack_priority_dps = sorted(stack_priority_dps, key=lambda x: x.stack.priority)

        self.roots_names = tuple([dp.name for dp in stack_priority_dps])
        self.root_name = self.roots_names[0]
        if meta_dp_state:
            if meta_dp_state.stack_root_name in self.roots_names:
                self.root_name = meta_dp_state.stack_root_name

        self.route_learning = False
        for dp in stack_port_dps:  # pylint: disable=invalid-name
            for vlan in dp.vlans.values():
                if vlan.faucet_vips:
                    self.route_learning = True

        edge_count = Counter()
        graph = networkx.MultiGraph()
        for dp in stack_port_dps:  # pylint: disable=invalid-name
            graph.add_node(dp.name)
            for port in dp.stack_ports():
                edge_name = self.add_link(graph, dp, port)
                edge_count[edge_name] += 1
        for edge_name, count in edge_count.items():
            test_config_condition(count != 2, '%s defined only in one direction' % edge_name)
        if graph.size() and self.name in graph:
            self.graph = graph
            for dp in graph.nodes():  # pylint: disable=invalid-name
                path_to_root_len = len(self.shortest_path(self.root_name, src_dp=dp))
                test_config_condition(
                    path_to_root_len == 0, '%s not connected to stack' % dp)
            if self.longest_path_to_root_len() > 2:
                self.root_flood_reflection = True

    def get_node_link_data(self):
        """Return network stacking graph as a node link representation"""
        return networkx.json_graph.node_link_data(self.graph)

    def longest_path_to_root_len(self):
        """Return length of the longest path to root in the stack."""
        if not self.graph or not self.root_name:
            return None
        len_paths_to_root = [
            len(self.shortest_path(self.root_name, src_dp=dp))
            for dp in self.graph.nodes()]
        if len_paths_to_root:
            return max(len_paths_to_root)
        return None

    def shortest_path(self, dest_dp, src_dp=None):
        """Return shortest path to a DP, as a list of DPs."""
        if src_dp is None:
            src_dp = self.name
        if self.graph:
            try:
                return sorted(networkx.all_shortest_paths(self.graph, src_dp, dest_dp))[0]
            except (networkx.exception.NetworkXNoPath, networkx.exception.NodeNotFound):
                pass
        return []

    def shortest_path_to_root(self, src_dp=None):
        """Return shortest path to root DP, as list of DPs."""
        return self.shortest_path(self.root_name, src_dp=src_dp)

    def is_root(self):
        """Return True if this DP is the root of the stack."""
        return self.root_name == self.name

    def is_root_candidate(self):
        """Return True if this DP could be a root of the stack."""
        return self.name in self.roots_names

    def is_edge(self):
        """Return True if this DP is a stack edge."""
        return (not self.is_root() and
                self.longest_path_to_root_len() == len(self.shortest_path_to_root()))

    def peer_up_ports(self, peer_dp):
        """Return list of stack ports that are up towards a peer."""
        return self.canonical_port_order([
            port for port in self.ports if port.running() and (
                port.stack['dp'].name == peer_dp)])

    def shortest_path_port(self, dest_dp):
        """Return first port on our DP, that is the shortest path towards dest DP."""
        shortest_path = self.shortest_path(dest_dp)
        if len(shortest_path) > 1:
            peer_dp = shortest_path[1]
            peer_dp_ports = self.peer_up_ports(peer_dp)
            if peer_dp_ports:
                return peer_dp_ports[0]
        return None

    def is_in_path(self, src_dp, dst_dp):
        """Return True if the current DP is in the path from src_dp to dst_dp
        Args:
            src_dp (str): DP name
            dst_dp (str): DP name
        Returns:
            bool: True if self is in the path from the src_dp to the dst_dp.
        """
        path = self.shortest_path(dst_dp, src_dp=src_dp)
        return self.name in path

    def peer_symmetric_up_ports(self, peer_dp):
        """Return list of stack ports that are up towards us from a peer"""
        # Sort adjacent ports by canonical port order
        return self.canonical_port_order([
            port.stack['port'] for port in self.ports if port.running() and (
                port.stack['dp'].name == peer_dp)])

    def shortest_symmetric_path_port(self, adj_dp):
        """Return port on our DP that is the first port of the adjacent DP towards us"""
        shortest_path = self.shortest_path(self.name, src_dp=adj_dp)
        if len(shortest_path) == 2:
            adjacent_up_ports = self.peer_symmetric_up_ports(adj_dp)
            if adjacent_up_ports:
                return adjacent_up_ports[0].stack['port']
        return None

    def any_port_up(self):
        """Return true if any stack port is UP"""
        for port in self.ports:
            if port.is_stack_up():
                return True
        return False
