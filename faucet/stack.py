
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

from collections import Counter
import networkx

from faucet.conf import Conf, test_config_condition


class Stack(Conf):
    """Stores state related to DP stack information, this includes the current elected root as that
is technically a fixed allocation for this DP Stack instance."""

    defaults = {
        'priority': None,
        # Sets the root priority value of the current DP with stacking
        'route_learning': False,
        # Use the stack route algorithms, will be forced true if routing is enabled
        'down_time_multiple': 3,
        # Number of update time intervals for a down stack node to still be considered healthy
        'min_stack_health': 1.0,
        # Minimum percentage value of required UP stack ports for this stack node to be considered healthy
        'min_lacp_health': 1.0,
        # Minimum percentage value of required UP LACP ports for this stack node to be considered healthy
    }

    defaults_types = {
        'priority': int,
        'route_learning': bool,
        'down_time_multiple': int,
        'min_stack_health': float,
        'min_lacp_health': float,
    }

    def __init__(self, _id, dp_id, name, canonical_port_order, lacp_down_ports, lacp_ports, conf):
        """
        Constructs a new stack object

        Args:
            _id (str): Name of the configuration key
            dp_id (int): DP ID of the DP that holds this stack instance
            name (str): Name of the DP that holds this stack instance
            canonical_port_order (func): Function to order ports in a standardized way
            lacp_down_ports (func): Returns a tuple of the not UP LACP ports for this stack node
            lacp_ports (func): Returns a tuple of all LACP ports for this stack node
            conf (dict): Stack configuration
        """
        self.name = name

        # Function to order ports in a standardized way
        self.canonical_port_order = canonical_port_order
        self.lacp_down_ports = lacp_down_ports
        self.lacp_ports = lacp_ports

        # Stack configuration options
        self.priority = None
        self.route_learning = None
        self.down_time_multiple = None
        self.min_stack_health = None
        self.min_lacp_health = None

        # Ports that have stacking configured
        self.ports = []

        # Stack graph containing all the DPs & ports in the stacking topology
        self.graph = None

        # Additional stacking information
        self.root_name = None
        self.roots_names = None
        self.root_flood_reflection = None

        # Whether the stack node is currently healthy
        # dyn_healthy_info := (<running>, <stack ports>, <lacp ports>)
        self.dyn_healthy_info = (False, 0.0, 0.0)
        self.dyn_healthy = False

        super(Stack, self).__init__(_id, dp_id, conf)

    def clone_dyn_state(self, prev_stack, dps=None):
        """Copy dyn state from the old stack instance when warm/cold starting"""
        if prev_stack:
            self.dyn_healthy = prev_stack.dyn_healthy
            self.dyn_healthy_info = prev_stack.dyn_healthy_info
            if dps:
                stack_port_dps = [dp for dp in dps if dp.stack_ports()]
                for dp in stack_port_dps:
                    for port in dp.stack_ports():
                        port_up = False
                        if port.is_stack_up():
                            port_up = True
                        elif port.is_stack_init() and port.stack['port'].is_stack_up():
                            port_up = True
                        self.modify_link(dp, port, add=port_up)

    def live_timeout_healthy(self, last_live_time, now, update_time):
        """
        Determines the timeout of the current stack node, and whether
        the current stack node can be considered healthy according to
        the `down_time_multiple` number of stack root update time intervals.

        Args:
            last_live_time (float): Last known live time for this current stack node
            now (float): Current time
            update_time (int): Update time interval
        Return:
            bool: If node down time is still in update time interval threshold; considered healthy,
            float: Time elapsed since timed out
        """
        # Time elapsed for the number of safe down time multiples before considered unhealthy
        down_time = self.down_time_multiple * update_time
        # Final time at which nodes are still considered healthy
        health_timeout = now - down_time
        # If node last known live time was greater than the health timeout then it is healthy
        timeout_healthy = last_live_time >= health_timeout
        return timeout_healthy, health_timeout

    def stack_port_healthy(self):
        """
        Determines the percentage of UP stack ports, and whether
        the current stack node can be considered healthy according to
        the `min_stack_health` configuration option.

        Return:
            bool: Whether threshold from DOWN stack ports is met; considered healthy,
            float: Percentage of stack ports UP out of all stack ports
        """
        down_ports = self.down_ports()
        all_ports = self.ports
        if len(all_ports) == 0:
            return True, 1.0
        percentage = 1.0 - (float(len(down_ports) / float(len(all_ports))))
        stack_ports_healthy = percentage >= self.min_stack_health
        return stack_ports_healthy, percentage

    def lacp_port_healthy(self):
        """
        Determines the percentage of UP LACP ports, and whether
        the current stack node can be considered healthy according to
        the `min_lacp_health` configuration option.

        Return:
            bool: Whether threshold from DOWN LACP ports is met; considered healthy,
            float: Percentage of LACP ports UP out of all lacp ports
        """
        down_ports = self.lacp_down_ports()
        all_ports = self.lacp_ports()
        if len(all_ports) == 0:
            return True, 1.0
        percentage = 1.0 - (float(len(down_ports) / float(len(all_ports))))
        lacp_ports_healthy = percentage >= self.min_lacp_health
        return lacp_ports_healthy, percentage

    def update_health(self, now, dp_last_live_time, update_time):
        """
        Determines whether the current stack node is healthy

        Args:
            now (float): Current time
            last_live_times (dict): Last live time value for each DP
            update_time (int): Stack root update interval time
        Return:
            tuple: Current stack node health state,
            str: Reason for the current state
        """
        reason = ''
        last_live_time = dp_last_live_time.get(self.name, 0)
        timeout_healthy, health_timeout = self.live_timeout_healthy(
            last_live_time, now, update_time)
        if not timeout_healthy:
            # Too long since DP last running, if DP not running then
            #   number of UP stack or LACP ports should be 0
            reason += 'last running %us ago (timeout %us)' % (now - last_live_time, health_timeout)
            self.dyn_healthy_info = (False, 0.0, 0.0)
            self.dyn_healthy = False
            return self.dyn_healthy, reason
        else:
            reason += 'running %us ago' % (now - last_live_time)
        if reason:
            reason += ', '
        stack_ports_healthy, stack_percentage = self.stack_port_healthy()
        if not stack_ports_healthy:
            # The number of DOWN stack ports surpasses the threshold for DOWN stack port tolerance
            reason += 'stack ports %s (%.0f%%) not up' % (
                list(self.down_ports()), (1.0 - stack_percentage) * 100.0)
        else:
            reason += '%.0f%% stack ports running' % (stack_percentage * 100.0)
        if self.lacp_ports():
            if reason:
                reason += ', '
            lacp_ports_healthy, lacp_percentage = self.lacp_port_healthy()
            if not lacp_ports_healthy:
                # The number of DOWN LACP ports surpasses the threshold for DOWN LACP port tolerance
                reason += 'lacp ports %s (%.0f%%) not up' % (
                    list(self.lacp_down_ports()), (1.0 - lacp_percentage) * 100.0)
            else:
                reason += '%.0f%% lacp ports running' % (lacp_percentage * 100.0)
        else:
            # No LACP ports in node, so default to 100% UP & don't report information
            lacp_ports_healthy = True
            lacp_percentage = 0.0
        self.dyn_healthy_info = (timeout_healthy, stack_percentage, lacp_percentage)
        if timeout_healthy and stack_ports_healthy and lacp_ports_healthy:
            self.dyn_healthy = True
        else:
            self.dyn_healthy = False
        return self.dyn_healthy, reason

    def nominate_stack_root(self, stacks):
        """Return stack names in priority order and the chosen root"""
        def health_priority(stack):
            # Invert the health priority info so it is sorted correctly
            #   in relation to priority and the binary health
            invert_info = (1.0 - stack.dyn_healthy_info[1],
                           1.0 - stack.dyn_healthy_info[2])
            return (not stack.dyn_healthy, *invert_info, stack.priority, stack.dp_id)
        stack_priorities = sorted(stacks, key=health_priority)
        priority_names = tuple(stack.name for stack in stack_priorities)
        nominated_name = priority_names[0]
        return priority_names, nominated_name

    def resolve_topology(self, dps, meta_dp_state):
        """
        Resolve & verify correct inter-DP stacking config

        Args:
            dps (list): List of configured DPs
            meta_dp_state (MetaDPState): Provided if reloading when choosing a new root DP
        """
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

        self.roots_names, self.root_name = self.nominate_stack_root(
            [dp.stack for dp in stack_priority_dps])

        if meta_dp_state:
            # If meta_dp_state exists, then we are reloading a new instance of the stack
            #   for a new 'dynamically' chosen root
            if meta_dp_state.stack_root_name in self.roots_names:
                self.root_name = meta_dp_state.stack_root_name

        for dp in stack_port_dps:  # pylint: disable=invalid-name
            for vlan in dp.vlans.values():
                if vlan.faucet_vips:
                    self.route_learning = True

        edge_count = Counter()
        graph = networkx.MultiGraph()
        for dp in stack_port_dps:  # pylint: disable=invalid-name
            graph.add_node(dp.name)
            for port in dp.stack_ports():
                edge_name = Stack.modify_topology(graph, dp, port)
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

    def modify_link(self, dp, port, add=True):
        """Update the stack topology according to the event"""
        return Stack.modify_topology(self.graph, dp, port, add)

    def hash(self):
        """Return hash of a topology graph"""
        return hash(tuple(sorted(self.graph.degree())))

    def get_node_link_data(self):
        """Return network stacking graph as a node link representation"""
        return networkx.readwrite.json_graph.node_link_data(self.graph)

    def add_port(self, port):
        """Add a port to this stack"""
        self.ports.append(port)

    def any_port_up(self):
        """Return true if any stack port is UP"""
        for port in self.ports:
            if port.is_stack_up():
                return True
        return False

    def down_ports(self):
        """Return tuple of not running stack ports"""
        return tuple([port for port in self.ports if not port.is_stack_up()])

    def canonical_up_ports(self, ports=None):
        """Obtains list of UP stack ports in canonical order"""
        if ports is None:
            ports = self.ports
        return self.canonical_port_order([port for port in ports if port.is_stack_up()])

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
        return self.name == self.root_name

    def is_root_candidate(self):
        """Return True if this DP could be a root of the stack."""
        return self.name in self.roots_names

    def is_edge(self):
        """Return True if this DP is a stack edge."""
        return (not self.is_root() and
                self.longest_path_to_root_len() == len(self.shortest_path_to_root()))

    def shortest_path_port(self, dest_dp):
        """Return first port on our DP, that is the shortest path towards dest DP."""
        shortest_path = self.shortest_path(dest_dp)
        if len(shortest_path) > 1:
            peer_dp = shortest_path[1]
            peer_dp_ports = self.peer_up_ports(peer_dp)
            if peer_dp_ports:
                return peer_dp_ports[0]
        return None

    def peer_up_ports(self, peer_dp):
        """Return list of stack ports that are up towards a peer."""
        return self.canonical_port_order([
            port for port in self.ports if port.running() and (
                port.stack['dp'].name == peer_dp)])

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

    def shortest_symmetric_path_port(self, peer_dp):
        """Return port on our DP that is the first port of the adjacent DP towards us"""
        shortest_path = self.shortest_path(self.name, src_dp=peer_dp)
        if len(shortest_path) == 2:
            adjacent_up_ports = self.peer_symmetric_up_ports(peer_dp)
            if adjacent_up_ports:
                return adjacent_up_ports[0].stack['port']
        return None
