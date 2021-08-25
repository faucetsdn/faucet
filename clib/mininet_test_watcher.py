#!/usr/bin/env python3

"""Manage a model of the Mininet topology for fault tolerance testing"""

import os
import networkx

from mininet.log import error


class OptimizedTopologyWatcher:
    """
    Watches multiple states of the network (both simulated and real) to calculate the
        next steps in the test to run.
    """

    # Mininet topo instance
    topo = None
    # Additional host information
    host_information = None
    # Routers configured in the test
    routers = None
    # Graph of only switch->switch links
    switch_graph = None
    # Graph of only host->switch links
    host_graph = None

    # Links that can be taken down
    eligable_links = None
    # Switches that can be taken down
    eligable_switches = None

    # List of fault names in order of occurence
    fault_list = None

    def __init__(self, topo, host_information, routers):
        """
        Args:
            topo (FaucetTopoGenerator): FaucetTopoGenerator
            host_information (dict): Additonal host information
            routers (dict): Configured routers
        """
        self.topo = topo
        self.host_information = host_information
        self.routers = routers
        self.fault_list = []

        # Create graph of only switch->switch links
        switch_graph = self.topo.g.convertTo(networkx.MultiGraph)
        for host in self.topo.hosts_by_id.values():
            switch_graph.remove_node(host)
        self.switch_graph = switch_graph

        # Create graph of only host->switch links
        host_graph = self.topo.g.convertTo(networkx.MultiGraph)
        remove_edges = []
        for edge in host_graph.edges():
            if set(edge).issubset(self.topo.switches_by_id.values()):
                remove_edges.append(edge)
        for edge in remove_edges:
            host_graph.remove_edge(*edge)
        self.host_graph = host_graph

    def add_fault(self, name):
        """
        Add a general/controller fault
        """
        error('FAULT: %s\n' % name)
        self.fault_list.append(name)

    def add_link_fault(self, src_i, dst_i, name):
        """
        Adds a link fault, i.e: removes a switch-switch edge from the predicted graph

        Args:
            src_i (int): Source index of the switch link
            dst_i (int): Destination index of the switch link
            name (str): Fault event name
        """
        try:
            self.switch_graph.remove_edge(
                self.topo.switches_by_id[src_i], self.topo.switches_by_id[dst_i])
            self.add_fault(name)
        except networkx.exception.NetworkXError:
            pass

    def add_switch_fault(self, i, name):
        """
        Add a switch fault, i.e: removes a switch node from the predicted graph

        Args:
            i (int): Index of the switch
            name (str): Fault event name
        """
        try:
            self.switch_graph.remove_node(self.topo.switches_by_id[i])
            self.add_fault(name)
        except networkx.exception.NetworkXError:
            pass

    def _get_longest_switch_path(self):
        """Return the longest simple path from comparing all possible longest simple paths"""
        # Find the longest path from all paths
        longest_path_len = 0
        longest_path = []
        for src in self.switch_graph:
            for dst in self.switch_graph:
                if src is dst:
                    continue
                for path in networkx.all_simple_paths(self.switch_graph, src, dst):
                    if len(path) > longest_path_len:
                        longest_path = path
                        longest_path_len = len(path)
                        if len(path) == len(self.switch_graph):
                            # We can stop searching as we have found the longest path
                            return longest_path
        return longest_path

    def _get_switch_connectivity_graph(self, symmetric=False, transitive=False):
        """Return connection graph of switch nodes"""
        connection_graph = networkx.MultiDiGraph()
        if not transitive:
            # Transitive assumption not present so complete all ping combinations
            for src in self.switch_graph:
                for dst in self.switch_graph:
                    connection_graph.add_edge(src, dst)
                    if not symmetric:
                        connection_graph.add_edge(dst, src)
        else:
            # Find the longest path from all paths
            longest_path = self._get_longest_switch_path()
            # Turn path into connection graph
            for i in range(0, len(longest_path) - 1):
                connection_graph.add_edge(longest_path[i], longest_path[i + 1])
                if not symmetric:
                    connection_graph.add_edge(longest_path[i + 1], longest_path[i])
            # Find and add remaining nodes
            for node in self.switch_graph:
                if node not in connection_graph:
                    # Add remaining nodes to connection graph
                    path = networkx.shortest_paths.shortest_path(
                        self.switch_graph, node, list(connection_graph.nodes())[0])
                    for i in range(0, len(path) - 1):
                        # Add path until we have reached a point that is completely inside
                        # the original simple graph
                        if path[i] in connection_graph and path[i + 1] in connection_graph:
                            break
                    connection_graph.add_edge(path[i], path[i + 1])
                    if not symmetric:
                        connection_graph.add_edge(path[i + 1], path[i])
        return connection_graph

    def get_connected_hosts(self, symmetric=False, transitive=False, intervlan_only=False):
        """
        Construct an expected connected host graph

        Args:
            symmetric (bool): Assume symmetric pings
            transitive (bool): Assume transitive pings
            intervlan_only (bool): Test hosts only inter-VLAN

        Returns:
            networkx.MultiDiGraph: expected host connection graph
        """
        # Generate switch connectivity graph
        switch_connection_graph = self._get_switch_connectivity_graph(
            symmetric=symmetric, transitive=transitive)
        # Convert switch connections to host connections
        host_connection_graph = networkx.MultiDiGraph()
        for src, dst in switch_connection_graph.edges():
            src_hosts = self.host_graph.neighbors(src)
            dst_hosts = self.host_graph.neighbors(dst)
            for src_host in src_hosts:
                for dst_host in dst_hosts:
                    if src_host is dst_host:
                        continue
                    if intervlan_only:
                        if self._routed_vlans(src_host, dst_host):
                            host_connection_graph.add_edge(src_host, dst_host)
                    else:
                        host_connection_graph.add_edge(src_host, dst_host)
        return host_connection_graph

    def _routed_vlans(self, src_host, dst_host):
        """Return true only if src_host, dst_host vlans share a router"""
        src_vlan = self.host_information[self.topo.nodeInfo(src_host)['host_n']]['vlan']
        dst_vlan = self.host_information[self.topo.nodeInfo(dst_host)['host_n']]['vlan']
        for vlans in self.routers.values():
            if src_vlan in vlans and dst_vlan in vlans:
                return True
        return False

    def get_eligable_link_events(self):
        """Return list of available stack links to take down"""
        # Remove bridges (prevents disjoint graphs)
        eligable_links = list(self.switch_graph.edges())
        graph = networkx.Graph(self.switch_graph)
        bridges = list(networkx.algorithms.bridges(graph))
        for bridge in bridges:
            if self.switch_graph.number_of_edges(*bridge) > 1:
                # Actually multiple links so not a bridge
                continue
            if bridge in eligable_links:
                eligable_links.remove(bridge)
        return eligable_links

    def get_eligable_switch_events(self):
        """Returns list of available switch names to take down"""
        # Remove bridges (prevents disjoint graphs)
        eligable_switches = list(self.switch_graph.nodes())
        graph = networkx.Graph(self.switch_graph)
        bridges = list(networkx.algorithms.bridges(graph))
        for bridge in bridges:
            if self.switch_graph.number_of_edges(*bridge) > 1:
                # Actually multiple links so not a bridge
                continue
            for node in bridge:
                if node in eligable_switches:
                    eligable_switches.remove(node)
        return eligable_switches

    def continue_faults(self):
        """Returns true whether there are more faults to occur"""
        return self.get_eligable_link_events() or self.get_eligable_switch_events()

    def dump_info(self, tmpdir):
        """Dump topology watcher info into test directory"""
        sw_graph_fn = os.path.join(tmpdir, 'final_switch_graph.txt')
        networkx.write_edgelist(self.switch_graph, sw_graph_fn)
        fault_list_fn = os.path.join(tmpdir, 'fault-list.txt')
        with open(fault_list_fn, 'w', encoding='utf-8') as fl_file:
            for fault_name in self.fault_list:
                fl_file.write(fault_name + '\n')
