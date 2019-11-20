#!/usr/bin/env python3

import os
import networkx


class TopologyWatcher():
    """
    Watches the topology (both predicted and actual) for differences via
        the host connectivity. This ensures that Faucet can facilitate the
        connection of hosts (that can form a path) after faults occur.
    Can take faults that have occured as a part of the fault-tolerance testing.
    The predicted & actual graph use switch dpids & host names as the nodes.
    """

    # List of fault names in order of occurence
    fault_list = None
    # The predicted total network graph (DPs & hosts)
    predicted_network_graph = None
    # The host connectivity graph
    host_connectivity_graph = None
    # Links that can be taken down
    eligable_links = None
    # Switches that can be taken down
    eligable_switches = None
    # Dict of src host key and dst hosts value
    connected_hosts = None

    def __init__(self, dpids, dp_links, host_links, n_vlans, host_information, routers):
        """
        Args:
            dpids (list): Switch dpids to match the DPID indices used in dp_links & other structures
            dp_links (dict):
            host_links (dict):
            n_vlans: Number of VLANs
            host_information (dict):
        """
        self.dpids = dpids
        self.dp_links = dp_links
        self.host_links = host_links
        self.n_vlans = n_vlans
        self.host_information = host_information
        self.routers = routers
        self.fault_list = []
        self.add_fault('Initial')
        self.generate_predicted_graph(dpids, dp_links, host_links, host_information)

    def generate_predicted_graph(self, dpids, dp_links, host_links, host_information):
        """Creates the predicted network graph"""
        self.predicted_network_graph = networkx.MultiGraph()
        for dpid in dpids:
            self.predicted_network_graph.add_node(dpid)
        for src, dsts in dp_links.items():
            for dst in dsts:
                self.predicted_network_graph.add_edge(self.dpids[src], self.dpids[dst])
        self.host_name_to_index = {}
        for host_id, host_info in host_information.items():
            host_name = host_info['host'].name
            self.host_name_to_index[host_name] = host_id
            self.predicted_network_graph.add_node(host_name)
            links = host_links[host_id]
            for link in links:
                self.predicted_network_graph.add_edge(host_name, self.dpids[link])

    def is_shared_router(self, src, dst):
        """Returns true if the host indices should be connected (via inter/intra VLAN)"""
        src_vlan = self.host_information[src]['vlan']
        dst_vlan = self.host_information[dst]['vlan']
        if src_vlan == dst_vlan:
            return True
        for vlans in self.routers.values():
            if (src_vlan in vlans and dst_vlan in vlans):
                return True
        return False

    def add_fault(self, name):
        """
        Add a general/controller fault
        Logs the fault name and resets the actual graph
        """
        self.fault_list.append(name)
        self.host_connectivity_graph = networkx.MultiDiGraph()
        self.eligable_links = []
        self.eligable_switches = []
        self.connected_hosts = {}

    def add_link_fault(self, srci, dsti, name):
        """
        Adds a link fault, i.e: removes a switch-switch edge from the predicted graph
        Args:
            srci: Source dpid index of the switch link
            dsti: Destination dpid index of the switch link
            name: Fault event name
        """
        self.predicted_network_graph.remove_edge(self.dpids[srci], self.dpids[dsti])
        self.add_fault(name)

    def add_switch_fault(self, i, name):
        """
        Add a switch fault, i.e: removes a switch node from the predicted graph
        Args:
            i: dpid index of the switch
            name: Fault event name
        """
        self.predicted_network_graph.remove_node(self.dpids[i])
        self.add_fault(name)

    def get_eligable_link_events(self):
        """Return list of available stack links to take down"""
        if self.eligable_links:
            return self.eligable_links
        edges = []
        for edge in self.predicted_network_graph.edges():
            if edge[0] in self.dpids and edge[1] in self.dpids:
                edges.append(edge)
        self.eligable_links = edges
        return edges

    def get_eligable_switch_events(self):
        """Return list of available switches to take down"""
        if self.eligable_switches:
            return self.eligable_switches
        switches = []
        for node in self.predicted_network_graph.nodes():
            if node in self.dpids:
                switches.append(node)
        self.eligable_switches = switches
        return switches

    def get_connected_hosts(self):
        """
        Hosts are connected if the shortest path they can form in the
            predicted graph that is longer than 3 (itself, shared DP, dst host)
        Returns dictionary of host index to list of connected host index
        """
        if self.connected_hosts:
            return self.connected_hosts
        connected_hosts = {i: [] for i in self.host_name_to_index.values()}
        for src_host in self.host_name_to_index:
            src_index = self.host_name_to_index[src_host]
            for dst_host in self.host_name_to_index:
                dst_index = self.host_name_to_index[dst_host]
                if src_index != dst_index and self.is_shared_router(src_index, dst_index):
                    try:
                        path_length = networkx.shortest_path_length(
                            self.predicted_network_graph, src_host, dst_host)
                        if path_length >= 3:
                            connected_hosts[src_index].append(dst_index)
                    except networkx.exception.NetworkXNoPath:
                        continue
        self.connected_hosts = connected_hosts
        return connected_hosts

    def add_network_info(self, src_host, dst_host, is_connected):
        """
        Add connection information to the current graph
        Args:
            src_host: name of the src host obj
            dst_host: name of the dst host obj
            is_connected: Whether hosti is connected to hostj
        """
        curr_graph = self.host_connectivity_graph
        if src_host not in curr_graph.nodes():
            curr_graph.add_node(src_host)
        if dst_host not in curr_graph.nodes():
            curr_graph.add_node(dst_host)
        if is_connected:
            curr_graph.add_edge(src_host, dst_host)

    def is_connected(self):
        """Return true if the actual graph has the same host connectivity as the predicted graph"""
        for src, dsts in self.connected_hosts.items():
            src_host = self.host_information[src]['host'].name
            for dst in dsts:
                dst_host = self.host_information[dst]['host'].name
                curr_graph = self.host_connectivity_graph
                if (src_host in curr_graph.nodes() and dst_host in curr_graph.nodes() and (
                        dst_host not in curr_graph.neighbors(src_host))):
                    return False
        return True

    def continue_faults(self):
        """Returns true whether there are more faults to occur"""
        connected_hosts = self.get_connected_hosts()
        for dsts in connected_hosts.values():
            if dsts:
                return True
        return False

    def is_initial(self):
        """Return true for the initial run"""
        return len(self.fault_list) == 1

    def dump_info(self, tmpdir):
        """Dump info to test directory"""
        pred_graph_fn = os.path.join(tmpdir, 'final_predicted_network_graph.txt')
        networkx.write_edgelist(self.predicted_network_graph, pred_graph_fn)
        act_graph_fn = os.path.join(tmpdir, 'final_actual_network_graph.txt')
        networkx.write_edgelist(self.host_connectivity_graph, act_graph_fn)
        fault_list_fn = os.path.join(tmpdir, 'fault_list.txt')
        file = open(fault_list_fn, 'w')
        for fault_name in self.fault_list:
            file.write(fault_name + '\n')
