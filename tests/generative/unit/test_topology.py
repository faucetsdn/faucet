#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_large_topology.py."""

# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
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


import random
import unittest
import yaml

from ryu.lib import mac
from ryu.ofproto import ofproto_v1_3 as ofp

import networkx
from networkx.generators.atlas import graph_atlas_g

from clib.valve_test_lib import ValveTestBases

from clib.config_generator import FaucetFakeOFTopoGenerator


class ValveGenerativeBase(ValveTestBases.ValveTestNetwork):
    """Base for generating configuration files"""

    topo = None

    graphs = None

    NUM_PORTS = 5

    NUM_DPS = 2
    NUM_VLANS = 2
    NUM_HOSTS = 1
    SWITCH_TO_SWITCH_LINKS = 1

    PORT_ORDER = [0, 1, 2, 3]
    START_PORT = 5

    serial = 0

    @staticmethod
    def create_bcast_match(in_port, in_vid=None):
        """Return bcast match"""
        bcast_match = {
            'in_port': in_port,
            'eth_dst': mac.BROADCAST_STR,
            'eth_type': 0x0800,
            'ip_proto': 1
        }
        if in_vid:
            in_vid = in_vid | ofp.OFPVID_PRESENT
            bcast_match['vlan_vid'] = in_vid
        return bcast_match

    def get_serialno(self, *_args, **_kwargs):
        """"Return mock serial number"""
        self.serial += 1
        return self.serial

    def create_topo_config(self, network_graph):
        """Return topo object and a simple stack config generated from network_graph"""
        host_links = {}
        host_vlans = {}
        dp_options = {}
        host_n = 0
        for dp_i in network_graph.nodes():
            for _ in range(self.NUM_HOSTS):
                a_vlans = random.randint(0, self.NUM_VLANS - 1)
                b_vlans = random.randint(0, self.NUM_VLANS - 1)
                min_vlans = min(a_vlans, b_vlans)
                max_vlans = max(a_vlans, b_vlans)
                is_tagged = random.choice([True, False])
                if is_tagged:
                    if min_vlans != max_vlans:
                        vlans = list(range(min_vlans, max_vlans))
                    else:
                        vlans = [min_vlans]
                    host_links[host_n] = [dp_i]
                    host_vlans[host_n] = vlans
                    host_n += 1
                else:
                    for v_i in range(min_vlans, max_vlans):
                        host_links[host_n] = [dp_i]
                        host_vlans[host_n] = v_i
                        host_n += 1
            dp_options[dp_i] = {'hardware': 'GenericTFM'}
            if dp_i == 0:
                dp_options[dp_i]['stack'] = {'priority': 1}
        switch_links = list(network_graph.edges()) * self.SWITCH_TO_SWITCH_LINKS
        link_vlans = {link: None for link in switch_links}
        topo = FaucetFakeOFTopoGenerator(
            'ovstype', 'portsock', 'testname',
            self.NUM_DPS, False,
            host_links, host_vlans, switch_links, link_vlans,
            start_port=self.START_PORT, port_order=self.PORT_ORDER,
            get_serialno=self.get_serialno)
        config = topo.get_config(self.NUM_VLANS, dp_options=dp_options)
        return topo, config

    def verify_flood_traversal(self):
        """Verify broadcasts flooding reach all destination hosts"""
        _, host_port_maps, _ = self.topo.create_port_maps()
        for src_host in host_port_maps:
            for dst_host in host_port_maps:
                if src_host == dst_host:
                    continue
                src_dpid, src_port, dst_dpid, dst_port = None, None, None, None
                for switch_n, ports in host_port_maps[src_host].items():
                    src_dpid = self.topo.dpids_by_id[switch_n]
                    src_port = ports[0]
                for switch_n, ports in host_port_maps[dst_host].items():
                    dst_dpid = self.topo.dpids_by_id[switch_n]
                    dst_port = ports[0]
                match = self.create_bcast_match(src_port)
                self.network.is_output(match, int(src_dpid), int(dst_dpid), port=dst_port)

    def verify_vlan_change(self):
        """Change host VLAN, check restart of rules consistent"""
        _, host_port_maps, _ = self.topo.create_port_maps()
        yaml_config = yaml.safe_load(self.CONFIG)
        intf_config = yaml_config['dps'][self.topo.switches_by_id[1]]['interfaces']

        for host_i in host_port_maps:
            # Find a host on the second switch
            if 1 in host_port_maps[host_i]:
                port = host_port_maps[host_i][1][0]
                if 'native_vlan' in intf_config[port]:
                    prev_name = intf_config[port]['native_vlan']
                    for v_i in range(self.NUM_VLANS):
                        # Make sure that the new VLAN will be different
                        new_name = self.topo.vlan_name(v_i)
                        if new_name != prev_name:
                            intf_config[port]['native_vlan'] = new_name
                            break
                    else:
                        # Keep on searching for a host VLAN to change
                        continue
                    # Created a different VLAN so now stop searching
                    break

        new_config = yaml.dump(yaml_config)
        self.update_and_revert_config(self.CONFIG, new_config, None)

    def validate_topology_change(self):
        """Test warm/cold-start changing topology"""
        for network_graph in self.graphs:
            if network_graph is self.graphs[0]:
                # Ignore the first one because we are already that network
                continue
            self.serial = 0
            _, new_config = self.create_topo_config(network_graph)
            self.update_and_revert_config(self.CONFIG, new_config, None)


class ClassGenerator:
    """Generates the required classes for the integration tests"""

    GRAPH_ATLAS = graph_atlas_g()

    MAX_TESTS = 150

    graphs = None

    def __init__(self):
        """Initialize the graph atlas"""
        self.graphs = {}
        for graph in self.GRAPH_ATLAS:
            if not graph or len(graph.nodes()) < 2 or not networkx.is_connected(graph):
                continue
            self.graphs.setdefault(graph.number_of_nodes(), [])
            self.graphs[graph.number_of_nodes()].append(graph)

    @staticmethod
    def setup_generator(func):
        """Returns the class set_up function"""
        def set_up(self, graphs):
            self.graphs = graphs
            self.topo, self.CONFIG = self.create_topo_config(graphs[0])
            self.setup_valves(self.CONFIG)
            func(self)
        return set_up

    @staticmethod
    def test_generator(graphs):
        """Returns the test set_up function"""
        def test(self):
            self.set_up(graphs)
        return test

    @staticmethod
    def sums(length, total_sum):
        """Returns the permutations of `length` numbers that sum to `total_sum`"""
        if length == 1:
            yield (total_sum,)
        else:
            for value in range(total_sum + 1):
                for permutation in ClassGenerator.sums(length - 1, total_sum - value):
                    yield (value,) + permutation

    def generate_atlas_class(self, class_name, verify_name, constants):
        """Return a class type generated as each test generated from the graph atlas"""
        test_class = type(class_name, (ValveGenerativeBase, ), {**constants})
        verify_func = getattr(test_class, verify_name)
        set_up = self.setup_generator(verify_func)
        setattr(test_class, 'set_up', set_up)
        for graphs in self.graphs.values():
            for graph in graphs:
                test_func = self.test_generator([graph])
                test_name = 'test_%s' % graph.name
                setattr(test_class, test_name, test_func)
        return test_class

    def generate_atlas_size_class(self, class_name, verify_name, constants):
        """Return a class type as each test generated from a set of tests in the graph atlas"""
        test_class = type(class_name, (ValveGenerativeBase, ), {**constants})
        verify_func = getattr(test_class, verify_name)
        set_up = self.setup_generator(verify_func)
        setattr(test_class, 'set_up', set_up)
        for num_dps, graph_list in self.graphs.items():
            test_func = self.test_generator(graph_list)
            test_name = 'test_reconfigure_topologies_%s_dps' % num_dps
            setattr(test_class, test_name, test_func)
        return test_class

    def generate_spine_and_leaf_class(self, class_name, verify_name, constants):
        """Return a class type as each test generated from a set of tests in the graph atlas"""
        test_class = type(class_name, (ValveGenerativeBase, ), {**constants})
        verify_func = getattr(test_class, verify_name)
        set_up = self.setup_generator(verify_func)
        setattr(test_class, 'set_up', set_up)
        curr_nodes = 8
        curr_tests = 0
        # Iteratively generate spine & leaf networks until `MAX_TESTS` stopping point
        # By testing all non-isomorphic topologies up to (and including) 7 nodes,
        #   SPINE_NODES + LEAF_NODES <= 7 are already tested
        # Loop until we have reached a desired number of tests
        while curr_tests <= self.MAX_TESTS:
            # Get permutations of numbers that sum to the current number of nodes
            # The current number of nodes will be split between the two partites of the topology
            for nodes in ClassGenerator.sums(2, curr_nodes):
                if 0 in nodes or nodes[0] > nodes[1]:
                    # Ignore empty partites or inverse solutions
                    continue
                test_name = 'test_%s_%s_spine_and_%s_leaf_topology' % (
                    curr_tests, nodes[0], nodes[1])
                graph = networkx.complete_multipartite_graph(*nodes)
                test_func = self.test_generator([graph])
                setattr(test_class, test_name, test_func)
                curr_tests += 1
                if curr_tests > self.MAX_TESTS:
                    break
            # Increase current number of nodes
            curr_nodes += 1
        return test_class


if __name__ == '__main__':
    class_generator = ClassGenerator()
    # Generate generative tests of all non-isomorphic, complete toplogies with 7 nodes or less
    ValveTopologyVLANTest = class_generator.generate_atlas_class(
        'ValveTopologyVLANTest', 'verify_vlan_change', {'NUM_HOSTS': 2})
    ValveTopologyTableTest = class_generator.generate_atlas_class(
        'ValveTopologyTableTest', 'verify_flood_traversal', {})
    ValveTopologyRestartTest = class_generator.generate_atlas_size_class(
        'ValveTopologyRestartTest', 'validate_topology_change', {})
    # Generate spine and leaf topologies
    ValveTopologySpineAndLeafTest = class_generator.generate_spine_and_leaf_class(
        'ValveTopologySpineAndLeafTest', 'verify_flood_traversal', {})
    # Create new tests that are copies of the previous tests but test with redundant links
    ValveTopologyVLANMultilinkTest = type(
        'ValveTopologyVLANMultilinkTest', (ValveTopologyVLANTest,), {})
    ValveTopologyVLANMultilinkTest.SWITCH_TO_SWITCH_LINKS = 2
    ValveTopologyTableMultilinkTest = type(
        'ValveTopologyTableMultilinkTest', (ValveTopologyTableTest,), {})
    ValveTopologyTableMultilinkTest.SWITCH_TO_SWITCH_LINKS = 2
    ValveTopologyRestartMultilinkTest = type(
        'ValveTopologyRestartMultilinkTest', (ValveTopologyRestartTest,), {})
    ValveTopologyRestartMultilinkTest.SWITCH_TO_SWITCH_LINKS = 2
    ValveTopologySpineAndLeafMultilinkTest = type(
        'ValveTopologySpineAndLeafMultilinkTest', (ValveTopologySpineAndLeafTest,), {})
    ValveTopologySpineAndLeafMultilinkTest.SWITCH_TO_SWITCH_LINKS = 2
    # Run unit tests
    unittest.main()
