#!/usr/bin/env python3

"""Mininet tests for FAUCET fault-tolerance results.

 * must be run as root
 * you can run a specific test case only, by adding the class name of the test
   case to the command. Eg ./mininet_main.py FaucetUntaggedIPv4RouteTest

It is strongly recommended to run these tests via Docker, to ensure you have
all dependencies correctly installed. See ../docs/.
"""

import networkx
from networkx.generators.atlas import graph_atlas_g

from clib.clib_mininet_test_main import test_main
from clib.mininet_test_topo_generator import FaucetTopoGenerator

import mininet_tests


def test_generator(num_dps, num_vlans, n_dp_links, stack_roots, func_graph):
    """Return the function that will start the fault-tolerance testing for a graph"""
    def test(self):
        """Test fault-tolerance of the topology"""
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            func_graph, n_dp_links=n_dp_links)
        self.set_up(num_dps, num_vlans, dp_links, stack_roots)
        self.network_function()
    return test

if __name__ == '__main__':
    GRAPHS = {}
    GRAPH_ATLAS = graph_atlas_g()
    for graph in GRAPH_ATLAS:
        if (not graph or
                graph.number_of_nodes() > mininet_tests.MAX_NODES or
                graph.number_of_nodes() < mininet_tests.MIN_NODES):
            continue
        if networkx.is_connected(graph):
            GRAPHS.setdefault(graph.number_of_nodes(), [])
            GRAPHS[graph.number_of_nodes()].append(graph)
    for i, test_class in enumerate(mininet_tests.TEST_CLASS_LIST):
        for test_graph in GRAPHS[test_class.NUM_DPS]:
            test_name = 'test_%s' % test_graph.name
            test_func = test_generator(
                test_class.NUM_DPS, test_class.NUM_VLANS,
                test_class.N_DP_LINKS, test_class.STACK_ROOTS, test_graph)
            setattr(test_class, test_name, test_func)

    test_main([mininet_tests.__name__])
