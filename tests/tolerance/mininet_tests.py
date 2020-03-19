#!/usr/bin/env python3

import random
import unittest
import networkx

from clib.mininet_test_topo_generator import FaucetTopoGenerator
from clib.mininet_test_watcher import TopologyWatcher
from clib.mininet_test_base_topo import FaucetTopoTestBase


class FaucetFaultToleranceBaseTest(FaucetTopoTestBase):
    """
    Generate a topology of the given parameters (using build_net & TopoBaseTest)
        and then call network function to test the network and then slowly tear out bits
        until the expected host connectivity does not match the real host connectivity.
    ===============================================================================================
    INSTANT_FAIL:
        The fault-tolerant tests will continue fail if there is a pair of hosts that can not
            establish a connection.
        Set to true to allow the test suite to continue testing the connectivity
            for a fault to build the full graph for the current fault.
    ASSUME_SYMMETRIC_PING:
        A simplification can assume that (h1 -> h2) implies (h2 -> h1).
        Set to true assume that host connectivity is symmetric.
    INTERVLAN_ONLY:
        Set to true to test only the inter-VLAN connectivity; ignore connections between hosts on
            the same VLAN. Speed up the inter-VLAN testing by ignoring the intra-VLAN cases for
            tests that inherit from a intra-VLAN test. This creates that assumption that inter-VLAN
            does not disrupt the intra-VLAN.
    ===============================================================================================
    TODO: Add the following options
    PROTECTED_NODES/EDGES: Prevent desired nodes/edges from being destroyed
    ASSUME_TRANSITIVE_PING: Assume for (h1 -> h2) & (h2 -> h3) then (h1 -> h3)
    IGNORE_SUBGRAPH: Assume for a topology with subgraphs, the subgraphs do not need to be tested
        (if they have already been tested)
    """
    INSTANT_FAIL = False
    ASSUME_SYMMETRIC_PING = True
    INTERVLAN_ONLY = False

    # Watches the faults and host connectvitiy
    topo_watcher = None
    # List of fault events
    fault_events = None
    # Number of faults to occur before recalculating connectivity
    num_faults = 1
    # Fault-tolerance tests will only work in software
    SOFTWARE_ONLY = True
    # Randomization variables
    seed = 1
    rng = None

    def setUp(self):
        pass

    def set_up(self, n_dps, n_vlans, dp_links, stack_roots,
               host_links=None, host_vlans=None, host_options=None):
        """
        Args:
            n_dps: Number of DPS to generate
            n_vlans: Number of VLANs to generate
            dp_links (dict): Topology to deploy
            stack_roots (dict): Stack root values for respective stack root DPS
            host_links (dict): (optional)
            host_vlans (dict): (optional)
            host_options (dict): (optional)
        """
        super(FaucetFaultToleranceBaseTest, self).setUp()
        if not host_links or not host_vlans:
            host_links, host_vlans = FaucetTopoGenerator.untagged_vlan_hosts(n_dps, n_vlans)
        vlan_options = {}
        if n_vlans >= 2:
            for i in range(n_vlans):
                vlan_options[i] = {
                    'faucet_mac': self.faucet_mac(i),
                    'faucet_vips': [self.faucet_vip(i)],
                    'targeted_gw_resolution': False
                }
        dp_options = {}
        if n_vlans >= 2:
            for i in range(n_dps):
                dp_options[i] = {
                    'arp_neighbor_timeout': 2,
                    'max_resolve_backoff_time': 2,
                    'proactive_learn_v4': True
                }
        routers = {}
        if n_vlans >= 2:
            routers = {0: list(range(n_vlans))}
        self.build_net(
            n_dps=n_dps, n_vlans=n_vlans, dp_links=dp_links,
            host_links=host_links, host_vlans=host_vlans,
            stack_roots=stack_roots, vlan_options=vlan_options,
            dp_options=dp_options, routers=routers, host_options=host_options)
        self.start_net()

    def host_connectivity(self, host, dst):
        """Ping to a destination, return True if the ping was successful"""
        try:
            self._ip_ping(host, dst, 5, timeout=50, count=5, require_host_learned=False)
        except AssertionError:
            return False
        return True

    def calculate_connectivity(self):
        """Ping between each set of host pairs to calculate host connectivity"""
        connected_hosts = self.topo_watcher.get_connected_hosts(
            two_way=not self.ASSUME_SYMMETRIC_PING, strictly_intervlan=self.INTERVLAN_ONLY)
        for src, dsts in connected_hosts.items():
            src_host = self.host_information[src]['host']
            for dst in dsts:
                dst_host = self.host_information[dst]['host']
                dst_ip = self.host_information[dst]['ip']
                result = self.host_connectivity(src_host, dst_ip.ip)
                self.topo_watcher.add_network_info(src_host.name, dst_host.name, result)
                self.assertTrue(not self.INSTANT_FAIL or result, 'Pair connection failed')

    def create_controller_fault(self, *args):
        """
        Set controller down (disconnects all switches from the controller)
        Args:
            index: The index to the controller to take down
        """
        index = args[0]
        controller = self.net.controllers[index]
        controller.stop()
        self.net.controllers.remove(controller)
        self.topo_watcher.add_fault('Controller %s DOWN' % controller.name)

    def create_random_controller_fault(self, *args):
        """Randomly create a fault for a controller"""
        controllers = [c for c in self.net.controllers if c.name != 'gauge']
        i = random.randrange(len(controllers))
        c_name = controllers[i].name
        controller = next((cont for cont in self.net.controllers if cont.name == c_name), None)
        if controller is None:
            return
        self.create_controller_fault(self.net.controllers.index(controller))

    def create_switch_fault(self, *args):
        """
        Set switch down (Deletes the OVS switch bridge)
        Args:
            index: Index of the switch dpid to take out
        """
        index = args[0]
        dpid = self.dpids[index]
        switch_name = self.topo.dpid_names[dpid]
        switch = next((switch for switch in self.net.switches if switch.name == switch_name), None)
        if switch is None:
            return
        self.dump_switch_flows(switch)
        name = '%s:%s DOWN' % (self.dp_name(index), self.dpids[index])
        self.topo_watcher.add_switch_fault(index, name)
        switch.stop()
        switch.cmd(self.VSCTL, 'del-controller', switch.name, '|| true')
        self.assertTrue(
            self.wait_for_prometheus_var(
                'of_dp_disconnections_total', 1, dpid=dpid), 'DP %s not detected as DOWN' % dpid)
        self.net.switches.remove(switch)

    def random_switch_fault(self, *args):
        """Randomly take out an available switch"""
        dpid_list = self.topo_watcher.get_eligable_switch_events()
        if len(self.stack_roots.keys()) <= 1:
            # Prevent only root from being destroyed
            sorted_roots = {
                k: v for k, v in sorted(self.stack_roots.items(), key=lambda item: item[1])}
            for root_index in sorted_roots.keys():
                root_dpid = self.dpids[root_index]
                if root_dpid in dpid_list:
                    dpid_list.remove(root_dpid)
                    break
        if not dpid_list:
            return
        dpid_item_index = self.rng.randrange(len(dpid_list))
        dpid_item = dpid_list[dpid_item_index]
        dpid_index = self.dpids.index(dpid_item)
        self.create_switch_fault(dpid_index)

    def dp_link_fault(self, *args):
        """
        Create a fault/tear down the stack link between two switches
        Args:
            src_dp_index: Index of the source DP of the stack link
            dst_dp_index: Index of the destination DP of the stack
        """
        src_i = args[0]
        dst_i = args[1]
        src_dpid = self.dpids[src_i]
        dst_dpid = self.dpids[dst_i]
        s1 = self.dp_name(src_i)
        s2 = self.dp_name(dst_i)
        for link in self.topo.dpid_peer_links(src_dpid):
            port, peer_dpid, peer_port = link.port, link.peer_dpid, link.peer_port
            status = self.stack_port_status(src_dpid, self.dp_name(src_i), port)
            if peer_dpid == dst_dpid and status == 3:
                self.set_port_down(port, src_dpid)
                self.set_port_down(peer_port, dst_dpid)
                self.wait_for_stack_port_status(src_dpid, self.dp_name(src_i), port, 4)
                self.wait_for_stack_port_status(dst_dpid, self.dp_name(dst_i), peer_port, 4)
                name = 'Link %s[%s]:%s-%s[%s]:%s DOWN' % (
                    s1, src_dpid, port, s2, dst_dpid, peer_port)
                self.topo_watcher.add_link_fault(src_i, dst_i, name)
                return

    def random_dp_link_fault(self, *args):
        """Randomly create a fault for a DP link"""
        link_list = self.topo_watcher.get_eligable_link_events()
        if not link_list:
            return
        index = self.rng.randrange(len(link_list))
        dplink = link_list[index]
        srcdp = self.dpids.index(dplink[0])
        dstdp = self.dpids.index(dplink[1])
        self.dp_link_fault(srcdp, dstdp)

    def create_proportional_random_fault_event(self):
        """Create a fault-event randomly based on the number of link and switch events available"""
        funcs = []
        for _ in self.topo_watcher.get_eligable_link_events():
            funcs.append(self.random_dp_link_fault)
        for _ in self.topo_watcher.get_eligable_switch_events():
            funcs.append(self.random_switch_fault)
        i = self.rng.randrange(len(funcs))
        funcs[i]()

    def create_random_fault_event(self):
        """Randomly choose an event type to fault on"""
        funcs = []
        if self.topo_watcher.get_eligable_link_events():
            funcs.append(self.random_dp_link_fault)
        if self.topo_watcher.get_eligable_switch_events():
            funcs.append(self.random_switch_fault)
        if not funcs:
            return
        i = self.rng.randrange(len(funcs))
        funcs[i]()

    def network_function(self, fault_events=None, num_faults=1):
        """
        Test the network by slowly tearing it down different ways
        Args:
            fault_events: (optional) list of tuples of fault event functions and the parameters to
                use in the given order; instead of randomly choosing parts of the network to break
            num_faults: (optional) number of faults to cause before each evaluation is made
        """
        self.verify_stack_up()

        self.fault_events = fault_events
        self.num_faults = num_faults
        self.rng = random.Random(self.seed)

        self.topo_watcher = TopologyWatcher(
            self.dpids, self.dp_links, self.host_links,
            self.n_vlans, self.host_information, self.routers)

        # Calculate stats (before any tear downs)
        self.calculate_connectivity()
        self.assertTrue(self.topo_watcher.is_connected(), (
            'Host connectivity does not match predicted'))
        # Start tearing down the network
        if self.fault_events:
            # Do Specified list of faults (in order) until failure or fault list completed
            fault_index = 0
            while fault_index < len(self.fault_events):
                for _ in range(self.num_faults):
                    event_func, params = self.fault_events[fault_index]
                    fault_index += 1
                    event_func(*params)
                    self.calculate_connectivity()
                    self.assertTrue(self.topo_watcher.is_connected(), (
                        'Host connectivity does not match predicted'))
        else:
            # Continue creating fault until none are available or expected connectivity does not
            #      match real connectivity
            while self.topo_watcher.continue_faults():
                for _ in range(self.num_faults):
                    self.create_proportional_random_fault_event()
                self.calculate_connectivity()
                self.assertTrue(self.topo_watcher.is_connected(), (
                    'Host connectivity does not match predicted'))

    def tearDown(self, ignore_oferrors=False):
        """Make sure to dump the watcher information too"""
        if self.topo_watcher:
            self.topo_watcher.dump_info(self.tmpdir)
        super(FaucetFaultToleranceBaseTest, self).tearDown(ignore_oferrors=ignore_oferrors)


class FaucetSingleFaultTolerance2DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 2 DPs"""

    NUM_DPS = 2
    NUM_HOSTS = 4
    NUM_VLANS = 2
    N_DP_LINKS = 1
    STACK_ROOTS = {0: 1}


class FaucetSingleFaultTolerance3DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 3 DPs"""

    NUM_DPS = 3
    NUM_HOSTS = 6
    NUM_VLANS = 2
    N_DP_LINKS = 1
    STACK_ROOTS = {0: 1}


class FaucetSingleFaultTolerance4DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 4 DPs"""

    NUM_DPS = 4
    NUM_HOSTS = 4
    NUM_VLANS = 1
    N_DP_LINKS = 1
    STACK_ROOTS = {0: 1}

    def test_ftp2_all_random_switch_failures(self):
        """Test fat-tree-pod-2 randomly tearing down only switches"""
        fault_events = [(self.random_switch_fault, (None,)) for _ in range(self.NUM_DPS)]
        stack_roots = {2*i: 1 for i in range(self.NUM_DPS//2)}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.cycle_graph(self.NUM_DPS))
        self.set_up(self.NUM_DPS, self.NUM_VLANS, dp_links, stack_roots)
        self.network_function(fault_events=fault_events)

    def test_ftp2_all_random_link_failures(self):
        """Test fat-tree-pod-2 randomly tearing down only switch-switch links"""
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.cycle_graph(self.NUM_DPS))
        fault_events = [(self.random_dp_link_fault, (None,)) for _ in range(len(dp_links))]
        stack_roots = {2*i: 1 for i in range(self.NUM_DPS//2)}
        self.set_up(self.NUM_DPS, self.NUM_VLANS, dp_links, stack_roots)
        self.network_function(fault_events=fault_events)

    def test_ftp2_edge_root_link_fault(self):
        """Test breaking a link between a edge switch to the root aggregation switch"""
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.cycle_graph(self.NUM_DPS))
        fault_events = [(self.dp_link_fault, (0, 3))]
        stack_roots = {2*i: i+1 for i in range(self.NUM_DPS//2)}
        self.set_up(self.NUM_DPS, self.NUM_VLANS, dp_links, stack_roots)
        self.network_function(fault_events=fault_events)

    def test_ftp2_destroying_one_of_each_link(self):
        """Test tearing down one of each link for a fat-tree-pod-2 with redundant edges"""
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.cycle_graph(self.NUM_DPS), n_dp_links=2)
        fault_events = []
        for i in range(self.NUM_DPS):
            j = i+1 if i+1 < self.NUM_DPS else 0
            fault_events.append((self.dp_link_fault, (i, j)))
        num_faults = len(fault_events)
        stack_roots = {2*i: 1 for i in range(self.NUM_DPS//2)}
        self.set_up(self.NUM_DPS, self.NUM_VLANS, dp_links, stack_roots)
        self.network_function(fault_events=fault_events, num_faults=num_faults)


@unittest.skip('Too expensive for Travis to run')
class FaucetSingleFaultTolerance5DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 5 DPs"""

    NUM_DPS = 5
    NUM_HOSTS = 5
    NUM_VLANS = 1
    N_DP_LINKS = 1
    STACK_ROOTS = {0: 1}


@unittest.skip('Too expensive for Travis to run')
class FaucetSingleFaultTolerance6DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 5 DPs"""

    NUM_DPS = 6
    NUM_HOSTS = 6
    NUM_VLANS = 1
    N_DP_LINKS = 1
    STACK_ROOTS = {0: 1}


@unittest.skip('Too expensive for Travis to run')
class FaucetSingleFaultTolerance7DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 5 DPs"""

    NUM_DPS = 7
    NUM_HOSTS = 7
    NUM_VLANS = 1
    N_DP_LINKS = 1
    STACK_ROOTS = {0: 1}


TEST_CLASS_LIST = [
    FaucetSingleFaultTolerance2DPTest,
    FaucetSingleFaultTolerance3DPTest,
    FaucetSingleFaultTolerance4DPTest,
    FaucetSingleFaultTolerance5DPTest,
    FaucetSingleFaultTolerance6DPTest,
    FaucetSingleFaultTolerance7DPTest
    ]
MIN_NODES = min([c.NUM_DPS for c in TEST_CLASS_LIST])
MAX_NODES = max([c.NUM_DPS for c in TEST_CLASS_LIST])
