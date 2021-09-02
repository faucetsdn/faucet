"""Base class for generative testing framework"""

import random
import unittest
import networkx

from clib.mininet_test_watcher import OptimizedTopologyWatcher
from clib.mininet_test_base_topo import FaucetTopoTestBase
from clib.mininet_test_topo import FAUCET


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
        Set to true to assume that host connectivity is symmetric.
    INTERVLAN_ONLY:
        Set to true to test only the inter-VLAN connectivity; ignore connections between hosts on
            the same VLAN. Speed up the inter-VLAN testing by ignoring the intra-VLAN cases for
            tests that inherit from a intra-VLAN test. This creates that assumption that inter-VLAN
            does not disrupt the intra-VLAN.
    ASSUME_SYMMETRIC_PING:
        A simplification can assume that (h1 -> h2) implies (h2 -> h1).
        Set to true to assume that host connectivity is symmetric.
        Symmetric only assumption produces `\\sum_{i=1}^{#nodes} i` pings per stage
    ASSUME_TRANSITIVE_PING:
        Assume for (h1 -> h2) & (h2 -> h3) then (h1 -> h3)
        Set to true to assume that host connectivity is transitive
        Transitive only assumption produces `#nodes` pings per stage
    ===============================================================================================
    """

    INSTANT_FAIL = True
    INTERVLAN_ONLY = False
    ASSUME_SYMMETRIC_PING = True
    ASSUME_TRANSITIVE_PING = True

    # Watches the faults and host connectvitiy
    topo_watcher = None

    # Randomization variables
    seed = 1
    rng = None

    # List of fault events
    fault_events = None
    # Number of faults to occur before recalculating connectivity
    num_faults = 1

    # Fault-tolerance tests will only work in software
    SOFTWARE_ONLY = True

    # Number of Faucet controllers to create
    NUM_FAUCET_CONTROLLERS = 2
    # Number of VLANs to create, if >= 2 then routing will be applied
    NUM_VLANS = None
    # Number of DPs in the network
    NUM_DPS = None
    # Number of links between switches
    N_DP_LINKS = None

    # Dictionary of roots to stack priority value
    stack_roots = None

    host_links = None
    switch_links = None
    routers = None

    def setUp(self):
        pass

    def set_up(self, network_graph, stack_roots, host_links=None, host_vlans=None):
        """
        Args:
            network_graph (networkx.MultiGraph): Network topology for the test
            stack_roots (dict): The priority values for the stack roots
            host_links (dict): Links for each host to switches
            host_vlans (dict): VLAN for each host
        """
        super().setUp()
        switch_links = list(network_graph.edges()) * self.N_DP_LINKS
        link_vlans = {edge: None for edge in switch_links}
        if not host_links or not host_vlans:
            # Setup normal host links & vlans
            host_links = {}
            host_vlans = {}
            host_n = 0
            for dp_i in network_graph.nodes():
                for v_i in range(self.NUM_VLANS):
                    host_links[host_n] = [dp_i]
                    host_vlans[host_n] = v_i
                    host_n += 1
        dp_options = {}
        for i in network_graph.nodes():
            dp_options.setdefault(i, {
                'group_table': self.GROUP_TABLE,
                'ofchannel_log': self.debug_log_path + str(i) if self.debug_log_path else None,
                'hardware': 'Open vSwitch'
            })
            if i in stack_roots:
                dp_options[i]['stack'] = {'priority': stack_roots[i]}
        vlan_options = {}
        routers = {}
        if self.NUM_VLANS >= 2:
            # Setup options for routing
            routers = {0: list(range(self.NUM_VLANS))}
            for i in range(self.NUM_VLANS):
                vlan_options[i] = {
                    'faucet_mac': self.faucet_mac(i),
                    'faucet_vips': [self.faucet_vip(i)],
                    'targeted_gw_resolution': False
                }
            for i in network_graph.nodes():
                dp_options[i]['arp_neighbor_timeout'] = 2
                dp_options[i]['max_resolve_backoff_time'] = 2
                dp_options[i]['proactive_learn_v4'] = True
        self.host_links = host_links
        self.switch_links = switch_links
        self.routers = routers
        self.stack_roots = stack_roots
        self.build_net(
            host_links=host_links,
            host_vlans=host_vlans,
            switch_links=switch_links,
            link_vlans=link_vlans,
            n_vlans=self.NUM_VLANS,
            dp_options=dp_options,
            vlan_options=vlan_options,
            routers=routers
        )
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
            symmetric=self.ASSUME_SYMMETRIC_PING, transitive=self.ASSUME_TRANSITIVE_PING,
            intervlan_only=self.INTERVLAN_ONLY)
        actual_graph = networkx.MultiDiGraph()
        for src, dst in connected_hosts.edges():
            src_id = self.topo.nodeInfo(src)['host_n']
            dst_id = self.topo.nodeInfo(dst)['host_n']
            result = self.host_connectivity(
                self.host_information[src_id]['host'], self.host_information[dst_id]['ip'].ip)
            if result:
                actual_graph.add_edge(src, dst)
            if self.INSTANT_FAIL:
                self.assertTrue(result, 'Connection failed: %s -/-> %s' % (src, dst))
        self.assertEqual(
            list(connected_hosts.edges()), list(actual_graph.edges()),
            'Resulting host connectivity graph does not match expected (%s != %s)' % (
                list(connected_hosts.edges()), list(actual_graph.edges())))

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

    def get_faucet_controllers(self):
        """Return list of Faucet controllers"""
        return [c for c in self.net.controllers if isinstance(c, FAUCET)]

    def create_random_controller_fault(self, *_args):
        """Randomly create a fault for a controller"""
        controllers = self.get_faucet_controllers()
        if len(controllers) == 1:
            return
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
        switch_name = self.topo.switches_by_id[index]
        switch = next((switch for switch in self.net.switches if switch.name == switch_name), None)
        if switch is None:
            return
        self.dump_switch_flows(switch)
        name = '%s:%s DOWN' % (self.topo.switches_by_id[index], self.dpids[index])
        self.topo_watcher.add_switch_fault(index, name)
        switch.stop()
        switch.cmd(self.VSCTL, 'del-controller', switch.name, '|| true')
        self.assertTrue(
            self.wait_for_prometheus_var(
                'of_dp_disconnections_total', 1, dpid=dpid), 'DP %s not detected as DOWN' % dpid)
        self.net.switches.remove(switch)

    def random_switch_fault(self, *_args):
        """Randomly take out an available switch"""
        sw_list = self.topo_watcher.get_eligable_switch_events()
        index_list = []
        for sw_name in sw_list:
            index_list.append(self.topo.nodeInfo(sw_name)['switch_n'])
        if len(self.stack_roots.keys()) <= 1:
            # Prevent the only root from being destroyed
            sorted_roots = dict(sorted(self.stack_roots.items(), key=lambda item: item[1]))
            for root_index in sorted_roots.keys():
                if root_index in index_list:
                    index_list.remove(root_index)
        if not index_list:
            return
        index = self.rng.randrange(len(index_list))
        sw_index = index_list[index]
        self.create_switch_fault(sw_index)

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
        s1_name = self.topo.switches_by_id[src_i]
        s2_name = self.topo.switches_by_id[dst_i]
        for port, link in self.topo.ports[s1_name].items():
            status = self.stack_port_status(src_dpid, s1_name, port)
            if link[0] == s2_name and status == 3:
                peer_port = link[1]
                self.set_port_down(port, src_dpid)
                self.set_port_down(peer_port, dst_dpid)
                self.wait_for_stack_port_status(src_dpid, s1_name, port, 4)
                self.wait_for_stack_port_status(dst_dpid, s2_name, peer_port, 4)
                name = 'Link %s[%s]:%s-%s[%s]:%s DOWN' % (
                    s1_name, src_dpid, port, s2_name, dst_dpid, peer_port)
                self.topo_watcher.add_link_fault(src_i, dst_i, name)
                return

    def random_link_fault(self, *_args):
        """Randomly create a fault for a DP link"""
        link_list = self.topo_watcher.get_eligable_link_events()
        if not link_list:
            return
        index = self.rng.randrange(len(link_list))
        dp_link = link_list[index]
        src_i = self.topo.nodeInfo(dp_link[0])['switch_n']
        dst_i = self.topo.nodeInfo(dp_link[1])['switch_n']
        self.dp_link_fault(src_i, dst_i)

    def create_proportional_random_fault_event(self):
        """Create a fault-event randomly based on the number of link and switch events available"""
        funcs = []
        for _ in self.topo_watcher.get_eligable_link_events():
            funcs.append(self.random_link_fault)
        for _ in self.topo_watcher.get_eligable_switch_events():
            funcs.append(self.random_switch_fault)
        for _ in range(len(self.get_faucet_controllers()) - 1):
            funcs.append(self.create_random_controller_fault)
        random.shuffle(funcs)
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

        self.topo_watcher = OptimizedTopologyWatcher(
            self.topo, self.host_information, self.configuration_options['routers'])

        # Calculate stats (before any tear downs)
        self.calculate_connectivity()
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
        else:
            # Continue creating fault until none are available or expected connectivity does not
            #      match real connectivity
            while (self.topo_watcher.continue_faults() or bool(len(self.get_faucet_controllers()) - 1)):
                for _ in range(self.num_faults):
                    self.create_proportional_random_fault_event()
                self.calculate_connectivity()

    def tearDown(self, ignore_oferrors=False):
        """Make sure to dump the watcher information too"""
        if self.topo_watcher:
            self.topo_watcher.dump_info(self.tmpdir)
        super().tearDown(ignore_oferrors=ignore_oferrors)


class FaucetFaultTolerance2DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 2 DPs"""

    NUM_DPS = 2
    NUM_HOSTS = 4
    NUM_VLANS = 2
    N_DP_LINKS = 1
    STACK_ROOTS = {0: 1}
    ASSUME_SYMMETRIC_PING = False


class FaucetFaultTolerance3DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 3 DPs"""

    NUM_DPS = 3
    NUM_HOSTS = 6
    NUM_VLANS = 2
    N_DP_LINKS = 1
    STACK_ROOTS = {0: 1}


class FaucetFaultTolerance4DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 4 DPs"""

    NUM_DPS = 4
    NUM_HOSTS = 4
    NUM_VLANS = 1
    N_DP_LINKS = 1
    STACK_ROOTS = {0: 1}

    def test_ftp2_all_random_switch_failures(self):
        """Test fat-tree-pod-2 randomly tearing down only switches"""
        fault_events = [(self.random_switch_fault, (None,)) for _ in range(self.NUM_DPS)]
        stack_roots = {2 * i: 1 for i in range(self.NUM_DPS // 2)}
        self.set_up(networkx.cycle_graph(self.NUM_DPS), stack_roots)
        self.network_function(fault_events=fault_events)

    def test_ftp2_all_random_link_failures(self):
        """Test fat-tree-pod-2 randomly tearing down only switch-switch links"""
        network_graph = networkx.cycle_graph(self.NUM_DPS)
        fault_events = [
            (self.random_link_fault, (None,)) for _ in range(len(network_graph.edges()))]
        stack_roots = {2 * i: 1 for i in range(self.NUM_DPS // 2)}
        self.set_up(network_graph, stack_roots)
        self.network_function(fault_events=fault_events)

    def test_ftp2_edge_root_link_fault(self):
        """Test breaking a link between a edge switch to the root aggregation switch"""
        fault_events = [(self.dp_link_fault, (0, 3))]
        stack_roots = {2 * i: i + 1 for i in range(self.NUM_DPS // 2)}
        self.set_up(networkx.cycle_graph(self.NUM_DPS), stack_roots)
        self.network_function(fault_events=fault_events)

    def test_ftp2_destroying_one_of_each_link(self):
        """Test tearing down one of each link for a fat-tree-pod-2 with redundant edges"""
        self.N_DP_LINKS = 2
        fault_events = []
        for i in range(self.NUM_DPS):
            j = i + 1 if i + 1 < self.NUM_DPS else 0
            fault_events.append((self.dp_link_fault, (i, j)))
        num_faults = len(fault_events)
        stack_roots = {2 * i: 1 for i in range(self.NUM_DPS // 2)}
        self.set_up(networkx.cycle_graph(self.NUM_DPS), stack_roots)
        self.network_function(fault_events=fault_events, num_faults=num_faults)
        self.N_DP_LINKS = 1


class FaucetFaultTolerance5DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 5 DPs"""

    NUM_DPS = 5
    NUM_HOSTS = 5
    NUM_VLANS = 1
    N_DP_LINKS = 1
    STACK_ROOTS = {0: 1}


class FaucetFaultTolerance6DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 5 DPs"""

    NUM_DPS = 6
    NUM_HOSTS = 6
    NUM_VLANS = 1
    N_DP_LINKS = 1
    STACK_ROOTS = {0: 1}


@unittest.skip('Too computationally complex')
class FaucetFaultTolerance7DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 5 DPs"""

    NUM_DPS = 7
    NUM_HOSTS = 7
    NUM_VLANS = 1
    N_DP_LINKS = 1
    STACK_ROOTS = {0: 1}


TEST_CLASS_LIST = [
    FaucetFaultTolerance2DPTest,
    FaucetFaultTolerance3DPTest,
    FaucetFaultTolerance4DPTest,
    FaucetFaultTolerance5DPTest,
    FaucetFaultTolerance6DPTest,
    FaucetFaultTolerance7DPTest
]
MIN_NODES = min([c.NUM_DPS for c in TEST_CLASS_LIST])
MAX_NODES = max([c.NUM_DPS for c in TEST_CLASS_LIST])
