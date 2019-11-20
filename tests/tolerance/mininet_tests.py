#!/usr/bin/env python3

import random
import networkx
import unittest

from clib.mininet_test_topo_generator import FaucetTopoGenerator
from clib.mininet_test_watcher import TopologyWatcher
from clib.mininet_test_base_topo import FaucetTopoTestBase


class FaucetFaultToleranceBaseTest(FaucetTopoTestBase):
    """
    Generate a topology of the given parameters (using build_net & TopoBaseTest)
        and then call network function to test the network and then slowly tear out bits
        until the expected host connectivity does not match the real host connectivity.
    """

    # Watches the faults and host connectvitiy
    topo_watcher = None
    # Instantly fail the test when a single ping fails
    INSTANT_FAIL = True
    # List of fault events
    fault_events = None
    # Number of faults to occur before recalculating connectivity
    num_faults = 1

    # Randomization variables
    seed = 0
    rng = None

    def setUp(self):
        pass

    def set_up(self, n_dps, n_vlans, dp_links, stack_roots):
        """
        Args:
            n_dps: Number of DPS to generate
            n_vlans: Number of VLANs to generate
            dp_links (dict): Topology to deploy
            stack_roots (dict): Stack root values for respective stack root DPS
        """
        super(FaucetFaultToleranceBaseTest, self).setUp()
        host_links, host_vlans = FaucetTopoGenerator.untagged_vlan_hosts(n_dps, n_vlans)
        vlan_options = {}
        for i in range(n_vlans):
            vlan_options[i] = {
                'faucet_mac': self.faucet_mac(i),
                'faucet_vips': [self.faucet_vip(i)],
                'targeted_gw_resolution': False
            }
        dp_options = {}
        for i in range(n_dps):
            dp_options[i] = {
                'drop_spoofed_faucet_mac': False,
                'arp_neighbor_timeout': 2,
                'max_resolve_backoff_time': 2,
                'proactive_learn_v4': True
            }
        routers = {0: list(range(n_vlans))}
        self.build_net(
            n_dps=n_dps, n_vlans=n_vlans, dp_links=dp_links,
            host_links=host_links, host_vlans=host_vlans,
            stack_roots=stack_roots, vlan_options=vlan_options,
            dp_options=dp_options, routers=routers)
        self.start_net()

    def _ip_ping(self, host, dst, retries=3, timeout=500,
                 fping_bin='fping', intf=None, expected_result=True, count=5,
                 require_host_learned=False):
        """Override: ping a destination from a host"""
        try:
            super(FaucetFaultToleranceBaseTest, self)._ip_ping(
                host, dst, retries, timeout, fping_bin, intf,
                expected_result, count, require_host_learned)
        except AssertionError as error:
            if self.INSTANT_FAIL:
                raise error
            return False
        return True

    def calculate_connectivity(self):
        """Ping between each set of host pairs to calculate host connectivity"""
        connected_hosts = self.topo_watcher.get_connected_hosts()
        for src, dsts in connected_hosts.items():
            src_vlan = self.host_information[src]['vlan']
            src_host = self.host_information[src]['host']
            for dst in dsts:
                dst_vlan = self.host_information[dst]['vlan']
                dst_host = self.host_information[dst]['host']
                dst_ip = self.host_information[dst]['ip']
                if self.is_routed_vlans(src_vlan, dst_vlan):
                    src_faucet_vip = self.faucet_vips[src_vlan]
                    dst_faucet_vip = self.faucet_vips[dst_vlan]
                    self._ip_ping(src_host, src_faucet_vip.ip)
                    self._ip_ping(dst_host, dst_faucet_vip.ip)
                result = self._ip_ping(src_host, dst_ip.ip)
                self.topo_watcher.add_network_info(src_host.name, dst_host.name, result)

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
                name = 'Link %s[%s]:%s-%s[%s]:%s DOWN' % (
                    s1, src_dpid, port, s2, dst_dpid, peer_port)
                self.topo_watcher.add_link_fault(src_i, dst_i, name)
                break

    def random_dp_link_fault(self, *args):
        """Randomly create a fault for a DP link"""
        link_list = self.topo_watcher.get_eligable_link_events()
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
            for i in range(len(self.fault_events)):
                event_func, params = self.fault_events[i]
                for _ in range(self.num_faults):
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

    def test_2_line(self):
        """Only topology worth testing on 2 DP is a path"""
        n_dps = 2
        n_vlans = 1
        stack_roots = {0: 1}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.path_graph(n_dps))
        self.set_up(n_dps, n_vlans, dp_links, stack_roots)
        self.network_function()


class FaucetSingleFaultTolerance3DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 3 DPs"""

    NUM_DPS = 3

    def test_3_line(self):
        """Test fault-tolerance of a path of length 3"""
        n_dps = 3
        n_vlans = 1
        stack_roots = {0: 1}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.path_graph(n_dps))
        self.set_up(n_dps, n_vlans, dp_links, stack_roots)
        self.network_function()

    def test_3_node_ring_links(self):
        """Test fault-tolerance of a 3-cycle graph"""
        n_dps = 3
        n_vlans = 1
        stack_roots = {0: 1}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.cycle_graph(n_dps))
        self.set_up(n_dps, n_vlans, dp_links, stack_roots)
        self.network_function()


class FaucetSingleFaultTolerance4DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 4 DPs"""

    NUM_DPS = 4

    def test_4_node_ring_links(self):
        """Test fault-tolerance of a 4-cycle graph"""
        n_dps = 4
        n_vlans = 1
        stack_roots = {0: 1}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.cycle_graph(n_dps))
        self.set_up(n_dps, n_vlans, dp_links, stack_roots)
        self.network_function()

    def test_fat_tree_2_all_random_switch_failures(self):
        """Test randomly tearing down only switches for a 4-cycle/2-fat tree pod"""
        n_dps = 4
        n_vlans = 1
        fault_events = [
            (self.random_switch_fault, (None,)),
            (self.random_switch_fault, (None,)),
            (self.random_switch_fault, (None,)),
            (self.random_switch_fault, (None,))
        ]
        stack_roots = {i: 1 for i in range(n_dps//2)}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.cycle_graph(n_dps))
        self.set_up(n_dps, n_vlans, dp_links, stack_roots)
        self.network_function(fault_events)

    def test_fat_tree_2_single_switch_failure(self):
        """Test tearing down the first switch (a root node) for a 4-cycle/2-fat tree pod"""
        n_dps = 4
        n_vlans = 1
        fault_events = [
            (self.create_switch_fault, (0,))
        ]
        stack_roots = {i: 1 for i in range(n_dps//2)}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.cycle_graph(n_dps))
        self.set_up(n_dps, n_vlans, dp_links, stack_roots)
        self.network_function(fault_events)


@unittest.skip('6 DP too much for travis')
class FaucetSingleFaultTolerance6DPTest(FaucetFaultToleranceBaseTest):
    """Run a range of fault-tolerance tests for topologies on 6 DPs"""

    NUM_DPS = 6

    def test_fat_tree_3(self):
        """Test fault-tolerance of a 6-cycle/3-fat tree pod"""
        n_dps = 6
        n_vlans = 1
        stack_roots = {i: 1 for i in range(n_dps//2)}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.cycle_graph(n_dps))
        self.set_up(n_dps, n_vlans, dp_links, stack_roots)
        self.network_function()

    def test_3_ladder(self):
        """Test fault-tolerance of a complete ladder graph n=3"""
        n_dps = 6
        n_vlans = 1
        stack_roots = {i: 1 for i in range(n_dps//2)}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.ladder_graph(n_dps//2))
        self.set_up(n_dps, n_vlans, dp_links, stack_roots)
        self.network_function()

    def test_k33(self):
        """Test fault-tolerance of a complete bipartite graph K_{n,m} n=m=3"""
        n_dps = 6
        n_vlans = 1
        stack_roots = {i: 1 for i in range(n_dps//2)}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
            networkx.complete_bipartite_graph(n_dps//2, n_dps//2))
        self.set_up(n_dps, n_vlans, dp_links, stack_roots)
        self.network_function()
