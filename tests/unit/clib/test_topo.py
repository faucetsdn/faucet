#!/usr/bin/env python3

"""Unit tests for Mininet Topologies in mininet_test_topo"""

from unittest import TestCase, main

from clib.config_generator import FaucetFakeOFTopoGenerator


class FaucetTopoTest(TestCase):
    """Tests for Faucet test suite mininet Topo class generator"""

    serial = 0

    START_PORT = 5
    PORT_ORDER = [0, 1, 2, 3]

    class FakeExtendedHost:
        """Fake class for a mininet extended host"""

    def get_serialno(self, *_args, **_kwargs):
        """"Return mock serial number"""
        self.serial += 1
        return self.serial

    def test_port_order(self):
        """Test port order extension & port order option"""
        port_order = [3, 2, 1, 0]
        extended = FaucetFakeOFTopoGenerator.extend_port_order(port_order, max_length=8)
        self.assertEqual(extended, [3, 2, 1, 0, 7, 6, 5, 4])
        port_order = [1, 2, 3, 4, 0]
        extended = FaucetFakeOFTopoGenerator.extend_port_order(port_order, max_length=10)
        self.assertEqual(extended, [1, 2, 3, 4, 0, 6, 7, 8, 9, 5])
        host_links = {0: [0], 1: [1]}
        host_vlans = {0: 0, 1: 0}
        switch_links = [(0, 1)]
        link_vlans = {(0, 1): [0]}
        port_order = [3, 2, 1, 0]
        expected_ports = [self.START_PORT + port for port in port_order]
        topo = FaucetFakeOFTopoGenerator(
            '', '', '',
            2, False,
            host_links, host_vlans, switch_links, link_vlans,
            start_port=self.START_PORT, port_order=port_order,
            get_serialno=self.get_serialno)
        s1_name = topo.switches_by_id[0]
        s1_ports = list(topo.ports[s1_name].keys())
        self.assertEqual(s1_ports, expected_ports[:2])
        s2_name = topo.switches_by_id[1]
        s2_ports = list(topo.ports[s2_name].keys())
        self.assertEqual(s2_ports, expected_ports[:2])

    def test_start_port(self):
        """Test the topology start port parameter option"""
        start_port = 55
        host_links = {0: [0], 1: [1]}
        host_vlans = {0: 0, 1: 0}
        switch_links = [(0, 1)]
        link_vlans = {(0, 1): [0]}
        port_order = [3, 2, 1, 0]
        expected_ports = [start_port + port for port in port_order]
        topo = FaucetFakeOFTopoGenerator(
            '', '', '',
            2, False,
            host_links, host_vlans, switch_links, link_vlans,
            start_port=start_port, port_order=port_order,
            get_serialno=self.get_serialno)
        s1_name, s2_name = topo.switches_by_id.values()
        h1_name, h2_name = topo.hosts_by_id.values()
        self.assertEqual(topo.ports[s1_name][expected_ports[0]][0], s2_name)
        self.assertEqual(topo.ports[s2_name][expected_ports[0]][0], s1_name)
        self.assertEqual(topo.ports[s1_name][expected_ports[1]][0], h1_name)
        self.assertEqual(topo.ports[s2_name][expected_ports[1]][0], h2_name)

    def test_hw_build(self):
        """Test the topology is built with hardware requirements"""
        host_links = {0: [0], 1: [1]}
        host_vlans = {0: 0, 1: 0}
        switch_links = [(0, 1)]
        link_vlans = {(0, 1): [0]}
        hw_dpid = 0x123
        hw_ports = {1: 'p1', 2: 'p2', 3: 'p3', 4: 'p4', 5: 'p5', 6: 'p6'}
        topo = FaucetFakeOFTopoGenerator(
            '', '', '',
            2, False,
            host_links, host_vlans, switch_links, link_vlans,
            hw_dpid=hw_dpid, hw_ports=hw_ports,
            start_port=self.START_PORT, port_order=self.PORT_ORDER,
            get_serialno=self.get_serialno)
        self.assertEqual(topo.dpids_by_id[0], hw_dpid)
        self.assertEqual(list(topo.ports[topo.switches_by_id[0]].keys()), [1, 2])

    def test_no_links(self):
        """Test single switch topology"""
        host_links = {0: [0]}
        host_vlans = {0: 0}
        switch_links = {}
        link_vlans = {}
        topo = FaucetFakeOFTopoGenerator(
            '', '', '',
            2, False,
            host_links, host_vlans, switch_links, link_vlans,
            start_port=self.START_PORT, port_order=self.PORT_ORDER,
            get_serialno=self.get_serialno)
        self.assertEqual(len(topo.hosts()), 1)
        self.assertEqual(len(topo.switches()), 1)
        self.assertEqual(len(topo.links()), 1)
        host_name = topo.hosts_by_id[0]
        switch_name = topo.switches_by_id[0]
        self.assertEqual((switch_name, host_name), topo.links()[0])

    def test_build(self):
        """Test the topology is built correctly"""
        host_links = {0: [0], 1: [1]}
        host_vlans = {0: 0, 1: [0, 1]}
        switch_links = [(0, 1), (0, 1), (0, 1)]
        link_vlans = {(0, 1): [0, 1]}
        topo = FaucetFakeOFTopoGenerator(
            '', '', '',
            2, False,
            host_links, host_vlans, switch_links, link_vlans,
            start_port=self.START_PORT, port_order=self.PORT_ORDER,
            get_serialno=self.get_serialno)
        self.assertEqual(len(topo.dpids_by_id), 2)
        self.assertEqual(len(topo.hosts_by_id), 2)
        self.assertEqual(len(topo.switches_by_id), 2)
        _, host_port_maps, link_port_maps = topo.create_port_maps()
        self.assertEqual(len(link_port_maps[(0, 1)]), 3)
        self.assertEqual(len(host_port_maps[0]), 1)
        self.assertEqual(len(host_port_maps[1]), 1)
        host0, host1 = topo.hosts_by_id.values()
        dp0, dp1 = topo.switches_by_id.values()
        links = topo.links()
        self.assertIn((dp0, host0), links)
        self.assertIn((dp1, host1), links)
        self.assertIn((dp0, dp1), links)
        self.assertEqual(links.count((dp0, dp1)), 3)

    def test_host_options(self):
        """Test the topology correctly provides mininet host options"""
        host_options = {
            0: {'inNamespace': True, 'ip': '127.0.0.1'},
            1: {'cls': self.FakeExtendedHost}}
        host_links = {0: [0], 1: [0]}
        host_vlans = {0: 0, 1: None}
        switch_links = []
        link_vlans = {}
        topo = FaucetFakeOFTopoGenerator(
            '', '', '',
            2, False,
            host_links, host_vlans, switch_links, link_vlans,
            host_options=host_options,
            start_port=self.START_PORT, port_order=self.PORT_ORDER,
            get_serialno=self.get_serialno)
        for host_id, opts in host_options.items():
            info = topo.nodeInfo(topo.hosts_by_id[host_id])
            for key, value in opts.items():
                self.assertIn(key, info)
                self.assertEqual(value, info[key])

    def test_link_port_map(self):
        """Test correctly generated link port map"""
        host_links = {0: [0], 1: [1]}
        host_vlans = {0: 0, 1: 0}
        switch_links = [(0, 1), (0, 1), (1, 2)]
        link_vlans = {edge: None for edge in switch_links}
        topo = FaucetFakeOFTopoGenerator(
            '', '', '',
            2, False,
            host_links, host_vlans, switch_links, link_vlans,
            start_port=self.START_PORT, port_order=self.PORT_ORDER,
            get_serialno=self.get_serialno)
        link_port_maps = topo._create_link_port_map()  # pylint: disable=protected-access
        self.assertEqual(
            link_port_maps,
            {(0, 1): [5, 6], (1, 0): [5, 6], (1, 2): [7], (2, 1): [5]})

    def test_host_port_map(self):
        """Test correctly generated host port map"""
        host_links = {0: [0, 2], 1: [1]}
        host_vlans = {0: 0, 1: 0}
        switch_links = [(0, 1), (0, 1), (1, 2)]
        link_vlans = {edge: None for edge in switch_links}
        topo = FaucetFakeOFTopoGenerator(
            '', '', '',
            2, False,
            host_links, host_vlans, switch_links, link_vlans,
            start_port=self.START_PORT, port_order=self.PORT_ORDER,
            get_serialno=self.get_serialno)
        host_port_maps = topo._create_host_port_map()  # pylint: disable=protected-access
        self.assertEqual(
            host_port_maps,
            {0: {0: [7], 2: [6]}, 1: {1: [8]}})


if __name__ == "__main__":
    main()
