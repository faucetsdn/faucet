#!/usr/bin/env python3

import os
import networkx

from clib.mininet_test_base import IPV4_ETH, IPV6_ETH
from clib.mininet_test_topo_generator import FaucetTopoGenerator
from clib.mininet_test_base_topo import FaucetTopoTestBase


class FaucetMultiDPTest(FaucetTopoTestBase):
    """Replaces the FaucetStringOfDPTest for the old integration tests"""

    def setUp(self):
        pass

    def set_up(self, stack=False, n_dps=1, n_tagged=0, n_untagged=0,
               include=None, include_optional=None,
               switch_to_switch_links=1, hw_dpid=None, stack_ring=False,
               lacp=False, use_external=False,
               vlan_options=None, dp_options=None, routers=None):
        """Set up a network with the given parameters"""
        super(FaucetMultiDPTest, self).setUp()
        n_vlans = 1
        dp_links = {}
        if stack_ring:
            dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
                networkx.cycle_graph(n_dps), n_dp_links=switch_to_switch_links)
        else:
            dp_links = FaucetTopoGenerator.dp_links_networkx_graph(
                networkx.path_graph(n_dps), n_dp_links=switch_to_switch_links)
        stack_roots = None
        if stack:
            stack_roots = {0: 1}
        host_links, host_vlans = FaucetTopoGenerator.tagged_untagged_hosts(
            n_dps, n_tagged, n_untagged)
        host_options = {}
        values = [False for _ in range(n_dps)]
        if use_external:
            for host_id, links in host_links.items():
                for link in links:
                    host_options[host_id] = {'loop_protect_external': values[link]}
                    values[link] = True
        self.build_net(
            n_dps=n_dps, n_vlans=n_vlans, dp_links=dp_links,
            host_links=host_links, host_vlans=host_vlans,
            stack_roots=stack_roots, vlan_options=vlan_options,
            dp_options=dp_options, routers=routers, include=include,
            include_optional=include_optional, hw_dpid=hw_dpid,
            lacp=lacp, host_options=host_options)
        self.start_net()


class FaucetStringOfDPUntaggedTest(FaucetMultiDPTest):
    """Test untagged hosts"""

    NUM_DPS = 3
    NUM_HOSTS = 4

    def test_untagged(self):
        """All untagged hosts in multi switch topology can reach one another."""
        self.set_up(n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS)
        self.verify_stack_hosts()
        self.verify_traveling_dhcp_mac()


class FaucetStringOfDPTaggedTest(FaucetMultiDPTest):
    """Test tagged hosts"""

    NUM_DPS = 3
    NUM_HOSTS = 4

    def test_tagged(self):
        """All tagged hosts in multi switch topology can reach one another."""
        self.set_up(n_dps=self.NUM_DPS, n_tagged=self.NUM_HOSTS)
        self.verify_stack_hosts(verify_bridge_local_rule=False)
        self.verify_traveling_dhcp_mac()


class FaucetSingleStackStringOfDPTagged0Test(FaucetMultiDPTest):
    """Test topology of stacked datapaths with tagged hosts."""

    NUM_DPS = 3

    def test_tagged(self):
        """All tagged hosts in stack topology can reach each other."""
        self.set_up(
            stack=True, n_dps=self.NUM_DPS, n_tagged=self.NUM_HOSTS, switch_to_switch_links=2)
        self.verify_stack_up()
        for coldstart in (False, True):
            self.verify_one_stack_down(0, coldstart)


class FaucetSingleStackStringOfDPTagged1Test(FaucetMultiDPTest):
    """Test topology of stacked datapaths with tagged hosts."""

    NUM_DPS = 3

    def test_tagged(self):
        self.set_up(
            stack=True, n_dps=self.NUM_DPS, n_tagged=self.NUM_HOSTS, switch_to_switch_links=2)
        self.verify_stack_up()
        for coldstart in (False, True):
            self.verify_one_stack_down(1, coldstart)


class FaucetStringOfDPLACPUntaggedTest(FaucetMultiDPTest):
    """Test topology of LACP-connected datapaths with untagged hosts."""

    NUM_DPS = 2
    NUM_HOSTS = 2
    match_bcast = {'dl_vlan': FaucetMultiDPTest.vlan_vid(0), 'dl_dst': 'ff:ff:ff:ff:ff:ff'}
    action_str = 'OUTPUT:%u'

    def setUp(self):  # pylint: disable=invalid-name
        super(FaucetStringOfDPLACPUntaggedTest, self).set_up(
            stack=False,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            switch_to_switch_links=2,
            hw_dpid=self.hw_dpid,
            lacp=True)

    def lacp_ports(self):
        """Return LACP ports"""
        first_link, second_link = sorted(self.non_host_links(self.dpid))
        first_lacp_port, second_lacp_port = first_link.port, second_link.port
        remote_first_lacp_port, remote_second_lacp_port = first_link.peer_port, second_link.peer_port
        return (first_lacp_port, second_lacp_port,
                remote_first_lacp_port, remote_second_lacp_port)

    def wait_for_lacp_state(self, port_no, wanted_state, dpid, dp_name, timeout=30):
        labels = self.port_labels(port_no)
        labels.update({'dp_id': '0x%x' % int(dpid), 'dp_name': dp_name})
        if not self.wait_for_prometheus_var(
                'port_lacp_state', wanted_state,
                labels=labels, dpid=False, timeout=timeout):
            self.fail('wanted LACP state for %s to be %u' % (labels, wanted_state))

    def wait_for_lacp_port_init(self, port_no, dpid, dp_name):
        self.wait_for_lacp_state(port_no, 1, dpid, dp_name)

    def wait_for_lacp_port_up(self, port_no, dpid, dp_name):

        self.wait_for_lacp_state(port_no, 3, dpid, dp_name)

    def wait_for_lacp_port_noact(self, port_no, dpid, dp_name):
        self.wait_for_lacp_state(port_no, 5, dpid, dp_name)

    # We sort non_host_links by port because FAUCET sorts its ports
    # and only floods out of the first active LACP port in that list

    def wait_for_all_lacp_up(self):
        (first_lacp_port, second_lacp_port, remote_first_lacp_port, _) = self.lacp_ports()
        self.wait_for_lacp_port_up(first_lacp_port, self.dpid, self.DP_NAME)
        self.wait_for_lacp_port_up(second_lacp_port, self.dpid, self.DP_NAME)
        self.wait_until_matching_flow(
            self.match_bcast, self._FLOOD_TABLE, actions=[self.action_str % first_lacp_port])
        self.wait_until_matching_flow(
            self.match_bcast, self._FLOOD_TABLE, actions=[self.action_str % remote_first_lacp_port],
            dpid=self.dpids[1])

    def test_lacp_port_down(self):
        """LACP works with any member down."""
        (first_lacp_port, second_lacp_port,
         remote_first_lacp_port, remote_second_lacp_port) = self.lacp_ports()
        local_ports = {first_lacp_port, second_lacp_port}
        remote_ports = {remote_first_lacp_port, remote_second_lacp_port}

        self.wait_for_all_lacp_up()
        self.retry_net_ping()

        for local_lacp_port, remote_lacp_port in (
                (first_lacp_port, remote_first_lacp_port),
                (second_lacp_port, remote_second_lacp_port)):
            other_local_lacp_port = list(local_ports - {local_lacp_port})[0]
            other_remote_lacp_port = list(remote_ports - {remote_lacp_port})[0]
            self.set_port_down(local_lacp_port, wait=False)
            self.wait_for_lacp_port_init(
                local_lacp_port, self.dpid, self.DP_NAME)
            self.wait_for_lacp_port_init(
                remote_lacp_port, self.dpids[1], 'faucet-2')
            self.wait_until_matching_flow(
                self.match_bcast, self._FLOOD_TABLE, actions=[
                    self.action_str % other_local_lacp_port])
            self.wait_until_matching_flow(
                self.match_bcast, self._FLOOD_TABLE, actions=[
                    self.action_str % other_remote_lacp_port],
                dpid=self.dpids[1])
            self.retry_net_ping()
            self.set_port_up(local_lacp_port)
            self.wait_for_all_lacp_up()

    def test_untagged(self):
        """All untagged hosts in stack topology can reach each other, LAG_CHANGE event emitted."""
        self._enable_event_log()
        for _ in range(3):
            self.wait_for_all_lacp_up()
            self.verify_stack_hosts()
            self.flap_all_switch_ports()
        # Check for presence of LAG_CHANGE event in event socket log
        self.wait_until_matching_lines_from_file(r'.+LAG_CHANGE.+', self.event_log)

    def test_dyn_fail(self):
        """Test lacp fail on reload with dynamic lacp status."""

        conf = self._get_faucet_conf()
        (src_port, dst_port, fail_port, _) = self.lacp_ports()

        self.wait_for_lacp_port_up(src_port, self.dpids[0], 'faucet-1')
        self.wait_for_lacp_port_up(dst_port, self.dpids[0], 'faucet-1')

        interfaces_conf = conf['dps']['faucet-2']['interfaces']
        interfaces_conf[fail_port]['lacp'] = 0
        interfaces_conf[fail_port]['lacp_active'] = False
        self.reload_conf(conf, self.faucet_config_path, restart=True,
                         cold_start=False, change_expected=False)

        self.wait_for_lacp_port_init(src_port, self.dpids[0], 'faucet-1')
        self.wait_for_lacp_port_up(dst_port, self.dpids[0], 'faucet-1')

    def test_passthrough(self):
        """Test lacp passthrough on port fail."""

        conf = self._get_faucet_conf()
        (src_port, dst_port, fail_port, end_port) = self.lacp_ports()

        interfaces_conf = conf['dps']['faucet-1']['interfaces']
        interfaces_conf[dst_port]['lacp_passthrough'] = [src_port]
        interfaces_conf[dst_port]['loop_protect_external'] = True
        interfaces_conf[dst_port]['lacp'] = 2
        interfaces_conf[src_port]['loop_protect_external'] = True
        interfaces_conf = conf['dps']['faucet-2']['interfaces']
        interfaces_conf[fail_port]['loop_protect_external'] = True
        interfaces_conf[end_port]['loop_protect_external'] = True
        interfaces_conf[end_port]['lacp'] = 2

        self.reload_conf(conf, self.faucet_config_path, restart=True,
                         cold_start=False, change_expected=False)

        self.wait_for_all_lacp_up()
        self.verify_stack_hosts()

        interfaces_conf[fail_port]['lacp'] = 0
        interfaces_conf[fail_port]['lacp_active'] = False
        self.reload_conf(conf, self.faucet_config_path, restart=True,
                         cold_start=False, change_expected=False)

        self.wait_for_lacp_port_init(src_port, self.dpids[0], 'faucet-1')
        self.wait_for_lacp_port_up(dst_port, self.dpids[0], 'faucet-1')
        self.wait_for_lacp_port_init(end_port, self.dpids[1], 'faucet-2')


class FaucetStackStringOfDPUntaggedTest(FaucetMultiDPTest):
    """Test topology of stacked datapaths with untagged hosts."""

    NUM_DPS = 2
    NUM_HOSTS = 2

    def test_untagged(self):
        """All untagged hosts in stack topology can reach each other."""
        self.set_up(
            stack=True, n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS,
            switch_to_switch_links=2, hw_dpid=self.hw_dpid)
        self.verify_stack_hosts()


class FaucetSingleStackStringOfDPExtLoopProtUntaggedTest(FaucetMultiDPTest):
    """Test topology of stacked datapaths with untagged hosts."""

    NUM_DPS = 2
    NUM_HOSTS = 3

    def setUp(self):  # pylint: disable=invalid-name
        super(FaucetSingleStackStringOfDPExtLoopProtUntaggedTest, self).set_up(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            switch_to_switch_links=2,
            hw_dpid=self.hw_dpid,
            use_external=True)

    def test_untagged(self):
        """Host can reach each other, unless both marked loop_protect_external"""
        for host in self.hosts_name_ordered():
            self.require_host_learned(host)

        # Part 1: Make sure things are connected properly.
        self.verify_protected_connectivity()  # Before reload

        # Part 2: Test the code on pipeline reconfiguration path.
        conf = self._get_faucet_conf()
        loop_interface = None
        for interface, interface_conf in conf['dps'][self.dp_name(1)]['interfaces'].items():
            if 'stack' in interface_conf:
                continue
            if not interface_conf.get('loop_protect_external', False):
                loop_interface = interface
                break

        self._mark_external(loop_interface, True)
        self._mark_external(loop_interface, False)

        # Part 3: Make sure things are the same after reload.
        self.verify_protected_connectivity()  # After reload

    def _mark_external(self, loop_interface, protect_external):
        """Change the loop interfaces loop_protect_external option"""
        conf = self._get_faucet_conf()
        conf['dps'][self.dp_name(1)]['interfaces'][loop_interface]['loop_protect_external'] = protect_external
        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=False, change_expected=True)

    def test_missing_ext(self):
        """Test stacked dp with all external ports down on a switch"""
        self.validate_with_externals_down_fails(self.dp_name(0))
        self.validate_with_externals_down_fails(self.dp_name(1))


class FaucetSingleStackStringOf3DPExtLoopProtUntaggedTest(FaucetMultiDPTest):
    """Test topology of stacked datapaths with untagged hosts."""

    NUM_DPS = 3
    NUM_HOSTS = 3

    def test_untagged(self):
        """Test the external loop protect with stacked DPs and untagged hosts"""
        self.set_up(stack=True, n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS,
                    switch_to_switch_links=2, hw_dpid=self.hw_dpid, use_external=True)
        self.verify_stack_up()
        int_hosts, ext_hosts, dp_hosts = self.map_int_ext_hosts()
        _, root_ext_hosts = dp_hosts[self.DP_NAME]

        for int_host in int_hosts:
            # All internal hosts can reach other internal hosts.
            for other_int_host in int_hosts - {int_host}:
                self.verify_broadcast(
                    hosts=(int_host, other_int_host), broadcast_expected=True)
                self.verify_unicast(
                    hosts=(int_host, other_int_host), unicast_expected=True)

            # All internal hosts should reach exactly one external host.
            self.verify_one_broadcast(int_host, ext_hosts)

        for ext_host in ext_hosts:
            # All external hosts cannot flood to each other
            for other_ext_host in ext_hosts - {ext_host}:
                self.verify_broadcast(
                    hosts=(ext_host, other_ext_host), broadcast_expected=False)

        remote_ext_hosts = ext_hosts - set(root_ext_hosts)
        # int host should never be broadcast to an ext host that is not on the root.
        for local_int_hosts, _ in dp_hosts.values():
            for local_int_host in local_int_hosts:
                for remote_ext_host in remote_ext_hosts:
                    self.verify_broadcast(
                        hosts=(local_int_host, remote_ext_host), broadcast_expected=False)


class FaucetGroupStackStringOfDPUntaggedTest(FaucetStackStringOfDPUntaggedTest):
    """Test topology of stacked datapaths with untagged hosts."""

    GROUP_TABLE = True


class FaucetStackRingOfDPTest(FaucetMultiDPTest):
    """Test Faucet with a 3-cycle topology"""

    NUM_DPS = 3
    SOFTWARE_ONLY = True

    def test_untagged(self):
        """Stack loop prevention works and hosts can ping each other."""
        self.set_up(stack=True, n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS,
                    switch_to_switch_links=1, stack_ring=True)
        self.verify_stack_up()
        self.verify_stack_has_no_loop()
        self.retry_net_ping()
        self.verify_traveling_dhcp_mac()
        # Move through each DP breaking either side of the ring
        for dpid_i in range(self.NUM_DPS):
            dpid = self.dpids[dpid_i]
            dp_name = self.dp_name(dpid_i)
            for link in self.non_host_links(dpid):
                port = link.port
                self.one_stack_port_down(dpid, dp_name, port)
                self.retry_net_ping()
                self.one_stack_port_up(dpid, dp_name, port)


class FaucetSingleStack4RingOfDPTest(FaucetStackRingOfDPTest):
    """Test Faucet with a 4-cycle topology"""

    NUM_DPS = 4


class FaucetSingleStack3RingOfDPReversePortOrderTest(FaucetMultiDPTest):
    """Make sure even if the ports are in reverse order, the stack can properly form"""

    NUM_DPS = 3
    NUM_HOSTS = 1
    SOFTWARE_ONLY = True
    port_order = [3, 2, 1, 0]

    def test_sequential_connection(self):
        """Ping in sequence respective to hosts names"""
        self.set_up(stack=True, n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS,
                    switch_to_switch_links=1, stack_ring=True)
        self.verify_stack_up()
        hosts = self.hosts_name_ordered()
        for src in hosts:
            for dst in hosts:
                if src != dst:
                    self.one_ipv4_ping(src, dst.IP())

    def test_reverse_sequential_connection(self):
        """Ping in reverse sequence respective to hosts names"""
        self.set_up(stack=True, n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS,
                    switch_to_switch_links=1, stack_ring=True)
        self.verify_stack_up()
        hosts = self.hosts_name_ordered()
        hosts.reverse()
        for src in hosts:
            for dst in hosts:
                if src != dst:
                    self.one_ipv4_ping(src, dst.IP())


class FaucetSingleStack4RingOfDPReversePortOrderTest(FaucetSingleStack3RingOfDPReversePortOrderTest):

    NUM_DPS = 4


class FaucetSingleStackAclControlTest(FaucetMultiDPTest):
    """Test ACL control of stacked datapaths with untagged hosts."""

    NUM_DPS = 3
    NUM_HOSTS = 3

    def acls(self):
        map1, map2, map3 = [self.port_maps[dpid] for dpid in self.dpids]
        return {
            1: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'nw_dst': '10.1.0.2',
                    'actions': {
                        'output': {
                            'port': map1['port_2']
                        }
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'dl_dst': 'ff:ff:ff:ff:ff:ff',
                    'actions': {
                        'output': {
                            'ports': [
                                map1['port_2'],
                                map1['port_4']]
                        }
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'actions': {
                        'output': {
                            'port': map1['port_4']
                        }
                    },
                }},
                {'rule': {
                    'actions': {
                        'allow': 1,
                    },
                }},
            ],
            2: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'actions': {
                        'output': {
                            'port': map2['port_5']
                        }
                    },
                }},
                {'rule': {
                    'actions': {
                        'allow': 1,
                    },
                }},
            ],
            3: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'nw_dst': '10.1.0.7',
                    'actions': {
                        'output': {
                            'port': map3['port_1']
                        }
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'dl_dst': 'ff:ff:ff:ff:ff:ff',
                    'actions': {
                        'output': {
                            'ports': [map3['port_1']]
                        }
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'actions': {
                        'allow': 0,
                    },
                }},
                {'rule': {
                    'actions': {
                        'allow': 1,
                    },
                }},
            ],
        }

    # DP-to-acl_in port mapping.
    def acl_in_dp(self):
        map1, map2, map3 = [self.port_maps[dpid] for dpid in self.dpids]
        return {
            0: {
                # Port 1, acl_in = 1
                map1['port_1']: 1,
            },
            1: {
                # Port 4, acl_in = 2
                map2['port_4']: 2,
            },
            2: {
                # Port 4, acl_in = 3
                map3['port_4']: 3,
            },
        }

    def setUp(self):  # pylint: disable=invalid-name
        super(FaucetSingleStackAclControlTest, self).set_up(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
        )

    def test_unicast(self):
        """Hosts in stack topology can appropriately reach each other over unicast."""
        hosts = self.hosts_name_ordered()
        self.verify_stack_up()
        self.verify_tp_dst_notblocked(5000, hosts[0], hosts[1], table_id=None)
        self.verify_tp_dst_blocked(5000, hosts[0], hosts[3], table_id=None)
        self.verify_tp_dst_notblocked(5000, hosts[0], hosts[6], table_id=None)
        self.verify_tp_dst_blocked(5000, hosts[0], hosts[7], table_id=None)
        self.verify_no_cable_errors()

    def test_broadcast(self):
        """Hosts in stack topology can appropriately reach each other over broadcast."""
        hosts = self.hosts_name_ordered()
        self.verify_stack_up()
        self.verify_bcast_dst_notblocked(5000, hosts[0], hosts[1])
        self.verify_bcast_dst_blocked(5000, hosts[0], hosts[3])
        self.verify_bcast_dst_notblocked(5000, hosts[0], hosts[6])
        self.verify_bcast_dst_blocked(5000, hosts[0], hosts[7])
        self.verify_no_cable_errors()


class FaucetStringOfDPACLOverrideTest(FaucetMultiDPTest):
    """Test overriding ACL rules"""

    NUM_DPS = 1
    NUM_HOSTS = 2

    # ACL rules which will get overridden.
    def acls(self):
        return {
            1: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'ip_proto': 6,
                    'tcp_dst': 5001,
                    'actions': {
                        'allow': 1,
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'ip_proto': 6,
                    'tcp_dst': 5002,
                    'actions': {
                        'allow': 0,
                    },
                }},
                {'rule': {
                    'actions': {
                        'allow': 1,
                    },
                }},
            ],
        }

    # ACL rules which get put into an include-optional
    # file, then reloaded into FAUCET.
    @staticmethod
    def acls_override():
        return {
            1: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'ip_proto': 6,
                    'tcp_dst': 5001,
                    'actions': {
                        'allow': 0,
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'ip_proto': 6,
                    'tcp_dst': 5002,
                    'actions': {
                        'allow': 1,
                    },
                }},
                {'rule': {
                    'actions': {
                        'allow': 1,
                    },
                }},
            ],
        }

    # DP-to-acl_in port mapping.
    def acl_in_dp(self):
        port_1 = self.port_map['port_1']
        return {
            0: {
                # First port, acl_in = 1
                port_1: 1,
            },
        }

    def setUp(self):  # pylint: disable=invalid-name
        self.acls_config = os.path.join(self.tmpdir, 'acls.yaml')
        missing_config = os.path.join(self.tmpdir, 'missing_config.yaml')
        super(FaucetStringOfDPACLOverrideTest, self).set_up(
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            include_optional=[self.acls_config, missing_config])

    def test_port5001_blocked(self):
        """Test that TCP port 5001 is blocked."""
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.verify_tp_dst_notblocked(5001, first_host, second_host)
        with open(self.acls_config, 'w') as config_file:
            config_file.write(self.get_config(acls=self.acls_override()))
        self.verify_faucet_reconf(cold_start=False, change_expected=True)
        self.verify_tp_dst_blocked(5001, first_host, second_host)
        self.verify_no_cable_errors()

    def test_port5002_notblocked(self):
        """Test that TCP port 5002 is not blocked."""
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.verify_tp_dst_blocked(5002, first_host, second_host)
        with open(self.acls_config, 'w') as config_file:
            config_file.write(self.get_config(acls=self.acls_override()))
        self.verify_faucet_reconf(cold_start=False, change_expected=True)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)
        self.verify_no_cable_errors()


class FaucetTunnelSameDpTest(FaucetMultiDPTest):
    """Test the tunnel ACL option with output to the same DP"""

    NUM_DPS = 2
    NUM_HOSTS = 2
    SWITCH_TO_SWITCH_LINKS = 2

    def acls(self):
        return {
            1: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'ip_proto': 1,
                    'actions': {
                        'allow': 0,
                        'output': {
                            'tunnel': {
                                'type': 'vlan',
                                'tunnel_id': 200,
                                'dp': 'faucet-1',
                                'port': 'b%(port_2)d'}
                        }
                    }
                }}
            ]
        }

    # DP-to-acl_in port mapping.
    def acl_in_dp(self):
        port_1 = self.port_map['port_1']
        return {
            0: {
                # First port 1, acl_in = 1
                port_1: 1,
            }
        }

    def test_tunnel_established(self):
        """Test a tunnel path can be created."""
        self.set_up(stack=True, n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS,
                    switch_to_switch_links=self.SWITCH_TO_SWITCH_LINKS, hw_dpid=self.hw_dpid)
        self.verify_stack_up()
        src_host, dst_host, other_host = self.hosts_name_ordered()[:3]
        self.verify_tunnel_established(src_host, dst_host, other_host)


class FaucetTunnelTest(FaucetMultiDPTest):
    """Test the Faucet tunnel ACL option"""

    NUM_DPS = 2
    NUM_HOSTS = 2
    SWITCH_TO_SWITCH_LINKS = 2

    def acls(self):
        dpid2 = self.dpids[1]
        port2_1 = self.port_maps[dpid2]['port_1']
        return {
            1: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'ip_proto': 1,
                    'actions': {
                        'allow': 0,
                        'output': {
                            'tunnel': {
                                'type': 'vlan',
                                'tunnel_id': 200,
                                'dp': 'faucet-2',
                                'port': port2_1}
                        }
                    }
                }}
            ]
        }

    # DP-to-acl_in port mapping.
    def acl_in_dp(self):
        port_1 = self.port_map['port_1']
        return {
            0: {
                # First port 1, acl_in = 1
                port_1: 1,
            }
        }

    def setUp(self):  # pylint: disable=invalid-name
        super(FaucetTunnelTest, self).set_up(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            switch_to_switch_links=self.SWITCH_TO_SWITCH_LINKS,
            hw_dpid=self.hw_dpid)

    def test_tunnel_established(self):
        """Test a tunnel path can be created."""
        self.verify_stack_up()
        src_host, other_host, dst_host = self.hosts_name_ordered()[:3]
        self.verify_tunnel_established(src_host, dst_host, other_host)

    def test_tunnel_path_rerouted(self):
        """Test a tunnel path is rerouted when a stack is down."""
        self.verify_stack_up()
        first_stack_port = self.non_host_links(self.dpid)[0].port
        self.one_stack_port_down(self.dpid, self.DP_NAME, first_stack_port)
        src_host, other_host, dst_host = self.hosts_name_ordered()[:3]
        self.verify_tunnel_established(src_host, dst_host, other_host, packets=10)
        self.set_port_up(first_stack_port, self.dpid)


class FaucetSingleUntaggedIPV4RoutingWithStackingTest(FaucetTopoTestBase):
    """IPV4 intervlan routing with stacking test"""

    IPV = 4
    NETPREFIX = 24
    ETH_TYPE = IPV4_ETH
    NUM_DPS = 4
    NUM_HOSTS = 8
    SOFTWARE_ONLY = True

    def setUp(self):
        pass

    def set_up(self, n_dps, host_links=None, host_vlans=None):
        super(FaucetSingleUntaggedIPV4RoutingWithStackingTest, self).setUp()
        n_vlans = 3
        routed_vlans = 2
        stack_roots = {0: 1}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(networkx.path_graph(n_dps))
        if not host_links and not host_vlans:
            host_links, host_vlans = FaucetTopoGenerator.untagged_vlan_hosts(n_dps, routed_vlans)
        vlan_options = {}
        for v in range(routed_vlans):
            vlan_options[v] = {
                'faucet_mac': self.faucet_mac(v),
                'faucet_vips': [self.faucet_vip(v)],
                'targeted_gw_resolution': False
            }
        dp_options = {dp: self.get_dp_options() for dp in range(n_dps)}
        routers = {0: [v for v in range(routed_vlans)]}
        self.build_net(
            n_dps=n_dps, n_vlans=n_vlans, dp_links=dp_links,
            host_links=host_links, host_vlans=host_vlans,
            stack_roots=stack_roots, vlan_options=vlan_options,
            dp_options=dp_options, routers=routers)
        self.start_net()

    @staticmethod
    def get_dp_options():
        return {
            'drop_spoofed_faucet_mac': False,
            'arp_neighbor_timeout': 2,
            'max_resolve_backoff_time': 2,
            'proactive_learn_v4': True
        }

    def test_intervlan_routing_2stack(self):
        """Verify intervlan routing works with 2 DPs in a stack"""
        self.NUM_DPS = 2
        self.set_up(self.NUM_DPS)
        self.verify_stack_up()
        self.verify_intervlan_routing()

    def test_intervlan_routing_3stack(self):
        """Verify intervlan routing works with 3 DPs in a stack"""
        self.NUM_DPS = 3
        self.set_up(self.NUM_DPS)
        self.verify_stack_up()
        self.verify_intervlan_routing()

    def test_intervlan_routing_4stack(self):
        """Verify intervlan routing works with 4 DPs in a stack"""
        self.NUM_DPS = 4
        self.set_up(self.NUM_DPS)
        self.verify_stack_up()
        self.verify_intervlan_routing()

    def test_path_no_vlans(self):
        """Test when a DP in the path of a intervlan route contains no routed VLANs"""
        self.NUM_DPS = 3
        host_links = {i: [i] for i in range(self.NUM_DPS)}
        host_vlans = {0: 0, 1: 2, 2: 1}
        self.set_up(self.NUM_DPS, host_links=host_links, host_vlans=host_vlans)
        self.verify_stack_up()
        self.verify_intervlan_routing()

    def test_dp_one_vlan_from_router(self):
        """Test when each DP contains a subset of the routed vlans"""
        self.NUM_DPS = 2
        host_links = {i: [i] for i in range(self.NUM_DPS)}
        host_vlans = {0: 0, 1: 1}
        self.set_up(self.NUM_DPS, host_links=host_links, host_vlans=host_vlans)
        self.verify_stack_up()
        self.verify_intervlan_routing()


class FaucetSingleUntaggedIPV6RoutingWithStackingTest(FaucetSingleUntaggedIPV4RoutingWithStackingTest):
    """IPV6 intervlan routing with stacking tests"""

    IPV = 6
    NETPREFIX = 64
    ETH_TYPE = IPV6_ETH

    def get_dp_options(self):
        return {
            'drop_spoofed_faucet_mac': False,
            'nd_neighbor_timeout': 2,
            'max_resolve_backoff_time': 1,
            'proactive_learn_v6': True
        }

    def host_ping(self, src_host, dst_ip):
        self.one_ipv6_ping(src_host, dst_ip, require_host_learned=False)

    def set_host_ip(self, host, host_ip):
        self.add_host_ipv6_address(host, host_ip)

    def faucet_vip(self, i):
        """Get the IPV6 faucet vip"""
        return 'fc0%u::1:254/112' % (i+1)

    def host_ip_address(self, host_index, vlan_index):
        """Get the IPV6 host ip"""
        return 'fc0%u::1:%u/%u' % (vlan_index+1, host_index+1, self.NETPREFIX)


class FaucetSingleUntaggedVlanStackFloodTest(FaucetTopoTestBase):
    """Test InterVLAN routing can flood packets to stack ports"""

    IPV = 4
    NETPREFIX = 24
    ETH_TYPE = IPV4_ETH
    NUM_DPS = 2
    NUM_HOSTS = 2
    NUM_VLANS = 2
    SOFTWARE_ONLY = True

    def setUp(self):
        pass

    def set_up(self):
        super(FaucetSingleUntaggedVlanStackFloodTest, self).setUp()
        stack_roots = {0: 1}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(networkx.path_graph(self.NUM_DPS))
        host_links = {0: [0], 1: [1]}
        host_vlans = {0: 0, 1: 1}
        vlan_options = {}
        for v in range(self.NUM_VLANS):
            vlan_options[v] = {
                'faucet_mac': self.faucet_mac(v),
                'faucet_vips': [self.faucet_vip(v)],
                'targeted_gw_resolution': False
            }
        dp_options = {dp: self.get_dp_options() for dp in range(self.NUM_DPS)}
        routers = {0: [v for v in range(self.NUM_VLANS)]}
        self.build_net(
            n_dps=self.NUM_DPS, n_vlans=self.NUM_VLANS, dp_links=dp_links,
            host_links=host_links, host_vlans=host_vlans,
            stack_roots=stack_roots, vlan_options=vlan_options,
            dp_options=dp_options, routers=routers)
        self.start_net()

    @staticmethod
    def get_dp_options():
        return {
            'drop_spoofed_faucet_mac': False,
            'arp_neighbor_timeout': 2,
            'max_resolve_backoff_time': 2,
            'proactive_learn_v4': True
        }

    def test_intervlan_stack_flooding(self):
        """
        Test intervlan can flood to stack ports
        h1 (dst_host) should not have talked on the network so Faucet does not know about
            it. h2 (src_host) -> h1 ping will normally fail (without flooding to the stack)
            because the ARP packet for resolving h1 does not make it across the stack.
        """
        self.set_up()
        self.verify_stack_up()
        src_host = self.host_information[1]['host']
        dst_ip = self.host_information[0]['ip']
        self.host_ping(src_host, dst_ip.ip)
