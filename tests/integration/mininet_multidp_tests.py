#!/usr/bin/env python3

import json
import os
import time
import networkx
import json

from mininet.log import error

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
               lacp_trunk=False, use_external=False,
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
            lacp_trunk=lacp_trunk, host_options=host_options)
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
    SOFTWARE_ONLY = True
    match_bcast = {'dl_vlan': FaucetMultiDPTest.vlan_vid(0), 'dl_dst': 'ff:ff:ff:ff:ff:ff'}
    action_str = 'OUTPUT:%u'

    def setUp(self):  # pylint: disable=invalid-name
        super(FaucetStringOfDPLACPUntaggedTest, self).set_up(
            stack=False,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            switch_to_switch_links=2,
            hw_dpid=self.hw_dpid,
            lacp_trunk=True)

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

    def wait_for_lacp_port_none(self, port_no, dpid, dp_name):
        """Wait for LACP state NONE"""
        self.wait_for_lacp_state(port_no, 0, dpid, dp_name)

    def wait_for_lacp_port_init(self, port_no, dpid, dp_name):
        """Wait for LACP state INIT"""
        self.wait_for_lacp_state(port_no, 1, dpid, dp_name)

    def wait_for_lacp_port_up(self, port_no, dpid, dp_name):
        """Wait for LACP state UP"""
        self.wait_for_lacp_state(port_no, 3, dpid, dp_name)

    def wait_for_lacp_port_nosync(self, port_no, dpid, dp_name):
        """Wait for LACP state NOSYNC"""
        self.wait_for_lacp_state(port_no, 5, dpid, dp_name)

    # We sort non_host_links by port because FAUCET sorts its ports
    # and only floods out of the first active LACP port in that list

    def wait_for_all_lacp_up(self):
        """Wait for all LACP ports to be up"""
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
            self.wait_for_lacp_port_none(
                local_lacp_port, self.dpid, self.DP_NAME)
            self.wait_for_lacp_port_none(
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
    SOFTWARE_ONLY = True

    def verify_events_log(self, event_log):
        with open(event_log, 'r') as event_log_file:
            events = [json.loads(event_log_line.strip()) for event_log_line in event_log_file]
            l2_learns = [event['L2_LEARN'] for event in events if 'L2_LEARN' in event]
            for event in l2_learns:
                if event.get('stack_descr', None):
                    return
            self.fail('stack_descr not in events: %s' % l2_learns)

    def test_untagged(self):
        """All untagged hosts in stack topology can reach each other."""
        self.set_up(
            stack=True, n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS,
            switch_to_switch_links=2, hw_dpid=self.hw_dpid)
        self._enable_event_log()
        self.verify_stack_hosts()
        self.verify_events_log(self.event_log)


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


class FaucetSingleStackOrderedAclControlTest(FaucetMultiDPTest):
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
                        'output': [
                            {'port': map1['port_2']}
                        ]
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'dl_dst': 'ff:ff:ff:ff:ff:ff',
                    'actions': {
                        'output': [
                            {'ports': [
                                map1['port_2'],
                                map1['port_4']]}
                        ]
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'actions': {
                        'output': [
                            {'port': map1['port_4']}
                        ]
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
                        'output': [
                            {'port': map2['port_5']}
                        ]
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
                        'output': [
                            {'ports': [map3['port_1']]}
                        ]
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
        super(FaucetSingleStackOrderedAclControlTest, self).set_up(
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
    SOFTWARE_ONLY = True

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
    SOFTWARE_ONLY = True
    SWITCH_TO_SWITCH_LINKS = 2

    def acls(self):
        """Return ACL config"""
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

    def acl_in_dp(self):
        """DP to acl port mapping"""
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


class FaucetSingleTunnelTest(FaucetMultiDPTest):
    """Test the Faucet tunnel ACL option"""

    NUM_DPS = 2
    NUM_HOSTS = 2
    SOFTWARE_ONLY = True
    SWITCH_TO_SWITCH_LINKS = 2

    def acls(self):
        """Return config ACL options"""
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

    def acl_in_dp(self):
        """DP-to-acl port mapping"""
        port_1 = self.port_map['port_1']
        return {
            0: {
                # First port 1, acl_in = 1
                port_1: 1,
            }
        }

    def setUp(self):  # pylint: disable=invalid-name
        """Start the network"""
        super(FaucetSingleTunnelTest, self).set_up(
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
        """Test a tunnel path is rerouted when a link is down."""
        self.verify_stack_up()
        src_host, other_host, dst_host = self.hosts_name_ordered()[:3]
        self.verify_tunnel_established(src_host, dst_host, other_host, packets=10)
        first_stack_port = self.non_host_links(self.dpid)[0].port
        self.one_stack_port_down(self.dpid, self.DP_NAME, first_stack_port)
        src_host, other_host, dst_host = self.hosts_name_ordered()[:3]
        self.verify_tunnel_established(src_host, dst_host, other_host, packets=10)


class FaucetTunnelLoopTest(FaucetSingleTunnelTest):
    """Test tunnel on a loop topology"""

    NUM_DPS = 3
    SWITCH_TO_SWITCH_LINKS = 1

    def setUp(self):  # pylint: disable=invalid-name
        """Start a loop topology network"""
        super(FaucetSingleTunnelTest, self).set_up(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            switch_to_switch_links=self.SWITCH_TO_SWITCH_LINKS,
            hw_dpid=self.hw_dpid,
            stack_ring=True)


class FaucetTunnelAllowTest(FaucetTopoTestBase):
    """Test Tunnels with ACLs containing allow=True"""

    NUM_DPS = 2
    NUM_HOSTS = 4
    NUM_VLANS = 2
    SOFTWARE_ONLY = True

    def acls(self):
        """Return config ACL options"""
        dpid2 = self.dpids[1]
        port2_1 = self.port_maps[dpid2]['port_1']
        return {
            1: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'ip_proto': 1,
                    'actions': {
                        'allow': 1,
                        'output': {
                            'tunnel': {
                                'type': 'vlan',
                                'tunnel_id': 300,
                                'dp': 'faucet-2',
                                'port': port2_1}
                        }
                    }
                }},
                {'rule': {
                    'actions': {
                        'allow': 1,
                    }
                }},
            ]
        }

    def acl_in_dp(self):
        """DP-to-acl port mapping"""
        port_1 = self.port_map['port_1']
        return {
            0: {
                # First port 1, acl_in = 1
                port_1: 1,
            }
        }

    def setUp(self):  # pylint: disable=invalid-name
        """Start the network"""
        super(FaucetTunnelAllowTest, self).setUp()
        stack_roots = {0: 1}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(networkx.path_graph(self.NUM_DPS))
        # LACP host doubly connected to sw0 & sw1
        host_links = {0: [0], 1: [0], 2: [1], 3: [1]}
        host_vlans = {0: 0, 1: 0, 2: 1, 3: 0}
        self.build_net(
            n_dps=self.NUM_DPS, n_vlans=self.NUM_VLANS, dp_links=dp_links,
            host_links=host_links, host_vlans=host_vlans, stack_roots=stack_roots)
        self.start_net()

    def test_tunnel_continue_through_pipeline_interaction(self):
        """Test packets that enter a tunnel with allow, also continue through the pipeline"""
        # Should be able to ping from h_{0,100} -> h_{1,100} & h_{3,100}
        #   and also have the packets arrive at h_{2,200} (the other end of the tunnel)
        self.verify_stack_up()
        # Ensure connection to the host on the other end of the tunnel can exist
        src_host, other_host, dst_host = self.hosts_name_ordered()[:3]
        self.verify_tunnel_established(src_host, dst_host, other_host)
        # Ensure a connection to a host not in the tunnel can exist
        #   this implies that the packet is also sent through the pipeline
        self.check_host_connectivity_by_id(0, 1)
        self.check_host_connectivity_by_id(0, 3)


class FaucetTunnelSameDpOrderedTest(FaucetMultiDPTest):
    """Test the tunnel ACL option with output to the same DP"""

    NUM_DPS = 2
    NUM_HOSTS = 2
    SOFTWARE_ONLY = True
    SWITCH_TO_SWITCH_LINKS = 2

    def acls(self):
        """Return ACL config"""
        return {
            1: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'ip_proto': 1,
                    'actions': {
                        'allow': 0,
                        'output': [
                            {'tunnel': {
                                'type': 'vlan',
                                'tunnel_id': 200,
                                'dp': 'faucet-1',
                                'port': 'b%(port_2)d'}}
                        ]
                    }
                }}
            ]
        }

    def acl_in_dp(self):
        """DP to acl port mapping"""
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


class FaucetSingleTunnelOrderedTest(FaucetMultiDPTest):
    """Test the Faucet tunnel ACL option"""

    NUM_DPS = 2
    NUM_HOSTS = 2
    SOFTWARE_ONLY = True
    SWITCH_TO_SWITCH_LINKS = 2

    def acls(self):
        """Return config ACL options"""
        dpid2 = self.dpids[1]
        port2_1 = self.port_maps[dpid2]['port_1']
        return {
            1: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'ip_proto': 1,
                    'actions': {
                        'allow': 0,
                        'output': [
                            {'tunnel': {
                                'type': 'vlan',
                                'tunnel_id': 200,
                                'dp': 'faucet-2',
                                'port': port2_1}}
                        ]
                    }
                }}
            ]
        }

    def acl_in_dp(self):
        """DP-to-acl port mapping"""
        port_1 = self.port_map['port_1']
        return {
            0: {
                # First port 1, acl_in = 1
                port_1: 1,
            }
        }

    def setUp(self):  # pylint: disable=invalid-name
        """Start the network"""
        super(FaucetSingleTunnelOrderedTest, self).set_up(
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
        """Test a tunnel path is rerouted when a link is down."""
        self.verify_stack_up()
        src_host, other_host, dst_host = self.hosts_name_ordered()[:3]
        self.verify_tunnel_established(src_host, dst_host, other_host, packets=10)
        first_stack_port = self.non_host_links(self.dpid)[0].port
        self.one_stack_port_down(self.dpid, self.DP_NAME, first_stack_port)
        src_host, other_host, dst_host = self.hosts_name_ordered()[:3]
        self.verify_tunnel_established(src_host, dst_host, other_host, packets=10)


class FaucetTunnelLoopOrderedTest(FaucetSingleTunnelOrderedTest):
    """Test tunnel on a loop topology"""

    NUM_DPS = 3
    SWITCH_TO_SWITCH_LINKS = 1

    def setUp(self):  # pylint: disable=invalid-name
        """Start a loop topology network"""
        super(FaucetSingleTunnelOrderedTest, self).set_up(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            switch_to_switch_links=self.SWITCH_TO_SWITCH_LINKS,
            hw_dpid=self.hw_dpid,
            stack_ring=True)


class FaucetTunnelAllowOrderedTest(FaucetTopoTestBase):
    """Test Tunnels with ACLs containing allow=True"""

    NUM_DPS = 2
    NUM_HOSTS = 4
    NUM_VLANS = 2
    SOFTWARE_ONLY = True

    def acls(self):
        """Return config ACL options"""
        dpid2 = self.dpids[1]
        port2_1 = self.port_maps[dpid2]['port_1']
        return {
            1: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'ip_proto': 1,
                    'actions': {
                        'allow': 1,
                        'output': [
                            {'tunnel': {
                                'type': 'vlan',
                                'tunnel_id': 300,
                                'dp': 'faucet-2',
                                'port': port2_1}}
                        ]
                    }
                }},
                {'rule': {
                    'actions': {
                        'allow': 1,
                    }
                }},
            ]
        }

    def acl_in_dp(self):
        """DP-to-acl port mapping"""
        port_1 = self.port_map['port_1']
        return {
            0: {
                # First port 1, acl_in = 1
                port_1: 1,
            }
        }

    def setUp(self):  # pylint: disable=invalid-name
        """Start the network"""
        super(FaucetTunnelAllowOrderedTest, self).setUp()
        stack_roots = {0: 1}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(networkx.path_graph(self.NUM_DPS))
        # LACP host doubly connected to sw0 & sw1
        host_links = {0: [0], 1: [0], 2: [1], 3: [1]}
        host_vlans = {0: 0, 1: 0, 2: 1, 3: 0}
        self.build_net(
            n_dps=self.NUM_DPS, n_vlans=self.NUM_VLANS, dp_links=dp_links,
            host_links=host_links, host_vlans=host_vlans, stack_roots=stack_roots)
        self.start_net()

    def test_tunnel_continue_through_pipeline_interaction(self):
        """Test packets that enter a tunnel with allow, also continue through the pipeline"""
        # Should be able to ping from h_{0,100} -> h_{1,100} & h_{3,100}
        #   and also have the packets arrive at h_{2,200} (the other end of the tunnel)
        self.verify_stack_up()
        # Ensure connection to the host on the other end of the tunnel can exist
        src_host, other_host, dst_host = self.hosts_name_ordered()[:3]
        self.verify_tunnel_established(src_host, dst_host, other_host)
        # Ensure a connection to a host not in the tunnel can exist
        #   this implies that the packet is also sent through the pipeline
        self.check_host_connectivity_by_id(0, 1)
        self.check_host_connectivity_by_id(0, 3)


class FaucetSingleUntaggedIPV4RoutingWithStackingTest(FaucetTopoTestBase):
    """IPV4 intervlan routing with stacking test"""

    IPV = 4
    NETPREFIX = 24
    ETH_TYPE = IPV4_ETH
    NUM_DPS = 4
    NUM_HOSTS = 8
    SOFTWARE_ONLY = True

    def setUp(self):
        """Disabling allows for each test case to start the test"""
        pass

    def set_up(self, n_dps, host_links=None, host_vlans=None):
        """
        Args:
            n_dps: Number of DPs
            host_links: How to connect each host to the DPs
            host_vlans: The VLAN each host is on
        """
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
        """Return DP config options"""
        return {
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
        """Return DP config options"""
        return {
            'nd_neighbor_timeout': 2,
            'max_resolve_backoff_time': 1,
            'proactive_learn_v6': True
        }

    def host_ping(self, src_host, dst_ip, intf=None):
        """Override to ping ipv6 addresses"""
        self.one_ipv6_ping(src_host, dst_ip, require_host_learned=False)

    def set_host_ip(self, host, host_ip):
        """Override to setup host ipv6 ip address"""
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
        """Disabling allows for each test case to start the test"""
        pass

    def set_up(self):
        """Start the network"""
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
        """Return DP config options"""
        return {
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


class FaucetUntaggedStackTransitTest(FaucetTopoTestBase):
    """Test that L2 connectivity exists over a transit switch with no VLANs"""

    NUM_DPS = 3
    NUM_HOSTS = 2
    NUM_VLANS = 1
    SOFTWARE_ONLY = True

    def setUp(self):
        """Set up network with transit switch with no hosts"""
        super(FaucetUntaggedStackTransitTest, self).setUp()
        stack_roots = {0: 1}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(networkx.path_graph(self.NUM_DPS))
        host_links = {0: [0], 1: [2]}
        host_vlans = {0: 0, 1: 0}
        self.build_net(
            n_dps=self.NUM_DPS, n_vlans=self.NUM_VLANS, dp_links=dp_links,
            host_links=host_links, host_vlans=host_vlans,
            stack_roots=stack_roots)
        self.start_net()

    def test_hosts_connect_over_stack_transit(self):
        """Test to ensure that hosts can be connected over stack transit switches"""
        self.verify_stack_up()
        self.verify_intervlan_routing()


class FaucetUntaggedStackTransitVLANTest(FaucetTopoTestBase):
    """Test that L2 connectivity exists over a transit switch with different VLANs"""

    NUM_DPS = 3
    NUM_HOSTS = 2
    NUM_VLANS = 2
    SOFTWARE_ONLY = True

    def setUp(self):
        """Set up network with transit switch on different VLAN"""
        super(FaucetUntaggedStackTransitVLANTest, self).setUp()
        stack_roots = {0: 1}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(networkx.path_graph(self.NUM_DPS))
        host_links = {0: [0], 1: [1], 2: [2]}
        host_vlans = {0: 0, 1: 1, 2: 0}
        self.build_net(
            n_dps=self.NUM_DPS, n_vlans=self.NUM_VLANS, dp_links=dp_links,
            host_links=host_links, host_vlans=host_vlans,
            stack_roots=stack_roots)
        self.start_net()

    def test_hosts_connect_over_stack_transit(self):
        """Test to ensure that hosts can be connected over stack transit switches"""
        self.verify_stack_up()
        self.verify_intervlan_routing()


class FaucetSingleLAGTest(FaucetTopoTestBase):
    """Test LACP LAG on Faucet stack topologies with a distributed LAG bundle"""

    NUM_DPS = 2
    NUM_HOSTS = 5
    NUM_VLANS = 2
    SOFTWARE_ONLY = True

    LACP_HOST = 2

    @staticmethod
    def get_dp_options():
        """Return DP config options"""
        return {
            'arp_neighbor_timeout': 2,
            'max_resolve_backoff_time': 2,
            'proactive_learn_v4': True,
            'lacp_timeout': 10
        }

    def setUp(self):
        """Disabling allows for each test case to start the test"""
        pass

    def set_up(self, lacp_host_links, host_vlans=None):
        """
        Args:
            lacp_host_links: List of dpid indices the LACP host will be connected to
            host_vlans: Default generate with one host on each VLAN, on each DP
                plus one LAG host the same VLAN as hosts
        """
        super(FaucetSingleLAGTest, self).setUp()
        stack_roots = {0: 1}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(networkx.path_graph(self.NUM_DPS))
        host_links = {0: [0], 1: [0], self.LACP_HOST: lacp_host_links, 3: [1], 4: [1]}
        if host_vlans is None:
            host_vlans = {0: 0, 1: 1, 2: 1, 3: 0, 4: 1}
        vlan_options = {}
        for v in range(self.NUM_VLANS):
            vlan_options[v] = {
                'faucet_mac': self.faucet_mac(v),
                'faucet_vips': [self.faucet_vip(v)],
                'targeted_gw_resolution': False
            }
        dp_options = {dp: self.get_dp_options() for dp in range(self.NUM_DPS)}
        routers = {0: [v for v in range(self.NUM_VLANS)]}
        host_options = {self.LACP_HOST: {'lacp': 1}}
        self.build_net(
            n_dps=self.NUM_DPS, n_vlans=self.NUM_VLANS, dp_links=dp_links,
            host_links=host_links, host_vlans=host_vlans,
            stack_roots=stack_roots, vlan_options=vlan_options,
            dp_options=dp_options, host_options=host_options, routers=routers)
        self.start_net()

    def test_lacp_lag(self):
        """Test LACP LAG, where LAG bundle is connected to the same DP"""
        lacp_host_links = [0, 0]
        self.set_up(lacp_host_links)
        self.verify_stack_up()
        self.verify_lag_connectivity(self.LACP_HOST)

    def test_mclag_vip_connectivity(self):
        """Test LACP MCLAG, where LAG bundle is connected to different DPs"""
        lacp_host_links = [0, 1]
        self.set_up(lacp_host_links)
        self.verify_stack_up()
        self.verify_lag_connectivity(self.LACP_HOST)

    def restart_on_down_lag_port(self, port_dp_index, cold_start_dp_index):
        """Down a port on port_dpid_index, cold-start on cold_start_dp, UP previous port"""
        # Bring a LACP port DOWN
        chosen_dpid = self.dpids[port_dp_index]
        port_no = self.host_information[self.LACP_HOST]['ports'][chosen_dpid][0]
        self.set_port_down(port_no, chosen_dpid)
        self.verify_num_lag_up_ports(1, chosen_dpid)
        # Cold start switch, cold-start twice to get back to initial condition
        cold_start_dpid = self.dpids[cold_start_dp_index]
        conf = self._get_faucet_conf()
        interfaces_conf = conf['dps'][self.dp_name(cold_start_dp_index)]['interfaces']
        for port, port_conf in interfaces_conf.items():
            if 'lacp' not in port_conf and 'stack' not in port_conf:
                # Change host VLAN to enable cold-starting on faucet-2
                curr_vlan = port_conf['native_vlan']
                port_conf['native_vlan'] = (
                    self.vlan_name(1) if curr_vlan == self.vlan_name(0) else self.vlan_name(0))
                # VLAN changed so just delete the host information instead of recomputing
                #   routes etc..
                for _id in self.host_information:
                    if cold_start_dpid in self.host_information[_id]['ports']:
                        ports = self.host_information[_id]['ports'][cold_start_dpid]
                        if port in ports:
                            del self.host_information[_id]
                            break
                break
        self.reload_conf(
            conf, self.faucet_config_path, restart=True,
            cold_start=True, change_expected=False)
        # Bring LACP port UP
        self.set_port_up(port_no, chosen_dpid)
        self.verify_num_lag_up_ports(2, chosen_dpid)
        # Take down all of the other ports
        for dpid, ports in self.host_information[self.LACP_HOST]['ports'].items():
            if dpid != chosen_dpid:
                for port in ports:
                    if port != port_no:
                        self.set_port_down(port, dpid)

    def test_mclag_coldstart(self):
        """Test LACP MCLAG after a cold start"""
        lacp_host_links = [0, 0, 1, 1]
        self.set_up(lacp_host_links)
        self.verify_stack_up()
        self.verify_lag_host_connectivity()
        self.restart_on_down_lag_port(1, 1)
        self.verify_lag_host_connectivity()

    def test_mclag_warmstart(self):
        """Test LACP MCLAG after a warm start"""
        lacp_host_links = [0, 0, 1, 1]
        self.set_up(lacp_host_links)
        self.verify_stack_up()
        self.verify_lag_host_connectivity()
        self.restart_on_down_lag_port(0, 1)
        self.verify_lag_host_connectivity()

    def test_mclag_portrestart(self):
        """Test LACP MCLAG after a port gets restarted"""
        lacp_host_links = [0, 0, 1, 1]
        self.set_up(lacp_host_links)
        self.verify_stack_up()
        self.verify_lag_host_connectivity()
        chosen_dpid = self.dpids[0]
        port_no = self.host_information[self.LACP_HOST]['ports'][chosen_dpid][0]
        self.set_port_down(port_no, chosen_dpid)
        self.set_port_up(port_no, chosen_dpid)
        for dpid, ports in self.host_information[self.LACP_HOST]['ports'].items():
            for port in ports:
                if dpid != chosen_dpid and port != port_no:
                    self.set_port_down(port, dpid)
        self.verify_lag_host_connectivity()


class FaucetSingleLAGOnUniqueVLANTest(FaucetSingleLAGTest):
    """Test LACP LAG on Faucet stack topologies with a distributed LAG bundle on a unique VLAN"""

    NUM_VLANS = 3

    def set_up(self, lacp_host_links, host_vlans=None):
        """
        Generate tests but with the LAG host on a different VLAN
        Args:
            lacp_host_links: List of dpid indices the LACP host will be connected to
        """
        host_vlans = {0: 0, 1: 1, self.LACP_HOST: 2, 3: 0, 4: 1}
        super(FaucetSingleLAGOnUniqueVLANTest, self).set_up(lacp_host_links, host_vlans)


class FaucetSingleMCLAGComplexTest(FaucetTopoTestBase):
    """Line topology on 3 nodes, MCLAG host with 2 connections to 2 different switches"""

    NUM_DPS = 3
    NUM_HOSTS = 4
    NUM_VLANS = 1
    SOFTWARE_ONLY = True

    LACP_HOST = 3

    @staticmethod
    def get_dp_options():
        return {
            'arp_neighbor_timeout': 2,
            'max_resolve_backoff_time': 2,
            'proactive_learn_v4': True,
            'lacp_timeout': 10
        }

    def setUp(self):
        pass

    def set_up(self):
        super(FaucetSingleMCLAGComplexTest, self).setUp()
        stack_roots = {0: 1}
        dp_links = FaucetTopoGenerator.dp_links_networkx_graph(networkx.path_graph(self.NUM_DPS))
        # LACP host doubly connected to sw0 & sw1
        host_links = {0: [0], 1: [1], 2: [2], 3: [0, 0, 2, 2]}
        host_vlans = {host_id: 0 for host_id in range(self.NUM_HOSTS)}
        dp_options = {dp: self.get_dp_options() for dp in range(self.NUM_DPS)}
        host_options = {self.LACP_HOST: {'lacp': 1}}
        self.build_net(
            n_dps=self.NUM_DPS, n_vlans=self.NUM_VLANS, dp_links=dp_links,
            host_links=host_links, host_vlans=host_vlans, stack_roots=stack_roots,
            dp_options=dp_options, host_options=host_options)
        self.start_net()

    def test_lag_connectivity(self):
        """Test whether the LAG host can connect to any other host"""
        self.set_up()
        self.verify_stack_up()
        self.require_linux_bond_up(self.LACP_HOST)
        self.verify_lag_host_connectivity()

    def test_all_lacp_links(self):
        """
        All of the LAG links should work, test by using the xmit_hash_policy
            with different IP addresses to change the link used by the packet
        """
        self.set_up()
        self.verify_stack_up()
        self.require_linux_bond_up(self.LACP_HOST)
        lacp_host = self.host_information[self.LACP_HOST]['host']
        lacp_switches = {self.net.switches[i] for i in self.host_links[self.LACP_HOST]}
        lacp_intfs = sorted({
            pair[0].name for switch in lacp_switches for pair in lacp_host.connectionsTo(switch)})
        dst_host_id = 1
        dst_host = self.host_information[dst_host_id]['host']
        tcpdump_filter = (
            'ip and ether src 0e:00:00:00:00:99 '
            'and src net %s and dst net %s' % (lacp_host.IP(), dst_host.IP()))
        # Loop until all links have been used to prove that they can be used
        link_used = [False for _ in range(len(lacp_intfs))]
        max_iter = len(lacp_intfs) * 2
        iterations = 0
        while link_used.count(False) > 2 and iterations <= max_iter:
            no_packets = True
            for i, intf in enumerate(lacp_intfs):
                funcs = []
                funcs.append(lambda: lacp_host.cmd('ping -c5 %s' % dst_host.IP()))
                tcpdump_txt = self.tcpdump_helper(
                    lacp_host, tcpdump_filter, intf_name=intf, funcs=funcs)
                no_packets = self.tcpdump_rx_packets(tcpdump_txt, packets=0)
                if not no_packets:
                    # Packets detected on link so can stop testing and
                    #   goto a new IP value for the remaining links
                    link_used[i] = True
                    error('%s via %s\n' % (dst_host.IP(), intf))
                    break
            # If no packets have been detected on any port then something
            #   has gone terribly wrong
            self.assertFalse(
                no_packets, 'Ping packets to host IP %s could not be found' % dst_host.IP())
            # Increment the host IP address to change the LACP hash value,
            #   potentially changing the link used
            self.increment_host_ip(dst_host_id)
            tcpdump_filter = (
                'ip and ether src 0e:00:00:00:00:99 '
                'and src net %s and dst net %s' % (lacp_host.IP(), dst_host.IP()))
            iterations += 1
        not_used = [list(lacp_intfs)[i] for i, value in enumerate(link_used) if not value]
        expected_links = [True, True, False, False]
        self.assertEqual(link_used, expected_links, 'Links %s not used' % not_used)

    def increment_host_ip(self, host_id):
        """Increases the host ip address"""
        host = self.host_information[host_id]['host']
        self.host_information[host_id]['ip'] += 3
        self.set_host_ip(host, self.host_information[host_id]['ip'])

    def test_lacp_port_change(self):
        """
        Test that communication to a host on a LAG is possible
            after the original selected link goes DOWN
        """
        self.set_up()
        self.verify_stack_up()
        self.require_linux_bond_up(self.LACP_HOST)
        self.verify_lag_host_connectivity()
        root_dpid = self.dpids[0]
        lacp_ports = self.host_information[self.LACP_HOST]['ports']
        for port in lacp_ports[root_dpid]:
            self.set_port_down(port, root_dpid)
        self.verify_num_lag_up_ports(0, root_dpid)
        self.verify_lag_host_connectivity()

    def test_broadcast_loop(self):
        """
        LACP packets should be hashed using xmit_hash_policy layer2+3
        This means that IP & MAC & Packet type is used for hashing/choosing
            the LAG link
        When LAG host sends broadcast, the packet should only be visible on
            one link (the sending link), if the broadcast packet is detected
            on the other links, then the packet was returned to it (via the
            Faucet network)
        """
        self.set_up()
        self.verify_stack_up()
        self.require_linux_bond_up(self.LACP_HOST)
        lacp_host = self.host_information[self.LACP_HOST]['host']
        lacp_switches = {self.net.switches[i] for i in self.host_links[self.LACP_HOST]}
        lacp_intfs = {
            pair[0].name for switch in lacp_switches for pair in lacp_host.connectionsTo(switch)}
        dst_host = self.host_information[1]['host']
        # Detect initial broadcast ARP
        tcpdump_filter = ('arp and ether src 0e:00:00:00:00:99 '
                          'and ether dst ff:ff:ff:ff:ff:ff')
        # Count the number of links that contained the broadcast ARP packet
        except_count = 0
        for intf in lacp_intfs:
            funcs = []
            # Delete all ARP records of the lacp host
            for host_id in self.host_information:
                host = self.host_information[host_id]['host']
                funcs.append(lambda: host.cmd('arp -d %s' % lacp_host.IP()))
                funcs.append(lambda: host.cmd('arp -d %s' % dst_host.IP()))
                funcs.append(lambda: lacp_host.cmd('arp -d %s' % host.IP()))
            # Ping to cause broadcast ARP request
            funcs.append(lambda: lacp_host.cmd('ping -c5 %s' % dst_host.IP()))
            # Start tcpdump looking for broadcast ARP packets
            tcpdump_txt = self.tcpdump_helper(
                lacp_host, tcpdump_filter, intf_name=intf, funcs=funcs)
            try:
                self.verify_no_packets(tcpdump_txt)
            except AssertionError:
                error('Broadcast detected on %s\n' % intf)
                except_count += 1
        # Only the source LACP link should detect the packet
        self.assertEqual(
            except_count, 1,
            'Number of links detecting the broadcast ARP %s (!= 1)' % except_count)


class FaucetStackTopoChangeTest(FaucetMultiDPTest):
    """Test STACK_TOPO_CHANGE event structure"""

    NUM_DPS = 3

    def test_graph_object(self):
        """Parse event log and validate graph object in event."""
        self.set_up(
            stack=True, n_dps=self.NUM_DPS, n_tagged=self.NUM_HOSTS, switch_to_switch_links=2)
        self._enable_event_log()
        self.verify_stack_up()
        stack_event_found = False
        with open(self.event_log, 'r') as event_log_file:
            for event_log_line in event_log_file.readlines():
                event = json.loads(event_log_line.strip())
                if 'STACK_TOPO_CHANGE' in event:
                    stack_event_found = True
                    graph = event.get('STACK_TOPO_CHANGE').get('graph')
                    self.assertTrue(graph)
                    nodeCount = len(graph.get('nodes'))
                    self.assertEqual(nodeCount, 3,
                                     'Number of nodes in graph object is %s (!=3)' % nodeCount)
        self.assertTrue(stack_event_found)
