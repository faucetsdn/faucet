#!/usr/bin/env python3

"""Mininet multi-switch integration tests for Faucet"""

import json
import os
import networkx

from mininet.log import error

from clib.mininet_test_base import IPV4_ETH, IPV6_ETH
from clib.mininet_test_base_topo import FaucetTopoTestBase


class FaucetMultiDPTest(FaucetTopoTestBase):
    """Converts old FaucetStringOfDPTest class to a generalized test topology & config builder"""

    def mininet_host_options(self):
        """Additional mininet host options"""
        return {}

    def include(self):
        """Additional include files"""
        return []

    def include_optional(self):
        """Additional optional-include files"""
        return []

    def dp_options(self):
        """Additional DP options"""
        return {}

    def host_options(self):
        """Additional host options"""
        return {}

    def link_options(self):
        """Additional link options"""
        return {}

    def vlan_options(self):
        """Additional VLAN options"""
        return {}

    def router_options(self):
        """Additional router options"""
        return {}

    def link_acls(self):
        """Host index or (switch index, switch index) link to acls_in mapping"""
        return {}

    def output_only(self):
        return set()

    def setUp(self):
        pass

    def set_up(self, stack=False, n_dps=1, n_tagged=0, n_untagged=0,
               switch_to_switch_links=1, stack_ring=False,
               lacp_trunk=False, use_external=False, routers=None):
        """
        Args:
            stack (bool): Whether to use stack or trunk links
            n_dps (int): The number of DPs in the topology
            n_tagged (int): The number of tagged hosts per DP
            n_untagged (int): The number of untagged hosts per DP
            switch_to_switch_links (int): The number of switch-switch links to generate
            stack_ring (bool): Whether to generate a cycle graph or a path graph
            lacp_trunk (bool): If true, configure LACP on trunk ports
            use_external (bool): If true, configure loop_protect_external
            routers (dict): The routers to generate in the configuration file
        """
        super().setUp()
        n_vlans = 1
        dp_links = {}
        if stack_ring:
            dp_links = networkx.cycle_graph(n_dps)
        else:
            dp_links = networkx.path_graph(n_dps)
        # Create list of switch-switch links for network topology
        switch_links = []
        switch_links = list(dp_links.edges()) * switch_to_switch_links
        # Create link type for the switch-switch links
        link_vlans = {}
        vlans = None if stack else list(range(n_vlans))
        for dp_i in dp_links.nodes():
            for link in dp_links.edges(dp_i):
                link_vlans[link] = vlans
        # Create link configuration options for DP interfaces
        link_options = {}
        for dp_i in dp_links.nodes():
            for link in dp_links.edges(dp_i):
                if lacp_trunk:
                    link_options.setdefault(link, {})
                    link_options[link] = {
                        'lacp': 1,
                        'lacp_active': True
                    }
        if self.link_options():
            for dp_i in dp_links.nodes():
                for link in dp_links.edges(dp_i):
                    link_options.setdefault(link, {})
                    for opt_key, opt_value in self.link_options().items():
                        link_options[link][opt_key] = opt_value
        # Create host link topology and vlan information
        host_links = {}
        host_vlans = {}
        tagged_vlans = list(range(n_vlans))
        host = 0
        for dp_i in range(n_dps):
            for _ in range(n_tagged):
                host_links[host] = [dp_i]
                host_vlans[host] = tagged_vlans
                host += 1
            for _ in range(n_untagged):
                host_links[host] = [dp_i]
                host_vlans[host] = 0
                host += 1
        for host in self.output_only():
            host_vlans[host] = None
        # Create Host configuration options for DP interfaces
        host_options = {}
        if use_external:
            # The first host with a link to a switch without an external host
            #   becomes an external host on all links
            values = [False for _ in range(n_dps)]
            for host, links in host_links.items():
                make_external = False
                for link in links:
                    if not values[link]:
                        make_external = True
                        values[link] = True
                host_options.setdefault(host, {})
                host_options[host]['loop_protect_external'] = make_external
        for host in host_links:
            for h_key, h_value in self.host_options().items():
                host_options[host][h_key] = h_value
        # Create DP configuration options
        dp_options = {}
        for dp_i in range(n_dps):
            dp_options.setdefault(dp_i, {
                'group_table': self.GROUP_TABLE,
                'ofchannel_log': self.debug_log_path + str(dp_i) if self.debug_log_path else None,
                'hardware': self.hardware if dp_i == 0 and self.hw_dpid else 'Open vSwitch'
            })
            if stack and dp_i == 0:
                dp_options[dp_i]['stack'] = {'priority': 1}
            if lacp_trunk:
                dp_options[dp_i]['lacp_timeout'] = 10
            for dp_key, dp_value in self.dp_options().items():
                dp_options[dp_i][dp_key] = dp_value
        # Create VLAN configuration options
        vlan_options = {}
        if routers:
            for vlans in routers:
                for vlan in vlans:
                    if vlan not in vlan_options:
                        vlan_options[vlan] = {
                            'faucet_mac': self.faucet_mac(vlan),
                            'faucet_vips': [self.faucet_vip(vlan)],
                            'targeted_gw_resolution': False
                        }
        for vlan in range(n_vlans):
            vlan_options.setdefault(vlan, {})
            for vlan_key, vlan_value in self.vlan_options().items():
                vlan_options[vlan][vlan_key] = vlan_value
        if self.link_acls():
            for link, acls in self.link_acls().items():
                if isinstance(link, tuple):
                    # link ACL
                    link_options.setdefault(link, {})
                    link_options[link]['acls_in'] = acls
                elif isinstance(link, int):
                    # host ACL
                    host_options.setdefault(link, {})
                    host_options[link]['acls_in'] = acls
        self.build_net(
            host_links=host_links,
            host_vlans=host_vlans,
            switch_links=switch_links,
            link_vlans=link_vlans,
            mininet_host_options=self.mininet_host_options(),
            n_vlans=n_vlans,
            dp_options=dp_options,
            host_options=host_options,
            link_options=link_options,
            vlan_options=vlan_options,
            routers=routers,
            router_options=self.router_options(),
            include=self.include(),
            include_optional=self.include_optional()
        )
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
        """Test all tagged hosts in stack topology can reach each other with one stack down"""
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
    match_bcast = {'dl_vlan': 100, 'dl_dst': 'ff:ff:ff:ff:ff:ff'}
    action_str = 'OUTPUT:%u'

    def setUp(self):  # pylint: disable=invalid-name
        """Setup network & create config file"""
        super(FaucetStringOfDPLACPUntaggedTest, self).set_up(
            stack=False,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            switch_to_switch_links=2,
            lacp_trunk=True)

    def lacp_ports(self):
        """Return LACP ports"""
        # We sort non_host_links by port because FAUCET sorts its ports
        # and only floods out of the first active LACP port in that list
        sname = self.topo.switches_by_id[0]
        dname = self.topo.switches_by_id[1]
        first_link, second_link = None, None
        for sport, link in self.topo.ports[sname].items():
            if link[0] == dname:
                if first_link is None:
                    first_link = (sport, link[1])
                else:
                    second_link = (sport, link[1])
        first_link, second_link = sorted([first_link, second_link])
        first_lacp_port, remote_first_lacp_port = first_link
        second_lacp_port, remote_second_lacp_port = second_link
        return (first_lacp_port, second_lacp_port,
                remote_first_lacp_port, remote_second_lacp_port)

    def wait_for_lacp_state(self, port_no, wanted_state, dpid, dp_name, timeout=30):
        """Wait for LACP port state"""
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

    def wait_for_all_lacp_up(self):
        """Wait for all LACP ports to be up"""
        (first_lacp_port, second_lacp_port, remote_first_lacp_port, _) = self.lacp_ports()
        self.wait_for_lacp_port_up(first_lacp_port, self.dpids[0], self.topo.switches_by_id[0])
        self.wait_for_lacp_port_up(second_lacp_port, self.dpids[0], self.topo.switches_by_id[0])
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
                local_lacp_port, self.dpids[0], self.topo.switches_by_id[0])
            self.wait_for_lacp_port_none(
                remote_lacp_port, self.dpids[1], self.topo.switches_by_id[1])
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
        # Check for presence of LAG_CHANGE event in event socket log and check for it's structure
        lag_event_found = None
        with open(self.event_log, 'r') as event_log_file:
            for event_log_line in event_log_file.readlines():
                event = json.loads(event_log_line.strip())
                if 'LAG_CHANGE' in event:
                    lag_event_found = event.get('LAG_CHANGE')
                    break
        self.assertTrue(lag_event_found)
        if lag_event_found:
            self.assertIn('state', lag_event_found)
            self.assertIn('role', lag_event_found)

    def test_dyn_fail(self):
        """Test lacp fail on reload with dynamic lacp status."""

        conf = self._get_faucet_conf()
        (src_port, dst_port, fail_port, _) = self.lacp_ports()

        self.wait_for_lacp_port_up(src_port, self.dpids[0], self.topo.switches_by_id[0])
        self.wait_for_lacp_port_up(dst_port, self.dpids[0], self.topo.switches_by_id[0])

        interfaces_conf = conf['dps'][self.topo.switches_by_id[1]]['interfaces']
        interfaces_conf[fail_port]['lacp'] = 0
        interfaces_conf[fail_port]['lacp_active'] = False
        self.reload_conf(conf, self.faucet_config_path, restart=True,
                         cold_start=False, change_expected=True)

        self.wait_for_lacp_port_init(src_port, self.dpids[0], self.topo.switches_by_id[0])
        self.wait_for_lacp_port_up(dst_port, self.dpids[0], self.topo.switches_by_id[0])

    def test_passthrough(self):
        """Test lacp passthrough on port fail."""

        conf = self._get_faucet_conf()
        (src_port, dst_port, fail_port, end_port) = self.lacp_ports()

        interfaces_conf = conf['dps'][self.topo.switches_by_id[0]]['interfaces']
        interfaces_conf[dst_port]['lacp_passthrough'] = [src_port]
        interfaces_conf[dst_port]['loop_protect_external'] = True
        interfaces_conf[dst_port]['lacp'] = 2
        interfaces_conf[src_port]['loop_protect_external'] = True
        interfaces_conf = conf['dps'][self.topo.switches_by_id[1]]['interfaces']
        interfaces_conf[fail_port]['loop_protect_external'] = True
        interfaces_conf[end_port]['loop_protect_external'] = True
        interfaces_conf[end_port]['lacp'] = 2

        self.reload_conf(conf, self.faucet_config_path, restart=True,
                         cold_start=True, change_expected=True)

        self.wait_for_all_lacp_up()
        self.verify_stack_hosts()

        interfaces_conf[fail_port]['lacp'] = 0
        interfaces_conf[fail_port]['lacp_active'] = False
        self.reload_conf(conf, self.faucet_config_path, restart=True,
                         cold_start=False, change_expected=True)

        self.wait_for_lacp_port_init(src_port, self.dpids[0], self.topo.switches_by_id[0])
        self.wait_for_lacp_port_up(dst_port, self.dpids[0], self.topo.switches_by_id[0])
        self.wait_for_lacp_port_init(end_port, self.dpids[1], self.topo.switches_by_id[1])


class FaucetStackStringOfDPUntaggedTest(FaucetMultiDPTest):
    """Test topology of stacked datapaths with untagged hosts."""

    NUM_DPS = 2
    NUM_HOSTS = 2
    SOFTWARE_ONLY = True

    def verify_events_log(self, event_log):
        """Verify event log has correct L2 learn events"""
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
            switch_to_switch_links=2)
        self._enable_event_log()
        self.verify_stack_hosts()
        self.verify_events_log(self.event_log)


class FaucetSingleStackStringOfDPExtLoopProtUntaggedTest(FaucetMultiDPTest):
    """Test topology of stacked datapaths with untagged hosts."""

    NUM_DPS = 2
    NUM_HOSTS = 3

    def setUp(self):  # pylint: disable=invalid-name
        """Setup network & configuration file"""
        super(FaucetSingleStackStringOfDPExtLoopProtUntaggedTest, self).set_up(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            switch_to_switch_links=2,
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
        dp_name = self.topo.switches_by_id[1]
        for interface, interface_conf in conf['dps'][dp_name]['interfaces'].items():
            if 'stack' in interface_conf:
                continue
            if not interface_conf.get('loop_protect_external', False):
                loop_interface = interface
                break

        self._mark_external(loop_interface, True)
        self._mark_external(loop_interface, False)

        # Part 3: Make sure things are the same after reload.
        self.verify_protected_connectivity()  # After reload

    def _mark_external(self, loop_intf, protect_external):
        """Change the loop interfaces loop_protect_external option"""
        conf = self._get_faucet_conf()
        dp_name = self.topo.switches_by_id[1]
        conf['dps'][dp_name]['interfaces'][loop_intf]['loop_protect_external'] = protect_external
        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=False, change_expected=True, dpid=self.topo.dpids_by_id[1])

    def test_missing_ext(self):
        """Test stacked dp with all external ports down on a switch"""
        self.validate_with_externals_down_fails(self.topo.switches_by_id[0])
        self.validate_with_externals_down_fails(self.topo.switches_by_id[1])


class FaucetSingleStackStringOf3DPExtLoopProtUntaggedTest(FaucetMultiDPTest):
    """Test topology of stacked datapaths with untagged hosts."""

    NUM_DPS = 3
    NUM_HOSTS = 3

    def test_untagged(self):
        """Test the external loop protect with stacked DPs and untagged hosts"""
        self.set_up(stack=True, n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS,
                    switch_to_switch_links=2, use_external=True)
        self.verify_stack_up()
        int_hosts, ext_hosts, dp_hosts = self.map_int_ext_hosts()
        _, root_ext_hosts = dp_hosts[self.topo.switches_by_id[0]]

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
        for link, ports in self.link_port_maps.items():
            dp_i, _ = link
            dpid = self.topo.dpids_by_id[dp_i]
            name = self.topo.switches_by_id[dp_i]
            for port in ports:
                self.one_stack_port_down(dpid, name, port)
                self.retry_net_ping()
                self.one_stack_port_up(dpid, name, port)


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
    """Test different port orders maintain consistent stack behaviour with size 4 ring topology"""

    NUM_DPS = 4


class FaucetSingleStackAclControlTest(FaucetMultiDPTest):
    """Test ACL control of stacked datapaths with untagged hosts."""

    NUM_DPS = 3
    NUM_HOSTS = 3

    def acls(self):
        """Configuration ACLs"""
        # 3 hosts on each DP (3 DPS)
        return {
            1: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'nw_dst': '10.1.0.2',
                    'actions': {
                        'output': {
                            'port': self.host_port_maps[1][0][0]  # Host 1
                        }
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'dl_dst': 'ff:ff:ff:ff:ff:ff',
                    'actions': {
                        'output': {
                            'ports': [
                                self.host_port_maps[1][0][0],  # Host 1
                                self.link_port_maps[(0, 1)][0]]  # link (0, 1)
                        }
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'actions': {
                        'output': {
                            'port': self.link_port_maps[(0, 1)][0]  # link (0, 1)
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
                            'port': self.link_port_maps[(1, 2)][0]  # link (1, 2)
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
                            'port': self.host_port_maps[6][2][0]  # host 6
                        }
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'dl_dst': 'ff:ff:ff:ff:ff:ff',
                    'actions': {
                        'output': {
                            'ports': [self.host_port_maps[6][2][0]]  # host 6
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
    def link_acls(self):
        """Host/link map to acls_in"""
        return {
            0: [1],  # Host 0 dp 0 'acls_in': [1]
            (1, 0): [2],
            (2, 1): [3]
        }

    def setUp(self):  # pylint: disable=invalid-name
        """Setup network & create configuration file"""
        super(FaucetSingleStackAclControlTest, self).set_up(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
        )

    def test_unicast(self):
        """Hosts in stack topology can appropriately reach each other over unicast."""
        host0 = self.net.get(self.topo.hosts_by_id[0])
        host1 = self.net.get(self.topo.hosts_by_id[1])
        host3 = self.net.get(self.topo.hosts_by_id[3])
        host6 = self.net.get(self.topo.hosts_by_id[6])
        host7 = self.net.get(self.topo.hosts_by_id[7])
        self.verify_stack_up()
        self.verify_tp_dst_notblocked(5000, host0, host1, table_id=None)
        self.verify_tp_dst_blocked(5000, host0, host3, table_id=None)
        self.verify_tp_dst_notblocked(5000, host0, host6, table_id=None)
        self.verify_tp_dst_blocked(5000, host0, host7, table_id=None)
        self.verify_no_cable_errors()

    def test_broadcast(self):
        """Hosts in stack topology can appropriately reach each other over broadcast."""
        host0 = self.net.get(self.topo.hosts_by_id[0])
        host1 = self.net.get(self.topo.hosts_by_id[1])
        host3 = self.net.get(self.topo.hosts_by_id[3])
        host6 = self.net.get(self.topo.hosts_by_id[6])
        host7 = self.net.get(self.topo.hosts_by_id[7])
        self.verify_stack_up()
        self.verify_bcast_dst_notblocked(5000, host0, host1)
        self.verify_bcast_dst_blocked(5000, host0, host3)
        self.verify_bcast_dst_notblocked(5000, host0, host6)
        self.verify_bcast_dst_blocked(5000, host0, host7)
        self.verify_no_cable_errors()


class FaucetSingleStackOrderedAclControlTest(FaucetMultiDPTest):
    """Test ACL control of stacked datapaths with untagged hosts."""

    NUM_DPS = 3
    NUM_HOSTS = 3

    def acls(self):
        """Configuration ACLs"""
        return {
            1: [
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'nw_dst': '10.1.0.2',
                    'actions': {
                        'output': [
                            {'port': self.host_port_maps[1][0][0]}  # Host 0
                        ]
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'dl_dst': 'ff:ff:ff:ff:ff:ff',
                    'actions': {
                        'output': [
                            {'ports': [
                                self.host_port_maps[1][0][0],  # Host 0
                                self.link_port_maps[(0, 1)][0]]}  # Link (0, 1)
                        ]
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'actions': {
                        'output': [
                            {'port': self.link_port_maps[(0, 1)][0]}  # Link (0, 1)
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
                            {'port': self.link_port_maps[(1, 2)][0]}  # Link (0, 2)
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
                            'port': self.host_port_maps[6][2][0]  # Host 6
                        }
                    },
                }},
                {'rule': {
                    'dl_type': IPV4_ETH,
                    'dl_dst': 'ff:ff:ff:ff:ff:ff',
                    'actions': {
                        'output': [
                            {'ports': [self.host_port_maps[6][2][0]]}  # Host 6
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

    def link_acls(self):
        """Host/link map to acls in"""
        return {
            0: [1],  # Host 0 dp 0 'acls_in': [1]
            (1, 0): [2],
            (2, 1): [3]
        }

    def setUp(self):  # pylint: disable=invalid-name
        """Setup network & create configuration file"""
        super(FaucetSingleStackOrderedAclControlTest, self).set_up(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
        )

    def test_unicast(self):
        """Hosts in stack topology can appropriately reach each other over unicast."""
        host0 = self.net.get(self.topo.hosts_by_id[0])
        host1 = self.net.get(self.topo.hosts_by_id[1])
        host3 = self.net.get(self.topo.hosts_by_id[3])
        host6 = self.net.get(self.topo.hosts_by_id[6])
        host7 = self.net.get(self.topo.hosts_by_id[7])
        self.verify_stack_up()
        self.verify_tp_dst_notblocked(5000, host0, host1, table_id=None)
        self.verify_tp_dst_blocked(5000, host0, host3, table_id=None)
        self.verify_tp_dst_notblocked(5000, host0, host6, table_id=None)
        self.verify_tp_dst_blocked(5000, host0, host7, table_id=None)
        self.verify_no_cable_errors()

    def test_broadcast(self):
        """Hosts in stack topology can appropriately reach each other over broadcast."""
        host0 = self.net.get(self.topo.hosts_by_id[0])
        host1 = self.net.get(self.topo.hosts_by_id[1])
        host3 = self.net.get(self.topo.hosts_by_id[3])
        host6 = self.net.get(self.topo.hosts_by_id[6])
        host7 = self.net.get(self.topo.hosts_by_id[7])
        self.verify_stack_up()
        self.verify_bcast_dst_notblocked(5000, host0, host1)
        self.verify_bcast_dst_blocked(5000, host0, host3)
        self.verify_bcast_dst_notblocked(5000, host0, host6)
        self.verify_bcast_dst_blocked(5000, host0, host7)
        self.verify_no_cable_errors()


class FaucetStringOfDPACLOverrideTest(FaucetMultiDPTest):
    """Test overriding ACL rules"""

    NUM_DPS = 2
    NUM_HOSTS = 2
    SOFTWARE_ONLY = True

    # ACL rules which will get overridden.
    def acls(self):
        """Return config ACLs"""
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
        """Return override ACLs option"""
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
    def link_acls(self):
        """Host/link port map to acls in"""
        return {
            0: [1]  # Host 0 'acls_in': [1]
        }

    def include_optional(self):
        if self.acls_config is None:
            self.acls_config = os.path.join(self.tmpdir, 'acls.yaml')
        if self.missing_config is None:
            self.missing_config = os.path.join(self.tmpdir, 'missing_config.yaml')
        return [self.acls_config, self.missing_config]

    def setUp(self):  # pylint: disable=invalid-name
        """Setup network & create configuration file"""
        self.acls_config = None
        self.missing_config = None
        super(FaucetStringOfDPACLOverrideTest, self).set_up(
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS)

    def test_port5001_blocked(self):
        """Test that TCP port 5001 is blocked."""
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.verify_tp_dst_notblocked(5001, first_host, second_host)
        with open(self.acls_config, 'w') as config_file:
            self.configuration_options['acl_options'] = self.acls_override()
            config_file.write(self.topo.get_config(n_vlans=1, **self.configuration_options))
        self.verify_faucet_reconf(cold_start=False, change_expected=True)
        self.verify_tp_dst_blocked(5001, first_host, second_host)

    def test_port5002_notblocked(self):
        """Test that TCP port 5002 is not blocked."""
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.verify_tp_dst_blocked(5002, first_host, second_host)
        with open(self.acls_config, 'w') as config_file:
            self.configuration_options['acl_options'] = self.acls_override()
            config_file.write(self.topo.get_config(n_vlans=1, **self.configuration_options))
        self.verify_faucet_reconf(cold_start=False, change_expected=True)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)


class FaucetTunnelSameDpTest(FaucetMultiDPTest):
    """Test the tunnel ACL option with output to the same DP"""

    NUM_DPS = 2
    NUM_HOSTS = 2
    SOFTWARE_ONLY = True
    SWITCH_TO_SWITCH_LINKS = 2

    def acls(self):
        """Return ACL config"""
        # Tunnel from host 0 (switch 0) to host 1 (switch 0)
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
                                'dp': self.topo.switches_by_id[0],  # Switch 0
                                'port': self.host_port_maps[1][0][0]}  # Switch 0 host 1
                        }
                    }
                }}
            ]
        }

    def link_acls(self):
        """DP to acl port mapping"""
        return {
            0: [1]  # Host 0 'acls_in': [1]
        }

    def test_tunnel_established(self):
        """Test a tunnel path can be created."""
        self.set_up(stack=True, n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS,
                    switch_to_switch_links=self.SWITCH_TO_SWITCH_LINKS)
        self.verify_stack_up()
        src_host = self.net.get(self.topo.hosts_by_id[0])
        dst_host = self.net.get(self.topo.hosts_by_id[1])
        other_host = self.net.get(self.topo.hosts_by_id[2])
        self.verify_tunnel_established(src_host, dst_host, other_host)


class FaucetSingleTunnelTest(FaucetMultiDPTest):
    """Test the Faucet tunnel ACL option both locally and remotely with link failure"""

    NUM_DPS = 2
    NUM_HOSTS = 2
    SOFTWARE_ONLY = True
    SWITCH_TO_SWITCH_LINKS = 2

    def acls(self):
        """Return config ACL options"""
        # Tunnel from host 0 (switch 0) to host 2 (switch 1)
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
                                'dp': self.topo.switches_by_id[1],
                                'port': self.host_port_maps[2][1][0]}
                        }
                    }
                }},
                {'rule': {
                    'dl_type': IPV6_ETH,
                    'ip_proto': 56,
                    'actions': {
                        'allow': 0,
                        'output': {
                            'tunnel': {
                                'type': 'vlan',
                                'tunnel_id': 200,
                                'dp': self.topo.switches_by_id[1],
                                'port': self.host_port_maps[2][1][0]}
                        }
                    }
                }},
            ]
        }

    def link_acls(self):
        """DP-to-acl port mapping"""
        return {
            0: [1],  # Host 0 'acls_in': [1]
            3: [1],  # Host 3 'acls_in': [1]
        }

    def output_only(self):
        return {2}   # Host 2 (first port, second switch).

    def setUp(self):  # pylint: disable=invalid-name
        """Start the network"""
        super(FaucetSingleTunnelTest, self).set_up(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            switch_to_switch_links=self.SWITCH_TO_SWITCH_LINKS)

    def verify_tunnels(self):
        """Test tunnel connectivity from local and remote switches."""
        other_host = self.net.get(self.topo.hosts_by_id[1])
        dst_host = self.net.get(self.topo.hosts_by_id[2])
        for src_host_id in (0, 3):
            src_host = self.net.get(self.topo.hosts_by_id[src_host_id])
            self.verify_tunnel_established(src_host, dst_host, other_host, packets=10)

    def test_tunnel_path_rerouted(self):
        """Test remote tunnel path is rerouted when a link is down."""
        self.verify_stack_up()
        self.verify_tunnels()
        first_stack_port = self.link_port_maps[(0, 1)][0]
        self.one_stack_port_down(self.dpids[0], self.topo.switches_by_id[0], first_stack_port)
        self.verify_tunnels()


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
            stack_ring=True)


class FaucetTunnelAllowTest(FaucetTopoTestBase):
    """Test Tunnels with ACLs containing allow=True"""

    NUM_DPS = 2
    NUM_HOSTS = 4
    NUM_VLANS = 2
    SOFTWARE_ONLY = True

    def acls(self):
        # Tunnel from host 0 (switch 0) to host 2 (switch 1)
        """Return config ACL options"""
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
                                'dp': self.topo.switches_by_id[1],
                                'port': self.host_port_maps[2][1][0]}
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



    def setUp(self):  # pylint: disable=invalid-name
        """Start the network"""
        super().setUp()
        network_graph = networkx.path_graph(self.NUM_DPS)
        dp_options = {}
        for dp_i in network_graph.nodes():
            dp_options.setdefault(dp_i, {
                'group_table': self.GROUP_TABLE,
                'ofchannel_log': self.debug_log_path + str(dp_i) if self.debug_log_path else None,
                'hardware': self.hardware if dp_i == 0 and self.hw_dpid else 'Open vSwitch'
            })
            if dp_i == 0:
                dp_options[0]['stack'] = {'priority': 1}
        switch_links = list(network_graph.edges())
        link_vlans = {edge: None for edge in switch_links}
        host_links = {0: [0], 1: [0], 2: [1], 3: [1]}
        host_vlans = {0: 0, 1: 0, 2: 1, 3: 0}
        host_options = {0: {'acls_in': [1]}}
        self.build_net(
            host_links=host_links,
            host_vlans=host_vlans,
            switch_links=switch_links,
            link_vlans=link_vlans,
            n_vlans=self.NUM_VLANS,
            dp_options=dp_options,
            host_options=host_options,
        )
        self.start_net()

    def test_tunnel_continue_through_pipeline_interaction(self):
        """Test packets that enter a tunnel with allow, also continue through the pipeline"""
        # Should be able to ping from h_{0,100} -> h_{1,100} & h_{3,100}
        #   and also have the packets arrive at h_{2,200} (the other end of the tunnel)
        self.verify_stack_up()
        # Ensure connection to the host on the other end of the tunnel can exist
        src_host = self.net.get(self.topo.hosts_by_id[0])  # h_{0,100}
        other_host = self.net.get(self.topo.hosts_by_id[1])  # h_{1,100}
        dst_host = self.net.get(self.topo.hosts_by_id[2])  # h_{2,200}
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
        # Tunnel from host 0 (switch 0) to host 1 (switch 0)
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
                                'dp': self.topo.switches_by_id[0],
                                'port': self.host_port_maps[1][0][0]}}
                        ]
                    }
                }}
            ]
        }

    def link_acls(self):
        """DP to acl port mapping"""
        return {
            0: [1]  # Host 0 'acls_in': [1]
        }

    def test_tunnel_established(self):
        """Test a tunnel path can be created."""
        self.set_up(stack=True, n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS,
                    switch_to_switch_links=self.SWITCH_TO_SWITCH_LINKS)
        self.verify_stack_up()
        src_host = self.net.get(self.topo.hosts_by_id[0])
        dst_host = self.net.get(self.topo.hosts_by_id[1])
        other_host = self.net.get(self.topo.hosts_by_id[2])
        self.verify_tunnel_established(src_host, dst_host, other_host)


class FaucetSingleTunnelOrderedTest(FaucetMultiDPTest):
    """Test the Faucet tunnel ACL option"""

    NUM_DPS = 2
    NUM_HOSTS = 2
    SOFTWARE_ONLY = True
    SWITCH_TO_SWITCH_LINKS = 2

    def acls(self):
        """Return config ACL options"""
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
                                'dp': self.topo.switches_by_id[1],
                                'port': self.host_port_maps[2][1][0]}}
                        ]
                    }
                }}
            ]
        }

    def link_acls(self):
        """DP link to list of acls to apply"""
        return {
            0: [1]  # Host 0 'acls_in': [1]
        }

    def setUp(self):  # pylint: disable=invalid-name
        """Start the network"""
        super(FaucetSingleTunnelOrderedTest, self).set_up(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            switch_to_switch_links=self.SWITCH_TO_SWITCH_LINKS)

    def test_tunnel_established(self):
        """Test a tunnel path can be created."""
        self.verify_stack_up()
        src_host = self.net.get(self.topo.hosts_by_id[0])
        dst_host = self.net.get(self.topo.hosts_by_id[2])
        other_host = self.net.get(self.topo.hosts_by_id[1])
        self.verify_tunnel_established(src_host, dst_host, other_host)

    def test_tunnel_path_rerouted(self):
        """Test a tunnel path is rerouted when a link is down."""
        self.verify_stack_up()
        src_host = self.net.get(self.topo.hosts_by_id[0])
        dst_host = self.net.get(self.topo.hosts_by_id[2])
        other_host = self.net.get(self.topo.hosts_by_id[1])
        self.verify_tunnel_established(src_host, dst_host, other_host, packets=10)
        first_stack_port = self.link_port_maps[(0, 1)][0]
        self.one_stack_port_down(self.dpids[0], self.topo.switches_by_id[0], first_stack_port)
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
            stack_ring=True)


class FaucetTunnelAllowOrderedTest(FaucetTopoTestBase):
    """Test Tunnels with ACLs containing allow=True"""

    NUM_DPS = 2
    NUM_HOSTS = 4
    NUM_VLANS = 2
    SOFTWARE_ONLY = True

    def acls(self):
        """Return config ACL options"""
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
                                'dp': self.topo.switches_by_id[1],
                                'port': self.host_port_maps[2][1][0]}}
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

    def setUp(self):  # pylint: disable=invalid-name
        """Start the network"""
        super().setUp()
        network_graph = networkx.path_graph(self.NUM_DPS)
        dp_options = {}
        for dp_i in network_graph.nodes():
            dp_options.setdefault(dp_i, {
                'group_table': self.GROUP_TABLE,
                'ofchannel_log': self.debug_log_path + str(dp_i) if self.debug_log_path else None,
                'hardware': self.hardware if dp_i == 0 and self.hw_dpid else 'Open vSwitch'
            })
            if dp_i == 0:
                dp_options[0]['stack'] = {'priority': 1}
        switch_links = list(network_graph.edges())
        link_vlans = {edge: None for edge in switch_links}
        host_links = {0: [0], 1: [0], 2: [1], 3: [1]}
        host_vlans = {0: 0, 1: 0, 2: 1, 3: 0}
        host_options = {0: {'acls_in': [1]}}
        self.build_net(
            host_links=host_links,
            host_vlans=host_vlans,
            switch_links=switch_links,
            link_vlans=link_vlans,
            n_vlans=self.NUM_VLANS,
            dp_options=dp_options,
            host_options=host_options,
        )
        self.start_net()

    def test_tunnel_continue_through_pipeline_interaction(self):
        """Test packets that enter a tunnel with allow, also continue through the pipeline"""
        # Should be able to ping from h_{0,100} -> h_{1,100} & h_{3,100}
        #   and also have the packets arrive at h_{2,200} (the other end of the tunnel)
        self.verify_stack_up()
        # Ensure connection to the host on the other end of the tunnel can exist
        src_host = self.net.get(self.topo.hosts_by_id[0])  # h_{0,100}
        other_host = self.net.get(self.topo.hosts_by_id[1])  # h_{1,100}
        dst_host = self.net.get(self.topo.hosts_by_id[2])  # h_{2,200}
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
    NUM_VLANS = 3
    SOFTWARE_ONLY = True


    def set_up(self, n_dps, host_links=None, host_vlans=None):
        """
        Args:
            n_dps: Number of DPs
            host_links: How to connect each host to the DPs
            host_vlans: The VLAN each host is on
        """
        network_graph = networkx.path_graph(n_dps)
        dp_options = {}
        for dp_i in network_graph.nodes():
            dp_options.setdefault(dp_i, {
                'group_table': self.GROUP_TABLE,
                'ofchannel_log': self.debug_log_path + str(dp_i) if self.debug_log_path else None,
                'hardware': self.hardware if dp_i == 0 and self.hw_dpid else 'Open vSwitch'
            })
            for key, value in self.dp_options().items():
                dp_options[dp_i][key] = value
            if dp_i == 0:
                dp_options[0]['stack'] = {'priority': 1}
        switch_links = list(network_graph.edges())
        link_vlans = {edge: None for edge in switch_links}
        routed_vlans = 2
        if host_links is None or host_vlans is None:
            host_links = {}
            host_vlans = {}
            host_n = 0
            for dp_i in range(n_dps):
                for vlan in range(routed_vlans):
                    host_links[host_n] = [dp_i]
                    host_vlans[host_n] = vlan
                    host_n += 1
        vlan_options = {}
        for v_i in range(routed_vlans):
            vlan_options[v_i] = {
                'faucet_mac': self.faucet_mac(v_i),
                'faucet_vips': [self.faucet_vip(v_i)],
                'targeted_gw_resolution': False
            }
        routers = {0: list(range(routed_vlans))}
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

    def dp_options(self):
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

    def dp_options(self):
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

    def set_up(self):
        """Start the network"""
        super().setUp()
        network_graph = networkx.path_graph(self.NUM_DPS)
        dp_options = {}
        for dp_i in network_graph.nodes():
            dp_options.setdefault(dp_i, {
                'group_table': self.GROUP_TABLE,
                'ofchannel_log': self.debug_log_path + str(dp_i) if self.debug_log_path else None,
                'hardware': self.hardware if dp_i == 0 and self.hw_dpid else 'Open vSwitch'
            })
            for key, value in self.dp_options().items():
                dp_options[dp_i][key] = value
            if dp_i == 0:
                dp_options[0]['stack'] = {'priority': 1}
        switch_links = list(network_graph.edges())
        link_vlans = {edge: None for edge in switch_links}
        host_links = {0: [0], 1: [1]}
        host_vlans = {0: 0, 1: 1}
        vlan_options = {}
        for v_i in range(self.NUM_VLANS):
            vlan_options[v_i] = {
                'faucet_mac': self.faucet_mac(v_i),
                'faucet_vips': [self.faucet_vip(v_i)],
                'targeted_gw_resolution': False
            }
        routers = {0: list(range(self.NUM_VLANS))}
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

    def dp_options(self):
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
        super().setUp()
        network_graph = networkx.path_graph(self.NUM_DPS)
        dp_options = {}
        for dp_i in network_graph.nodes():
            dp_options.setdefault(dp_i, {
                'group_table': self.GROUP_TABLE,
                'ofchannel_log': self.debug_log_path + str(dp_i) if self.debug_log_path else None,
                'hardware': self.hardware if dp_i == 0 and self.hw_dpid else 'Open vSwitch'
            })
            if dp_i == 0:
                dp_options[0]['stack'] = {'priority': 1}
        switch_links = list(network_graph.edges())
        link_vlans = {edge: None for edge in switch_links}
        host_links = {0: [0], 1: [2]}
        host_vlans = {0: 0, 1: 0}
        self.build_net(
            host_links=host_links,
            host_vlans=host_vlans,
            switch_links=switch_links,
            link_vlans=link_vlans,
            n_vlans=self.NUM_VLANS,
            dp_options=dp_options,
        )
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
        super().setUp()
        network_graph = networkx.path_graph(self.NUM_DPS)
        dp_options = {}
        for dp_i in network_graph.nodes():
            dp_options.setdefault(dp_i, {
                'group_table': self.GROUP_TABLE,
                'ofchannel_log': self.debug_log_path + str(dp_i) if self.debug_log_path else None,
                'hardware': self.hardware if dp_i == 0 and self.hw_dpid else 'Open vSwitch'
            })
            if dp_i == 0:
                dp_options[0]['stack'] = {'priority': 1}
        switch_links = list(network_graph.edges())
        link_vlans = {edge: None for edge in switch_links}
        host_links = {0: [0], 1: [1], 2: [2]}
        host_vlans = {0: 0, 1: 1, 2: 0}
        self.build_net(
            host_links=host_links,
            host_vlans=host_vlans,
            switch_links=switch_links,
            link_vlans=link_vlans,
            n_vlans=self.NUM_VLANS,
            dp_options=dp_options,
        )
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

    def dp_options(self):
        """Return DP config options"""
        return {
            'arp_neighbor_timeout': 2,
            'max_resolve_backoff_time': 2,
            'proactive_learn_v4': True,
            'lacp_timeout': 10
        }

    def setUp(self):
        """Disabling allows for each test case to start the test"""

    def set_up(self, lacp_host_links, host_vlans=None):
        """
        Args:
            lacp_host_links: List of dpid indices the LACP host will be connected to
            host_vlans: Default generate with one host on each VLAN, on each DP
                plus one LAG host the same VLAN as hosts
        """
        super().setUp()
        network_graph = networkx.path_graph(self.NUM_DPS)
        dp_options = {}
        for dp_i in network_graph.nodes():
            dp_options.setdefault(dp_i, {
                'group_table': self.GROUP_TABLE,
                'ofchannel_log': self.debug_log_path + str(dp_i) if self.debug_log_path else None,
                'hardware': self.hardware if dp_i == 0 and self.hw_dpid else 'Open vSwitch'
            })
            for key, value in self.dp_options().items():
                dp_options[dp_i][key] = value
            if dp_i == 0:
                dp_options[0]['stack'] = {'priority': 1}
        switch_links = list(network_graph.edges())
        link_vlans = {edge: None for edge in switch_links}
        host_links = {0: [0], 1: [0], self.LACP_HOST: lacp_host_links, 3: [1], 4: [1]}
        if host_vlans is None:
            host_vlans = {0: 0, 1: 1, 2: 1, 3: 0, 4: 1}
        vlan_options = {}
        for v_i in range(self.NUM_VLANS):
            vlan_options[v_i] = {
                'faucet_mac': self.faucet_mac(v_i),
                'faucet_vips': [self.faucet_vip(v_i)],
                'targeted_gw_resolution': False
            }
        routers = {0: list(range(self.NUM_VLANS))}
        host_options = {self.LACP_HOST: {'lacp': 1}}
        self.build_net(
            host_links=host_links,
            host_vlans=host_vlans,
            switch_links=switch_links,
            link_vlans=link_vlans,
            n_vlans=self.NUM_VLANS,
            dp_options=dp_options,
            vlan_options=vlan_options,
            routers=routers,
            host_options=host_options
        )
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

    def test_mclag_warmstart(self):
        """Test LACP MCLAG after a warm start"""
        lacp_host_links = [0, 0, 1, 1]
        self.set_up(lacp_host_links)

        # Perform initial test
        self.verify_stack_up()
        self.verify_lag_host_connectivity()

        # Take down single LAG port
        self.set_port_down(self.host_port_maps[self.LACP_HOST][0][0], self.dpids[0])
        self.verify_num_lag_up_ports(1, self.dpids[0])

        # Force warm start on switch by changing native VLAN of host1
        conf = self._get_faucet_conf()
        interfaces_conf = conf['dps'][self.topo.switches_by_id[0]]['interfaces']
        interfaces_conf[self.host_port_maps[1][0][0]]['native_vlan'] = self.topo.vlan_name(0)
        self.reload_conf(
            conf, self.faucet_config_path, restart=True,
            cold_start=False, change_expected=False)
        self.host_information.pop(1)

        # Set a single LAG port back UP
        self.set_port_up(self.host_port_maps[self.LACP_HOST][0][0], self.dpids[0])
        self.verify_num_lag_up_ports(2, self.dpids[0])

        # Verify connectivity
        self.verify_lag_host_connectivity()

    def test_mclag_portrestart(self):
        """Test LACP MCLAG after a port gets restarted"""
        lacp_host_links = [0, 0, 1, 1]
        self.set_up(lacp_host_links)

        # Perform initial test
        self.verify_stack_up()
        self.verify_lag_host_connectivity()

        # Set LAG port down
        self.set_port_down(self.host_port_maps[self.LACP_HOST][0][0], self.dpids[0])
        self.verify_num_lag_up_ports(1, self.dpids[0])

        # Set LAG port back up
        self.set_port_up(self.host_port_maps[self.LACP_HOST][0][0], self.dpids[0])
        self.verify_num_lag_up_ports(2, self.dpids[0])

        # Verify connectivity
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

    def dp_options(self):
        """Return config DP options"""
        return {
            'arp_neighbor_timeout': 2,
            'max_resolve_backoff_time': 2,
            'proactive_learn_v4': True,
            'lacp_timeout': 10
        }

    def setUp(self):
        """Ignore to allow for setting up network in each test"""

    def set_up(self):
        """Set up network"""
        super().setUp()
        network_graph = networkx.path_graph(self.NUM_DPS)
        dp_options = {}
        for dp_i in network_graph.nodes():
            dp_options.setdefault(dp_i, {
                'group_table': self.GROUP_TABLE,
                'ofchannel_log': self.debug_log_path + str(dp_i) if self.debug_log_path else None,
                'hardware': self.hardware if dp_i == 0 and self.hw_dpid else 'Open vSwitch'
            })
            for key, value in self.dp_options().items():
                dp_options[dp_i][key] = value
            if dp_i == 0:
                dp_options[0]['stack'] = {'priority': 1}
        switch_links = list(network_graph.edges())
        link_vlans = {edge: None for edge in switch_links}
        host_links = {0: [0], 1: [1], 2: [2], 3: [0, 0, 2, 2]}
        host_vlans = {host_id: 0 for host_id in range(self.NUM_HOSTS)}
        host_options = {self.LACP_HOST: {'lacp': 1}}
        self.build_net(
            host_links=host_links,
            host_vlans=host_vlans,
            switch_links=switch_links,
            link_vlans=link_vlans,
            n_vlans=self.NUM_VLANS,
            dp_options=dp_options,
            host_options=host_options
        )
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
        lacp_switches = {
            self.net.get(self.topo.switches_by_id[i])
            for i in self.host_port_maps[self.LACP_HOST]}
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
        lacp_ports = self.host_port_maps[self.LACP_HOST][0]
        for port in lacp_ports:
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
        lacp_switches = {
            self.net.get(self.topo.switches_by_id[i])
            for i in self.host_port_maps[self.LACP_HOST]}
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
                    node_count = len(graph.get('nodes'))
                    self.assertEqual(node_count, 3,
                                     'Number of nodes in graph object is %s (!=3)' % node_count)
        self.assertTrue(stack_event_found)


class FaucetStackWarmStartTest(FaucetTopoTestBase):
    """Test various stack warm starting conditions to ensure stack port stays UP"""

    NUM_DPS = 3
    NUM_HOSTS = 1
    NUM_VLANS = 2
    SOFTWARE_ONLY = True

    def setUp(self):
        """Ignore to allow for setting up network in each test"""

    def set_up(self, host_links=None, host_vlans=None, switch_to_switch_links=1):
        """
        Args:
            host_links (dict): Host index map to list of DPs it is connected to
            host_vlans (dict): Host index map to list of vlans it belongs to
        """
        super().setUp()
        network_graph = networkx.path_graph(self.NUM_DPS)
        dp_options = {}
        for dp_i in network_graph.nodes():
            dp_options.setdefault(dp_i, {
                'group_table': self.GROUP_TABLE,
                'ofchannel_log': self.debug_log_path + str(dp_i) if self.debug_log_path else None,
                'hardware': self.hardware if dp_i == 0 and self.hw_dpid else 'Open vSwitch'
            })
            if dp_i == 0:
                dp_options[0]['stack'] = {'priority': 1}
        switch_links = list(network_graph.edges()) * switch_to_switch_links
        link_vlans = {edge: None for edge in switch_links}
        if host_links is None:
            host_links = {0: [0], 1: [1], 2: [2]}
        if host_vlans is None:
            host_vlans = {h_i: 0 for h_i in host_links.keys()}
        self.build_net(
            host_links=host_links,
            host_vlans=host_vlans,
            switch_links=switch_links,
            link_vlans=link_vlans,
            n_vlans=self.NUM_VLANS,
            dp_options=dp_options,
        )
        self.start_net()

    def test_native_vlan(self):
        """Test warm starting changing host native VLAN"""
        host_vlans = {0: 0, 1: 0, 2: 1}
        self.set_up(host_vlans=host_vlans)
        self.verify_stack_up()
        self.verify_intervlan_routing()
        conf = self._get_faucet_conf()
        interfaces_conf = conf['dps'][self.topo.switches_by_id[2]]['interfaces']
        interfaces_conf[self.host_port_maps[2][2][0]]['native_vlan'] = self.topo.vlan_name(0)
        self.reload_conf(
            conf, self.faucet_config_path, restart=True,
            cold_start=False, change_expected=True, dpid=self.topo.dpids_by_id[2])
        self.verify_stack_up(timeout=1)
        self.verify_intervlan_routing()

    def test_vlan_change(self):
        """Test warm starting changing a VLAN option"""
        host_vlans = {0: 0, 1: 0, 2: 1}
        self.set_up(host_vlans=host_vlans)
        self.verify_stack_up()
        self.verify_intervlan_routing()
        conf = self._get_faucet_conf()
        conf['vlans'][self.topo.vlan_name(0)]['edge_learn_stack_root'] = False
        self.reload_conf(
            conf, self.faucet_config_path, restart=True,
            cold_start=False, change_expected=True)
        self.verify_stack_up(timeout=1)
        self.verify_intervlan_routing()

    def test_transit_vlan_change(self):
        """Test warm starting changing host native VLAN with a transit stack switch"""
        import ipaddress
        host_links = {0: [0], 1: [0], 2: [2], 3: [2]}
        host_vlans = {0: 0, 1: 0, 2: 0, 3: 1}
        self.set_up(host_links=host_links, host_vlans=host_vlans)
        self.verify_stack_up()
        self.verify_intervlan_routing()
        conf = self._get_faucet_conf()
        interfaces_conf = conf['dps'][self.topo.switches_by_id[0]]['interfaces']
        interfaces_conf[self.host_port_maps[0][0][0]]['native_vlan'] = self.topo.vlan_name(1)
        self.host_information[0]['vlan'] = 1
        self.reload_conf(
            conf, self.faucet_config_path, restart=True,
            cold_start=False, change_expected=True, dpid=self.topo.dpids_by_id[0])
        self.verify_stack_up(timeout=1)
        ip_intf = ipaddress.ip_interface(self.host_ip_address(0, 1))
        self.host_information[0]['ip'] = ip_intf
        self.set_host_ip(self.host_information[0]['host'], ip_intf)
        self.verify_intervlan_routing()

    def test_del_seconday_stack_port(self):
        """Test deleting stack port"""
        self.set_up(switch_to_switch_links=2)
        self.verify_stack_up()
        self.verify_intervlan_routing()
        conf = self._get_faucet_conf()
        del conf['dps'][self.topo.switches_by_id[1]]['interfaces'][self.link_port_maps[(1, 2)][0]]
        del conf['dps'][self.topo.switches_by_id[2]]['interfaces'][self.link_port_maps[(2, 1)][0]]
        self.reload_conf(
            conf, self.faucet_config_path, restart=True,
            cold_start=False, change_expected=True, dpid=self.topo.dpids_by_id[0])
        # Due to flood table size changes, some DPs will be cold starting
        self.verify_stack_up(timeout=1, prop=0.5)
        self.verify_intervlan_routing()

    def test_del_primary_stack_port(self):
        """Test deleting lowest/primary stack port"""
        self.set_up(switch_to_switch_links=2)
        self.verify_stack_up()
        self.verify_intervlan_routing()
        conf = self._get_faucet_conf()
        del conf['dps'][self.topo.switches_by_id[1]]['interfaces'][self.link_port_maps[(1, 2)][1]]
        del conf['dps'][self.topo.switches_by_id[2]]['interfaces'][self.link_port_maps[(2, 1)][1]]
        self.reload_conf(
            conf, self.faucet_config_path, restart=True,
            cold_start=False, change_expected=True, dpid=self.topo.dpids_by_id[0])
        # Due to flood table size changes, some DPs will be cold starting
        self.verify_stack_up(timeout=1, prop=0.5)
        self.verify_intervlan_routing()

    def test_del_host(self):
        """Test removing a port/host from Faucet"""
        host_links = {0: [0], 1: [0], 2: [1], 3: [2]}
        self.set_up(host_links=host_links)
        self.verify_stack_up()
        self.verify_intervlan_routing()
        conf = self._get_faucet_conf()
        interfaces_conf = conf['dps'][self.topo.switches_by_id[0]]['interfaces']
        del interfaces_conf[self.host_port_maps[0][0][0]]
        self.reload_conf(
            conf, self.faucet_config_path, restart=True,
            cold_start=True, change_expected=True, dpid=self.topo.dpids_by_id[0])
        self.verify_stack_up()
        del self.host_information[0]
        self.verify_intervlan_routing()

    def test_root_add_stack_link(self):
        """Add a redundant stack link between two switches (one a root)"""
        host_links = {0: [0], 1: [0], 2: [1], 3: [1], 4: [2], 5: [2]}
        self.set_up(host_links=host_links)
        self.verify_stack_up()
        self.verify_intervlan_routing()
        conf = self._get_faucet_conf()
        # Create an additional link between S1-S2
        port_num = self.topo._create_next_port(self.topo.switches_by_id[0])
        rev_port_num = self.topo._create_next_port(self.topo.switches_by_id[1])
        interfaces_conf = conf['dps'][self.topo.switches_by_id[0]]['interfaces']
        interfaces_conf[port_num] = {
            'name': 'b%u' % port_num,
            'stack': {'dp': self.topo.switches_by_id[1], 'port': rev_port_num}}
        interfaces_conf = conf['dps'][self.topo.switches_by_id[1]]['interfaces']
        interfaces_conf[rev_port_num] = {
            'name': 'b%u' % rev_port_num,
            'stack': {'dp': self.topo.switches_by_id[0], 'port': port_num}}
        self.reload_conf(
            conf, self.faucet_config_path, restart=True,
            cold_start=False, change_expected=True, dpid=self.topo.dpids_by_id[2])
        self.verify_stack_up()
        self.verify_intervlan_routing()

    def test_add_stack_link(self):
        """Add a redundant stack link between two non-root switches"""
        host_links = {0: [0], 1: [0], 2: [1], 3: [1], 4: [2], 5: [2]}
        self.set_up(host_links=host_links)
        self.verify_stack_up()
        self.verify_intervlan_routing()
        conf = self._get_faucet_conf()
        # Create an additional link between S1-S2
        port_num = self.topo._create_next_port(self.topo.switches_by_id[1])
        rev_port_num = self.topo._create_next_port(self.topo.switches_by_id[2])
        interfaces_conf = conf['dps'][self.topo.switches_by_id[1]]['interfaces']
        interfaces_conf[port_num] = {
            'name': 'b%u' % port_num,
            'stack': {'dp': self.topo.switches_by_id[2], 'port': rev_port_num}}
        interfaces_conf = conf['dps'][self.topo.switches_by_id[2]]['interfaces']
        interfaces_conf[rev_port_num] = {
            'name': 'b%u' % rev_port_num,
            'stack': {'dp': self.topo.switches_by_id[1], 'port': port_num}}
        self.reload_conf(
            conf, self.faucet_config_path, restart=True,
            cold_start=False, change_expected=True, dpid=self.topo.dpids_by_id[0])
        self.verify_stack_up()
        self.verify_intervlan_routing()

    def test_add_stack_link_transit(self):
        """Add a redundant stack link between two non-root switches (with a transit switch)"""
        host_links = {0: [0], 1: [0], 4: [2], 5: [2]}
        self.set_up(host_links=host_links)
        self.verify_stack_up()
        self.verify_intervlan_routing()
        conf = self._get_faucet_conf()
        # Create an additional link between S1-S2
        port_num = self.topo._create_next_port(self.topo.switches_by_id[1])
        rev_port_num = self.topo._create_next_port(self.topo.switches_by_id[2])
        interfaces_conf = conf['dps'][self.topo.switches_by_id[1]]['interfaces']
        interfaces_conf[port_num] = {
            'name': 'b%u' % port_num,
            'stack': {'dp': self.topo.switches_by_id[2], 'port': rev_port_num}}
        interfaces_conf = conf['dps'][self.topo.switches_by_id[2]]['interfaces']
        interfaces_conf[rev_port_num] = {
            'name': 'b%u' % rev_port_num,
            'stack': {'dp': self.topo.switches_by_id[1], 'port': port_num}}
        # Expected cold start as topology changed with all ports being stack ports
        self.reload_conf(
            conf, self.faucet_config_path, restart=True,
            cold_start=False, change_expected=True, dpid=self.topo.dpids_by_id[0])
        self.verify_stack_up()
        self.verify_intervlan_routing()
