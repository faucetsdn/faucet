#!/usr/bin/env python3

import os
import random
import re
import time
import ipaddress
import pprint
from functools import partial
import yaml  # pytype: disable=pyi-error

from clib.mininet_test_util import timeout_cmd
from clib.mininet_test_base import FaucetTestBase, IPV4_ETH
from clib.mininet_test_topo_generator import FaucetTopoGenerator


class FaucetTopoTestBase(FaucetTestBase):
    """
    Extension to the base test for the integration test suite to help set up arbitrary topologies
    This is supposed to be called with clib.mininet_topo_generator to take networkx graph
        generators and produce a set of switch-switch links and host-switch links
    """

    NETPREFIX = 24
    IPV = 4
    GROUP_TABLE = False

    NUM_DPS = 2
    NUM_HOSTS = 4
    LINKS_PER_HOST = 1

    LACP_TIMEOUT = 10

    dpids = None
    port_maps = None
    n_vlans = 0
    dp_links = None
    host_links = None
    host_vlans = None
    stack_roots = None
    routers = None
    dp_options = None
    host_options = None
    vlan_options = None
    host_information = None
    faucet_vips = None

    def non_host_links(self, dpid):
        """Return dpid peer links from topo"""
        return self.topo.dpid_peer_links(dpid)

    @staticmethod
    def get_config_header(_config_global, _debug_log, _dpid, _hardware):
        """Don't generate standard config file header."""
        return ''

    @staticmethod
    def acls():
        """Dictionary of ACLs"""
        return {}

    @staticmethod
    def acl_in_dp():
        """Dictionary of DP & port map to ACL"""
        return {}

    @staticmethod
    def dp_name(i):
        """DP config name"""
        return 'faucet-%u' % (i + 1)

    def faucet_vip(self, i):
        """Faucet VLAN VIP"""
        return '10.%u.0.254/%u' % (i+1, self.NETPREFIX)

    @staticmethod
    def faucet_mac(i):
        """Faucet VLAN MAC"""
        return '00:00:00:00:00:%u%u' % (i+1, i+1)

    def host_ip_address(self, host_index, vlan_index):
        """Create a string of the host IP address"""
        if isinstance(vlan_index, tuple):
            vlan_index = vlan_index[0]
        return '10.%u.0.%u/%u' % (vlan_index+1, host_index+1, self.NETPREFIX)

    @staticmethod
    def vlan_name(i):
        """VLAN name"""
        return 'vlan-%i' % (i+1)

    @staticmethod
    def vlan_vid(i):
        """VLAN VID value"""
        return (i+1) * 100

    def host_ping(self, src_host, dst_ip, intf=None):
        """Default method to ping from one host to an IP address"""
        self.one_ipv4_ping(
            src_host, dst_ip, require_host_learned=False, retries=5, timeout=1000, intf=intf)

    def set_host_ip(self, host, host_ip):
        """Default method for setting a hosts IP address"""
        host.setIP(str(host_ip.ip), prefixLen=self.NETPREFIX)

    def build_net(self, n_dps=1, n_vlans=1,
                  dp_links=None, host_links=None, host_vlans=None,
                  vlan_options=None, dp_options=None, host_options=None,
                  routers=None, stack_roots=None,
                  include=None, include_optional=None,
                  hw_dpid=None, lacp_trunk=False):
        """
        Use the TopologyGenerator to generate the YAML configuration and create the network
        Args:
            n_dps: Number of DPs
            n_vlans: Number of VLANs
            dp_links (dict): dp index to dp index
            host_links (dict): host index to list of dp index
            host_vlans (dict): host index to vlan index
            vlan_options (dict): vlan_index to key, value dp options
            dp_options (dict): dp index to key, value dp options
            host_options (dict): Host index to host option key, values
            routers (dict): router index to list of vlan index
            stack_roots (dict): dp index to priority value (leave none for tagged links)
            include:
            include_optional:
            hw_dpid: DPID of hardware switch
            lacp_trunk: Use LACP trunk ports
        """
        if include is None:
            include = []
        if include_optional is None:
            include_optional = []
        self.NUM_DPS = n_dps
        self.dpids = [str(self.rand_dpid()) for _ in range(n_dps)]
        self.dpids[0] = self.dpid
        vlan_vids = {vlan: self.vlan_vid(vlan) for vlan in range(n_vlans)}
        self.topo = FaucetTopoGenerator(
            self.OVS_TYPE,
            self.ports_sock,
            self._test_name(),
            self.dpids,
            dp_links,
            host_links,
            host_vlans,
            vlan_vids,
            hw_dpid=self.hw_dpid,
            switch_map=self.switch_map,
            port_order=self.port_order,
            start_port=self.start_port
        )
        self.port_maps = {dpid: self.create_port_map(dpid) for dpid in self.dpids}
        self.port_map = self.port_maps[self.dpid]
        self.CONFIG = self.get_config(
            dpids=self.dpids,
            hw_dpid=hw_dpid,
            hardware=self.hardware,
            ofchannel_log=self.debug_log_path,
            n_vlans=n_vlans,
            host_links=host_links,
            host_vlans=host_vlans,
            stack_roots=stack_roots,
            include=include,
            include_optional=include_optional,
            acls=self.acls(),
            acl_in_dp=self.acl_in_dp(),
            lacp_trunk=lacp_trunk,
            vlan_options=vlan_options,
            dp_options=dp_options,
            routers=routers,
            host_options=host_options
        )
        self.n_vlans = n_vlans
        self.dp_links = dp_links
        self.host_links = host_links
        self.host_vlans = host_vlans
        self.stack_roots = stack_roots
        self.routers = routers
        self.dp_options = dp_options
        self.host_options = host_options
        self.vlan_options = vlan_options

    def start_net(self):
        """
        Override start_net to create the faucet vips, the host information and set up the
            host routes for routed hosts
        """
        super(FaucetTopoTestBase, self).start_net()
        # Create a dictionary of host information that might be used in a test later on.
        # This makes it easier to retrieve certain information and consolidates it into one
        #   location.
        self.host_information = {}
        for host_id, host_name in self.topo.hosts_by_id.items():
            host_obj = self.net.get(host_name)
            vlan = self.host_vlans[host_id]
            ip_interface = ipaddress.ip_interface(self.host_ip_address(host_id, vlan))
            self.set_host_ip(host_obj, ip_interface)
            self.host_information[host_id] = {
                'host': host_obj,
                'ip': ip_interface,
                'mac': host_obj.MAC(),
                'vlan': vlan,
                'bond': None,
                'ports': {}
            }
        # Add information of hosts chosen dpid, port map values
        # TODO: This redoes logic from get_config()
        for i, dpid in enumerate(self.dpids):
            index = 1
            for host_id, links in self.host_links.items():
                if i in links:
                    n_links = links.count(i)
                    for _ in range(n_links):
                        port = self.port_maps[dpid]['port_%d' % index]
                        self.host_information[host_id]['ports'].setdefault(dpid, [])
                        self.host_information[host_id]['ports'][dpid].append(port)
                        index += 1
        # Store faucet vip interfaces
        self.faucet_vips = {}
        for vlan in range(self.n_vlans):
            self.faucet_vips[vlan] = ipaddress.ip_interface(self.faucet_vip(vlan))
        # Setup the linux bonds for LACP connected hosts
        self.setup_lacp_bonds()
        # Add host routes to hosts for inter vlan routing
        self.setup_intervlan_host_routes()

    def setup_lacp_bonds(self):
        """Search through host options for lacp hosts and configure accordingly"""
        if not self.host_options:
            return
        bond_index = 1
        for host_id, options in self.host_options.items():
            if 'lacp' in options:
                host = self.host_information[host_id]['host']
                # LACP must be configured with host ports down
                for dpid, ports in self.host_information[host_id]['ports'].items():
                    for port in ports:
                        self.set_port_down(port, dpid)
                orig_ip = host.IP()
                lacp_switches = [self.net.switches[i] for i in self.host_links[host_id]]
                bond_members = [
                    pair[0].name for switch in lacp_switches for pair in host.connectionsTo(switch)]
                bond_name = 'bond%u' % (bond_index)
                self.host_information[host_id]['bond'] = bond_name
                for bond_member in bond_members:
                    # Deconfigure bond members
                    self.quiet_commands(host, (
                        'ip link set %s down' % bond_member,
                        'ip address flush dev %s' % bond_member))
                # Configure bond interface
                self.quiet_commands(host, (
                    ('ip link add %s address 0e:00:00:00:00:99 '
                        'type bond mode 802.3ad lacp_rate fast miimon 100 '
                        'xmit_hash_policy layer2+3') % (bond_name),
                    'ip add add %s/%s dev %s' % (orig_ip, self.NETPREFIX, bond_name),
                    'ip link set %s up' % bond_name))
                # Add bond members
                for bond_member in bond_members:
                    self.quiet_commands(host, (
                        'ip link set dev %s master %s' % (bond_member, bond_name),))
                bond_index += 1
                # Return the ports to UP
                for dpid, ports in self.host_information[host_id]['ports'].items():
                    for port in ports:
                        self.set_port_up(port, dpid)

    def setup_intervlan_host_routes(self):
        """Configure host routes between hosts that belong on routed VLANs"""
        if self.routers:
            for src in self.host_information:
                src_host = self.host_information[src]['host']
                src_vlan = self.host_information[src]['vlan']
                src_ip = self.host_information[src]['ip']
                for dst in self.host_information:
                    if src != dst:
                        dst_host = self.host_information[dst]['host']
                        dst_vlan = self.host_information[dst]['vlan']
                        dst_ip = self.host_information[dst]['ip']
                        if src_vlan != dst_vlan and self.is_routed_vlans(src_vlan, dst_vlan):
                            src_faucet_vip = self.faucet_vips[src_vlan]
                            dst_faucet_vip = self.faucet_vips[dst_vlan]
                            self.add_host_route(src_host, dst_ip, src_faucet_vip.ip)
                            self.add_host_route(dst_host, src_ip, dst_faucet_vip.ip)

    def get_config(self, dpids=None, hw_dpid=None, hardware=None, ofchannel_log=None,
                   n_vlans=1, host_links=None, host_vlans=None, stack_roots=None,
                   include=None, include_optional=None, acls=None, acl_in_dp=None,
                   lacp_trunk=False, vlan_options=None, dp_options=None,
                   routers=None, host_options=None):
        """
        Args:
            dpids: List of DPIDs the dp indices in the configuration dictionaries refer to
            hw_dpid: DPID for connected hardware switch
            hardware:
            ofchannel_log: Debug log path
            n_vlans: Number of VLANs
            host_links (dict): host index to dp index
            host_vlans (dict): host index to vlan index
            stack_roots (dict): dp index to priority value (leave none for tagged links)
            include:
            include_optional:
            hw_dpid: DPID of hardware switch
            lacp_trunk: Use LACP trunk ports
            vlan_options (dict): vlan_index to key, value dp options
            dp_options (dict): dp index to key, value dp options
            routers (dict): router index to list of vlan index
            host_options (dict): Host index to host option key, values
        """
        if dpids is None:
            dpids = []
        if include is None:
            include = []
        if include_optional is None:
            include_optional = []
        if acls is None:
            acls = {}
        if acl_in_dp is None:
            acl_in_dp = {}

        def add_vlans(n_vlans, host_vlans, vlan_options):
            vlans_config = {}
            for vlan in range(n_vlans):
                n_tagged = 0
                n_untagged = 0
                for vlans in host_vlans.values():
                    if isinstance(vlans, int) and vlan == vlans:
                        n_untagged += 1
                    elif isinstance(vlans, tuple) and vlan in vlans:
                        n_tagged += 1
                vlans_config[self.vlan_name(vlan)] = {
                    'description': '%s tagged, %s untagged' % (n_tagged, n_untagged),
                    'vid': self.vlan_vid(vlan)
                }
            if vlan_options:
                for vlan, options in vlan_options.items():
                    for key, value in options.items():
                        vlans_config[self.vlan_name(vlan)][key] = value
            return vlans_config

        def add_routers(routers):
            router_config = {}
            for i, vlans in routers.items():
                router_config['router-%s' % i] = {
                    'vlans': [self.vlan_name(vlan) for vlan in vlans]
                }
            return router_config

        def add_acl_to_port(i, port, interfaces_config):
            if i in acl_in_dp and port in acl_in_dp[i]:
                interfaces_config[port]['acl_in'] = acl_in_dp[i][port]

        def add_dp(i, dpid, hw_dpid, ofchannel_log, group_table,
                   n_vlans, host_vlans, stack_roots, host_links, dpid_peer_links, port_maps):
            dp_config = {
                'dp_id': int(dpid),
                'hardware': hardware if dpid == hw_dpid else 'Open vSwitch',
                'ofchannel_log': ofchannel_log + str(i) if ofchannel_log else None,
                'interfaces': {},
                'group_table': group_table,
            }

            if dp_options and i in dp_options:
                for key, value in dp_options[i].items():
                    dp_config[key] = value

            if stack_roots and i in stack_roots:
                dp_config['stack'] = {}
                dp_config['stack']['priority'] = stack_roots[i]  # pytype: disable=unsupported-operands

            interfaces_config = {}
            # Generate host links
            index = 1
            for host_id, links in host_links.items():
                if i in links:
                    n_links = links.count(i)
                    vlan = host_vlans[host_id]
                    if isinstance(vlan, int):
                        key = 'native_vlan'
                        value = self.vlan_name(vlan)
                    else:
                        key = 'tagged_vlans'
                        value = [self.vlan_name(vlan) for vlan in vlan]
                    for _ in range(n_links):
                        port = port_maps[dpid]['port_%d' % index]
                        interfaces_config[port] = {
                            key: value
                        }
                        if host_options and host_id in host_options:
                            for option_key, option_value in host_options[host_id].items():
                                interfaces_config[port][option_key] = option_value
                        index += 1
                        add_acl_to_port(i, port, interfaces_config)

            # Generate switch-switch links
            for link in dpid_peer_links:
                port, peer_dpid, peer_port = link.port, link.peer_dpid, link.peer_port
                interfaces_config[port] = {}
                if stack_roots:
                    interfaces_config[port].update({
                        'stack': {
                            'dp': self.dp_name(dpids.index(peer_dpid)),
                            'port': peer_port
                        }})
                else:
                    tagged_vlans = [self.vlan_name(vlan) for vlan in range(n_vlans)]
                    interfaces_config[port].update({'tagged_vlans': tagged_vlans})
                    if lacp_trunk:
                        interfaces_config[port].update({
                            'lacp': 1,
                            'lacp_active': True
                        })
                        dp_config['lacp_timeout'] = 10
                add_acl_to_port(i, port, interfaces_config)

            dp_config['interfaces'] = interfaces_config
            return dp_config

        config = {'version': 2}
        if include:
            config['include'] = list(include)
        if include_optional:
            config['include_optional'] = list(include_optional)
        config['acls'] = acls.copy()
        config['vlans'] = add_vlans(n_vlans, host_vlans, vlan_options)

        if routers:
            config['routers'] = add_routers(routers)

        dpid_names = {dpids[i]: self.dp_name(i) for i in range(len(dpids))}
        self.set_dpid_names(dpid_names)
        config['dps'] = {}
        for i, dpid in enumerate(dpids):
            config['dps'][self.dp_name(i)] = add_dp(
                i, dpid, hw_dpid, ofchannel_log, self.GROUP_TABLE, n_vlans, host_vlans,
                stack_roots, host_links, self.topo.dpid_peer_links(dpid), self.port_maps)

        return yaml.dump(config, default_flow_style=False)

    def debug(self):
        """Print host information when debugging"""
        try:
            super(FaucetTopoTestBase, self).debug()
        except Exception:
            pprint.pprint(self.host_information)
            raise

    def verify_no_cable_errors(self):
        """Check that prometheus does not detect any stack cabling errors on all DPs"""
        i = 0
        for dpid in self.dpids:
            i += 1
            labels = {'dp_id': '0x%x' % int(dpid), 'dp_name': 'faucet-%u' % i}
            self.assertEqual(
                0, self.scrape_prometheus_var(
                    var='stack_cabling_errors_total', labels=labels, default=None))
            self.assertGreater(
                self.scrape_prometheus_var(
                    var='stack_probes_received_total', labels=labels), 0)

    def verify_stack_hosts(self, verify_bridge_local_rule=True, retries=3):
        """Verify hosts with stack LLDP messages"""
        lldp_cap_files = []
        for host in self.hosts_name_ordered():
            lldp_cap_file = os.path.join(self.tmpdir, '%s-lldp.cap' % host)
            lldp_cap_files.append(lldp_cap_file)
            host.cmd(timeout_cmd(
                'tcpdump -U -n -c 1 -i %s -w %s ether proto 0x88CC and not ether src %s &' % (
                    host.defaultIntf(), host.MAC(), lldp_cap_file), 60))
        # should not flood LLDP from hosts
        self.verify_lldp_blocked(self.hosts_name_ordered())
        # hosts should see no LLDP probes
        self.verify_empty_caps(lldp_cap_files)
        if verify_bridge_local_rule:
            # Verify 802.1x flood block triggered.
            for dpid in self.dpids:
                self.wait_nonzero_packet_count_flow(
                    {'dl_dst': '01:80:c2:00:00:00/ff:ff:ff:ff:ff:f0'},
                    dpid=dpid, table_id=self._FLOOD_TABLE, ofa_match=False)
        self.retry_net_ping(retries=retries)

    def stack_port_status(self, dpid, dp_name, port_no):
        """Return the status of a stack port from prometheus"""
        labels = self.port_labels(port_no)
        labels.update({'dp_id': '0x%x' % int(dpid), 'dp_name': dp_name})
        return self.scrape_prometheus_var(
            'port_stack_state', labels=labels,
            default=None, dpid=dpid)

    def wait_for_stack_port_status(self, dpid, dp_name, port_no, status, timeout=25):
        """Wait until prometheus detects a stack port has a certain status"""
        labels = self.port_labels(port_no)
        labels.update({'dp_id': '0x%x' % int(dpid), 'dp_name': dp_name})
        if not self.wait_for_prometheus_var(
                'port_stack_state', status, labels=labels,
                default=None, dpid=False, timeout=timeout):
            self.fail('did not get expected dpid %x port %u port_stack_state %u' % (
                int(dpid), port_no, status))

    def one_stack_port_down(self, dpid, dp_name, port):
        """Set a stack port down and wait for prometheus to detect the change"""
        self.set_port_down(port, dpid, wait=False)
        self.wait_for_stack_port_status(dpid, dp_name, port, 4)

    def one_stack_port_up(self, dpid, dp_name, port):
        """Set a stack port up and wait for prometheus to detect the change"""
        self.set_port_up(port, dpid, wait=False)
        self.wait_for_stack_port_status(dpid, dp_name, port, 3)

    def verify_stack_up(self, prop=1.0, timeout=25):
        """Verify all stack ports are up"""
        for _ in range(timeout):
            links = 0
            links_up = 0
            for i, dpid in enumerate(self.dpids):
                dp_name = self.dp_name(i)
                for link in self.non_host_links(dpid):
                    status = self.stack_port_status(dpid, dp_name, link.port)
                    links += 1
                    if status == 3:  # up
                        links_up += 1
            prop_up = links_up / links
            if prop_up >= prop:
                return
            time.sleep(1)
        self.fail('not enough links up: %f / %f' % (links_up, links))

    def verify_one_stack_down(self, stack_offset_port, coldstart=False):
        """Test conditions when one stack port is down"""
        self.retry_net_ping()
        stack_port = self.non_host_links(self.dpid)[stack_offset_port].port
        remote_stack_port = self.non_host_links(self.dpid)[stack_offset_port].peer_port
        self.set_port_down(stack_port, wait=False)
        # self.dpids[1] is the intermediate switch.
        self.set_port_down(remote_stack_port, self.dpids[1], wait=False)
        # test case where one link is down when coldstarted.
        if coldstart:
            self.coldstart_conf()
        self.verify_stack_up(prop=0.75)
        self.verify_stack_hosts(verify_bridge_local_rule=False)
        # Broadcast works, and first switch doesn't see broadcast packet ins from stack.
        packet_in_before_broadcast = self.scrape_prometheus_var('of_vlan_packet_ins')
        self.verify_broadcast()
        packet_in_after_broadcast = self.scrape_prometheus_var('of_vlan_packet_ins')
        self.assertEqual(
            packet_in_before_broadcast,
            packet_in_after_broadcast)
        self.verify_no_cable_errors()

    def verify_no_arp_storm(self, ping_host, tcpdump_host):
        """Check that there is no excess ARP packets in the network"""
        num_arp_expected = self.topo.switch_to_switch_links * 2
        tcpdump_filter = 'arp and ether src %s' % ping_host.MAC()
        tcpdump_txt = self.tcpdump_helper(
            tcpdump_host, tcpdump_filter, [
                lambda: ping_host.cmd('arp -d %s' % tcpdump_host.IP()),
                lambda: ping_host.cmd('ping -c1 %s' % tcpdump_host.IP())],
            packets=(num_arp_expected+1))
        num_arp_received = len(re.findall(
            'who-has %s tell %s' % (tcpdump_host.IP(), ping_host.IP()), tcpdump_txt))
        self.assertTrue(num_arp_received)
        self.assertLessEqual(num_arp_received, num_arp_expected)

    def verify_stack_has_no_loop(self):
        """Ping between first and last hosts (by name) then verify there is no broadcast storm"""
        for ping_host, tcpdump_host in (
                (self.hosts_name_ordered()[0], self.hosts_name_ordered()[-1]),
                (self.hosts_name_ordered()[-1], self.hosts_name_ordered()[0])):
            self.verify_no_arp_storm(ping_host, tcpdump_host)

    def verify_all_stack_hosts(self):
        """Test conditions for stack hosts"""
        for _ in range(2):
            self.verify_stack_up()
            self.verify_no_cable_errors()
            self.verify_stack_hosts()
            self.verify_traveling_dhcp_mac()
            self.verify_unicast_not_looped()
            self.verify_no_bcast_to_self()
            self.verify_stack_has_no_loop()
            self.flap_all_switch_ports()

    def verify_tunnel_established(self, src_host, dst_host, other_host, packets=3):
        """Verify ICMP packets tunnelled from src to dst."""
        icmp_match = {'eth_type': IPV4_ETH, 'ip_proto': 1}
        self.wait_until_matching_flow(icmp_match, table_id=self._PORT_ACL_TABLE, ofa_match=False)
        tcpdump_text = self.tcpdump_helper(
            dst_host, 'icmp[icmptype] == 8', [
                # need to set static ARP as only ICMP is tunnelled.
                lambda: src_host.cmd('arp -s %s %s' % (other_host.IP(), other_host.MAC())),
                lambda: src_host.cmd('ping -c%u -t1 %s' % (packets, other_host.IP()))
            ],
            packets=1, timeout=(packets + 1),
        )
        self.wait_nonzero_packet_count_flow(
            icmp_match, table_id=self._PORT_ACL_TABLE, ofa_match=False)
        self.assertTrue(re.search(
            '%s: ICMP echo request' % other_host.IP(), tcpdump_text
        ), 'Tunnel was not established')

    def verify_one_broadcast(self, from_host, to_hosts):
        """Verify host connectivity via broadcast"""
        self.assertGreater(len(to_hosts), 1, 'Testing only one ext host is not useful')
        received_broadcasts = []
        for to_host in to_hosts:
            if self.verify_broadcast(hosts=(from_host, to_host), broadcast_expected=None):
                received_broadcasts.append(to_host)
        received_names = {host.name: host for host in received_broadcasts}
        self.assertEqual(len(received_broadcasts), 1,
                         'Received not exactly one broadcast from %s: %s' %
                         (from_host.name, received_names))

    def map_int_ext_hosts(self):
        """
        Obtains a list of the interal hosts, the external hosts and a dictionary
            of the internal and external hosts for each DP by DP name
        Returns int_hosts, ext_hosts, dp_hosts
        """
        int_hosts = []
        ext_hosts = []
        dp_hosts = {self.dp_name(dp_index): ([], []) for dp_index in range(self.NUM_DPS)}
        for host_id, options in self.host_options.items():
            host = self.host_information[host_id]['host']
            if options.get('loop_protect_external', False):
                ext_hosts.append(host)
                int_or_ext = 1
            else:
                int_hosts.append(host)
                int_or_ext = 0
            for link in self.host_links[host_id]:
                dp_hosts[self.dp_name(link)][int_or_ext].append(host)
        return set(int_hosts), set(ext_hosts), dp_hosts

    def verify_protected_connectivity(self):
        """
        Checks:
            - All internal hosts can reach other internal hosts
            - All internal hosts can reach exactly one external host
            - All external hosts cannot flood to each other
            - All external hosts can reach the internal hosts
        """
        self.verify_stack_up()
        int_hosts, ext_hosts, _ = self.map_int_ext_hosts()

        for int_host in int_hosts:
            # All internal hosts can reach other internal hosts.
            for other_int_host in int_hosts - {int_host}:
                self.verify_broadcast(hosts=(int_host, other_int_host), broadcast_expected=True)
                self.one_ipv4_ping(int_host, other_int_host.IP())

            # All internal hosts can reach exactly one external host.
            self.verify_one_broadcast(int_host, ext_hosts)

        for ext_host in ext_hosts:
            # All external hosts can reach internal hosts.
            for int_host in int_hosts:
                self.verify_broadcast(hosts=(ext_host, int_host), broadcast_expected=True)
                self.one_ipv4_ping(ext_host, int_host.IP())

            # All external hosts cannot flood to each other.
            for other_ext_host in ext_hosts - {ext_host}:
                self.verify_broadcast(hosts=(ext_host, other_ext_host), broadcast_expected=False)

    def set_externals_state(self, dp_name, externals_up):
        """Set the port up/down state of all external ports on a switch"""
        dp_conf = self._get_faucet_conf()['dps'][dp_name]
        for port_num, port_conf in dp_conf['interfaces'].items():
            if port_conf.get('loop_protect_external'):
                if externals_up:
                    self.set_port_up(port_num, dp_conf.get('dp_id'))
                else:
                    self.set_port_down(port_num, dp_conf.get('dp_id'))

    def validate_with_externals_down(self, dp_name):
        """Check situation when all externals on a given dp are down"""
        self.set_externals_state(dp_name, False)
        self.verify_protected_connectivity()
        self.set_externals_state(dp_name, True)

    def validate_with_externals_down_fails(self, dp_name):
        """Faucet code is not currently correct, so expect to fail."""
        # TODO: Fix faucet so the test inversion is no longer required.
        asserted = False
        try:
            self.validate_with_externals_down(dp_name)
        except AssertionError:
            asserted = True
        self.assertTrue(asserted, 'Did not fail as expected for %s' % dp_name)

    def verify_intervlan_routing(self):
        """Verify intervlan routing but for LAG host use bond interface"""
        for src in self.host_information:
            for dst in self.host_information:
                if dst > src:
                    self.check_host_connectivity_by_id(src, dst)

    def check_host_connectivity_by_id(self, src_id, dst_id):
        """Ping from src to dst with host_id parameters if they should be able to"""
        src_host, src_ip, _, src_vlan, src_bond, _ = self.host_information[src_id].values()
        dst_host, dst_ip, _, dst_vlan, dst_bond, _ = self.host_information[dst_id].values()
        connectivity = src_vlan == dst_vlan or self.is_routed_vlans(src_vlan, dst_vlan)
        if self.is_routed_vlans(src_vlan, dst_vlan):
            src_vip = self.faucet_vips[src_vlan]
            dst_vip = self.faucet_vips[dst_vlan]
            self.host_ping(src_host, src_vip.ip, src_bond)  # pytype: disable=attribute-error
            self.host_ping(dst_host, dst_vip.ip, dst_bond)  # pytype: disable=attribute-error
        if connectivity:
            self.host_ping(src_host, dst_ip.ip, src_bond)  # pytype: disable=attribute-error
            self.host_ping(dst_host, src_ip.ip, dst_bond)  # pytype: disable=attribute-error

    def is_routed_vlans(self, vlan_a, vlan_b):
        """Return true if the two vlans share a router"""
        if self.routers:
            for vlans in self.routers.values():
                if (vlan_a in vlans and vlan_b in vlans):
                    return True
        return False

    def bcast_dst_blocked_helper(self, port, first_host, second_host, success_re, retries):
        """Helper for checking broadcast destination has been blocked"""
        tcpdump_filter = 'udp and ether src %s and ether dst %s' % (
            first_host.MAC(), "ff:ff:ff:ff:ff:ff")
        target_addr = str(self.faucet_vips[0].network.broadcast_address)
        for _ in range(retries):
            tcpdump_txt = self.tcpdump_helper(
                second_host, tcpdump_filter, [
                    partial(first_host.cmd, (
                        'date | socat - udp-datagram:%s:%d,broadcast' % (
                            target_addr, port)))],
                packets=1)
            if re.search(success_re, tcpdump_txt):
                return True
            time.sleep(1)
        return False

    def get_expected_synced_states(self, host_id):
        """Return the list of regex string for the expected sync state of a LACP LAG connection"""
        synced_state_list = []
        oper_key = self.host_options[host_id]['lacp']
        lacp_ports = [
            port for ports in self.host_information[host_id]['ports'].values() for port in ports]
        for port in lacp_ports:
            synced_state_txt = r"""
Slave Interface: \S+
MII Status: up
Speed: \d+ Mbps
Duplex: full
Link Failure Count: \d+
Permanent HW addr: \S+
Slave queue ID: 0
Aggregator ID: \d+
Actor Churn State: monitoring
Partner Churn State: monitoring
Actor Churned Count: \d+
Partner Churned Count: \d+
details actor lacp pdu:
    system priority: 65535
    system mac address: 0e:00:00:00:00:99
    port key: \d+
    port priority: 255
    port number: \d+
    port state: 63
details partner lacp pdu:
    system priority: 65535
    system mac address: 0e:00:00:00:00:01
    oper key: %d
    port priority: 255
    port number: %d
    port state: 62
""".strip() % (oper_key, port)
            synced_state_list.append(synced_state_txt)
        return synced_state_list

    def prom_lacp_up_ports(self, dpid):
        """Get the number of up LAG ports according to Prometheus for a dpid"""
        lacp_up_ports = 0
        for host_id, options in self.host_options.items():
            # Find LACP hosts
            for key in options.keys():
                if key == 'lacp':
                    # Is LACP host
                    host_information = self.host_information[host_id]
                    if dpid in host_information['ports']:
                        # LACP host has links to dpid
                        lacp_ports = host_information['ports'][dpid]
                        for port in lacp_ports:
                            # Obtain up LACP ports for that dpid
                            port_labels = self.port_labels(port)
                            lacp_state = self.scrape_prometheus_var(
                                'port_lacp_state', port_labels, default=0, dpid=dpid)
                            lacp_up_ports += 1 if lacp_state == 3 else 0
        return lacp_up_ports

    def verify_num_lag_up_ports(self, expected_up_ports, dpid):
        """Checks to see if Prometheus has the expected number of up LAG ports on the specified DP"""
        for _ in range(self.LACP_TIMEOUT*10):
            if self.prom_lacp_up_ports(dpid) == expected_up_ports:
                return
            time.sleep(1)
        self.assertEqual(self.prom_lacp_up_ports(dpid), expected_up_ports)

    def require_linux_bond_up(self, host_id):
        """Checks to see if the host has properly formed into a bonded state"""
        synced_state_list = self.get_expected_synced_states(host_id)
        host = self.host_information[host_id]['host']
        bond_name = self.host_information[host_id]['bond']
        for _ in range(self.LACP_TIMEOUT*2):
            result = host.cmd('cat /proc/net/bonding/%s|sed "s/[ \t]*$//g"' % bond_name)
            result = '\n'.join([line.rstrip() for line in result.splitlines()])
            with open(os.path.join(self.tmpdir, 'bonding-state.txt'), 'w') as state_file:
                state_file.write(result)
            matched_all = True
            for state_txt in synced_state_list:
                if not re.search(state_txt, result):
                    matched_all = False
                    break
            if matched_all:
                return
            time.sleep(1)
        synced_state_txt = r""""""
        for state_txt in synced_state_list:
            synced_state_txt += state_txt + "\n\n"
        synced_state_txt.strip()
        self.assertFalse(
            re.search(synced_state_txt, result),
            msg='LACP did not synchronize: %s\n\nexpected:\n\n%s' % (result, synced_state_txt))

    def verify_lag_connectivity(self, host_id):
        """Verify LAG connectivity"""
        lacp_ports = self.host_information[host_id]['ports']
        # All ports down
        for dpid, ports in lacp_ports.items():
            for port in ports:
                self.set_port_down(port, dpid)
            self.verify_num_lag_up_ports(0, dpid)
        # Pick a port to set up
        up_dpid = random.choice(list(lacp_ports.keys()))
        up_port = random.choice(lacp_ports[up_dpid])
        self.set_port_up(up_port, up_dpid)
        self.verify_num_lag_up_ports(1, up_dpid)
        # Ensure connectivity with one port
        self.verify_lag_host_connectivity()
        # Set the other ports to UP
        for dpid, ports in lacp_ports.items():
            for port in ports:
                self.set_port_up(port, dpid)
            self.verify_num_lag_up_ports(len(ports), dpid)
        # Ensure connectivity with all ports
        self.require_linux_bond_up(host_id)
        self.verify_lag_host_connectivity()
        # Tear down first port
        self.set_port_down(up_port, up_dpid)
        self.verify_num_lag_up_ports(len(lacp_ports[up_dpid])-1, up_dpid)
        # Ensure connectivity with new ports only
        self.verify_lag_host_connectivity()

    def verify_lag_host_connectivity(self):
        """Verify LAG hosts can connect to any other host using the interface"""
        # Find all LACP hosts
        for lacp_id, host_options in self.host_options.items():
            if 'lacp' in host_options:
                # Found LACP host
                for dst_id in self.host_information:
                    if lacp_id == dst_id:
                        continue
                    # Test connectivity to any other host (might be another LAG host)
                    self.check_host_connectivity_by_id(lacp_id, dst_id)
