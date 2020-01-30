#!/usr/bin/env python3


from clib.mininet_test_util import get_serialno
from clib.mininet_test_topo import FaucetSwitchTopo, SWITCH_START_PORT


class FaucetTopoGenerator(FaucetSwitchTopo):
    """
    Generate a Faucet topology for use in the mininet integration tests
    FaucetTopoGenerator is able to connect up a network in an arbitrary
        topology based off a dp_link, host_link and host_vlan dictionary
    """

    @staticmethod
    def dp_links_networkx_graph(graph, offset=0, n_dp_links=1):
        """
        Networkx provides methods for generating different graphs
        Args:
            graph: Networkx graph
            offset: DP offset
            n_dp_links: Redundant switch-switch links
        Return dp_links a networkx graph
        """
        dp_links = {}
        for edge in graph.edges():
            src = edge[0] + offset
            dst = edge[1] + offset
            if src not in dp_links:
                dp_links[src] = []
            for _ in range(n_dp_links):
                dp_links[src].append(dst)
        return dp_links

    @staticmethod
    def tagged_untagged_hosts(n_dps, n_tagged, n_untagged,
                              n_host_links=1, dp_offset=0, host_offset=0):
        """
        Generate links & vlans for a number of tagged and untagged vlan hosts on each dp
        Args:
            n_dps: Number of DPs to generate hosts on
            n_tagged: Number of tagged hosts to generate on each DP
            n_untagged: Number of untagged hosts to generate on each DP
            n_host_links: Number of redundant host to switch links
            dp_offset: DP index offset
            host_offset: Host index offset
        Return host_links, host_vlans
        """
        host_links = {}
        host_vlans = {}
        vlan = 0
        host_id = host_offset
        for i in range(n_dps):
            for _ in range(n_tagged):
                host_links[host_id] = []
                for _ in range(n_host_links):
                    host_links[host_id].append(i + dp_offset)
                host_vlans[host_id] = (vlan,)
                host_id += 1
            for _ in range(n_untagged):
                host_links[host_id] = []
                for _ in range(n_host_links):
                    host_links[host_id].append(i + dp_offset)
                host_vlans[host_id] = vlan
                host_id += 1
        return host_links, host_vlans

    @staticmethod
    def tagged_vlan_hosts(n_dps, vlan, n_host_links=1, dp_offset=0, host_offset=0):
        """
        Generate dictionaries for a single tagged host on each DP
        Args:
            n_dps: Number of DPs to generate hosts on
            vlan: The host's tagged VLAN
            n_host_links: Number of redundant links
            dp_offset: DP index offset
            host_offset: Host index offset
        Return host_links, host_vlans
        """
        host_links = {}
        host_vlans = {}
        host_id = host_offset
        for i in range(n_dps):
            host_links[host_id] = []
            for _ in range(n_host_links):
                host_links[host_id].append(i + dp_offset)
            host_vlans[host_id] = (vlan, )
            host_id += 1
        return host_links, host_vlans

    @staticmethod
    def untagged_vlan_hosts(n_dps, n_vlans, n_host_links=1, dp_offset=0, host_offset=0):
        """
        Generate dictionaries for an untagged host on each vlan on each DP
        Args:
            n_dps: Number of DPs to generate hosts on
            n_vlans: Number of vlans to generate hosts on
            n_host_links: Number of redundant links
            dp_offset: DP index offset
            host_offset: Host index offset
        Return host_links, host_vlans
        """
        host_links = {}
        host_vlans = {}
        host_id = host_offset
        for i in range(n_dps):
            for vlan in range(n_vlans):
                host_links[host_id] = []
                for _ in range(n_host_links):
                    host_links[host_id].append(i + dp_offset)
                host_vlans[host_id] = vlan
                host_id += 1
        return host_links, host_vlans

    @staticmethod
    def untagged_vlan_hosts_by_amount(n_dps, n_vlan_hosts,
                                      n_host_links=1, dp_offset=0, host_offset=0):
        """
        Generate dictionaries for untagged hosts on each DP with specified number of hosts
        Args:
            n_dps: Number of DPs to generate hosts on
            n_vlans: Number of VLANs
            n_vlan_hosts (dict): VLAN index to number of hosts on that VLAN on each DP
            n_host_links: Number of redundant host-switch links
            dp_offset: DP index offset
            host_offset: Host index offset
        Return host_links, host_vlans
        """
        host_links = {}
        host_vlans = {}
        host_id = host_offset
        for i in range(n_dps):
            for vlan, n_hosts in n_vlan_hosts.items():
                for _ in range(n_hosts):
                    host_links[host_id] = []
                    for _ in range(n_host_links):
                        host_links[host_id].append(i + dp_offset)
                    host_vlans[host_id] = vlan
                    host_id += 1
        return host_links, host_vlans

    def dpid_peer_links(self, dpid):
        """Return peer_link list for dpid, remapping if necessary"""
        name = self.dpid_names[dpid]
        links = [self.hw_remap_peer_link(dpid, link) for link in self.switch_peer_links[name]]
        return links

    def _add_host_to_switch_link(self, switch, dpid, host, curr_index):
        """
        Add a link from a switch to a host
        Args:
            switch: Switch
            dpid: Switch dpid
            host: Host
            curr_index: Port order index
        """
        self.switch_ports.setdefault(switch, [])
        self.dpid_port_host.setdefault(int(dpid), {})
        index = curr_index
        port = self.start_port + self.port_order[index]
        self.addLink(switch, host, port1=port, delay=self.DELAY, use_htb=True)
        self.switch_ports[switch].append(port)
        self.dpid_port_host[int(dpid)][port] = host
        index += 1
        return index

    def _add_switch_to_switch_link(self, src, dst, next_index):
        """
        Args:
            src: Source switch
            dst: Dest switch
            next_index: Next port order index
        """
        self.switch_peer_links.setdefault(src, [])
        self.switch_peer_links.setdefault(dst, [])
        dpid1, dpid2 = self.switch_dpids[src], self.switch_dpids[dst]
        index1, index2 = next_index[src], next_index[dst]
        port1, port2 = [self.start_port + self.port_order[i] for i in (index1, index2)]
        self.addLink(src, dst, port1=port1, port2=port2)
        # Update port and link lists
        self.switch_ports.setdefault(src, [])
        self.switch_ports.setdefault(dst, [])
        self.switch_ports[src].append(port1)
        self.switch_ports[dst].append(port2)
        self.switch_peer_links[src].append(self.peer_link(port1, dpid2, port2))
        self.switch_peer_links[dst].append(self.peer_link(port2, dpid1, port1))
        # Update next indices on src and dest
        next_index[src] += 1
        next_index[dst] += 1

    def build(self, ovs_type, ports_sock, test_name, dpids,
              dp_links, host_links, host_vlans, vlan_vids,
              hw_dpid=None, switch_map=None, start_port=SWITCH_START_PORT,
              port_order=None, get_serialno=get_serialno):
        """
        Creates the Faucet mininet switches & hosts
        Args:
            dp_links (dict): dp id key to list of dp id value
            host_links (dict): host id key to list of dp id value
            host_vlans (dict): host id key to vlans id value
            vlan_vids (dict): VLAN IDs for vlan index
        """
        self.hw_dpid = hw_dpid
        self.hw_ports = sorted(switch_map) if switch_map else []
        self.start_port = start_port

        self.switch_to_switch_links = 0
        for dplinks in dp_links.values():
            self.switch_to_switch_links += len(dplinks)

        self.host_to_switch_links = 0
        for hostlinks in host_links.values():
            self.host_to_switch_links += len(hostlinks)

        max_ports = self.host_to_switch_links + (2 * self.switch_to_switch_links)
        self.port_order = self.extend_port_order(port_order, max_ports)

        # Create hosts
        self.hosts_by_id = {}
        for host_id, vlans in host_vlans.items():
            serialno = get_serialno(ports_sock, test_name)
            sid_prefix = self._get_sid_prefix(serialno)
            if isinstance(vlans, int):
                self.hosts_by_id[host_id] = self._add_untagged_host(sid_prefix, host_id)
            elif isinstance(vlans, tuple):
                self.hosts_by_id[host_id] = self._add_tagged_host(
                    sid_prefix, [vlan_vids[v] for v in vlans], host_id)

        # Create switches & then host-switch links
        self.switch_peer_links = {}
        next_index = {}
        self.dpid_to_switch = {}
        for i, dpid in enumerate(dpids):
            serialno = get_serialno(ports_sock, test_name)
            sid_prefix = self._get_sid_prefix(serialno)
            switch = self._add_faucet_switch(sid_prefix, dpid, hw_dpid, ovs_type)
            self.dpid_to_switch[dpid] = switch
            next_index[switch] = 0
            # Create host-switch links
            for host_id, hostlinks in host_links.items():
                if i in hostlinks:
                    n_links = hostlinks.count(i)
                    for _ in range(n_links):
                        host = self.hosts_by_id[host_id]
                        next_index[switch] = self._add_host_to_switch_link(
                            switch, dpid, host, next_index[switch])

        # Create switch-switch links
        for src_index, dplinks in dp_links.items():
            for dst_index in dplinks:
                src = self.dpid_to_switch[dpids[src_index]]
                dst = self.dpid_to_switch[dpids[dst_index]]
                self._add_switch_to_switch_link(src, dst, next_index)
