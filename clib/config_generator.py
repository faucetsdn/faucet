
"""Mininet Topo class with YAML config generator"""

# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
import string

import yaml

from mininet.log import output
from mininet.topo import Topo

from clib import mininet_test_util
from clib.mininet_test_topo import FaucetHost, VLANHost, FaucetSwitch, NoControllerFaucetSwitch


class GenerationError(Exception):
    """Indicates a problem with generating the configuration file"""


class FaucetTopoGenerator(Topo):
    """Creates a mininet topology and then provides a method to generate a YAML config file"""

    # Host CPU option
    CPUF = 0.5
    # Link delay option
    DELAY = '1ms'

    # Switch index map to switch name
    switches_by_id = {}
    # Switch index map to switch dpid
    dpids_by_id = {}
    # Host index map to host name
    hosts_by_id = {}

    # Generated hardware switch name
    hw_name = None
    # DPID of the hardware switch
    hw_dpid = None
    # List of port order for the hardware switch
    hw_ports = None

    # Function to resolve serial numbers
    get_serialno = None

    # Additional mininet host options
    host_options = None

    # The generated starting port for each switch
    start_port = None
    # The port order for each switch
    port_order = None

    def get_dpids(self):
        """Returns list of DPIDs in switch index order"""
        return [self.dpids_by_id[key] for key in sorted(self.dpids_by_id)]

    def _create_link_port_map(self):
        """Switch pair link map to list of ports for that pair"""
        port_maps = {}
        for i, name in self.switches_by_id.items():
            for port, link in self.ports[name].items():
                if self.isSwitch(link[0]):
                    peer_id = self.nodeInfo(link[0])['switch_n']
                    port_maps.setdefault((i, peer_id), [])
                    port_maps[(i, peer_id)].append(port)
        return port_maps

    def _create_host_port_map(self):
        """Host map to linked switches to list of ports from switch to host"""
        host_port_map = {}
        for host, name in self.hosts_by_id.items():
            host_port_map.setdefault(host, {})
            for link in self.ports[name].values():
                switch_id = self.nodeInfo(link[0])['switch_n']
                host_port_map[host].setdefault(switch_id, [])
                host_port_map[host][switch_id].append(link[1])
        return host_port_map

    def _create_port_map(self):
        """Create a map from port to the true port"""
        port_maps = {}
        for i, dpid in self.dpids_by_id.items():
            switch_name = self.switches_by_id[i]
            ports = self.ports[switch_name].keys()
            port_maps[dpid] = {'port_%d' % i: port for i, port in enumerate(ports)}
        return port_maps

    def create_port_maps(self):
        """Return host port maps and link port maps"""
        return self._create_port_map(), self._create_host_port_map(), self._create_link_port_map()

    def dp_dpid(self, i):
        """DP DPID"""
        if i == 0 and self.hw_dpid:
            return self.hw_dpid
        reserved_range = 100
        while True:
            dpid = random.randint(1, (2**32 - reserved_range)) + reserved_range
            if dpid not in self.dpids_by_id.values():
                return str(dpid)

    def vlan_name(self, i):
        """VLAN name"""
        return 'vlan-%i' % (i+1)

    def vlan_vid(self, i):
        """VLAN VID value"""
        return (i+1) * 100

    def router_name(self, i):
        """Router name"""
        return 'router-%s' % (i+1)

    def __init__(self, *args, **kwargs):
        self.switches_by_id = {}
        self.dpids_by_id = {}
        self.hosts_by_id = {}
        super().__init__(*args, **kwargs)

    @staticmethod
    def _get_sid_prefix(ports_served):
        """Return a unique switch/host prefix for a test."""
        # Linux tools require short interface names.
        id_chars = ''.join(sorted(string.ascii_letters + string.digits))  # pytype: disable=module-attr
        id_a = int(ports_served / len(id_chars))
        id_b = ports_served - (id_a * len(id_chars))
        return '%s%s' % (
            id_chars[id_a], id_chars[id_b])

    @staticmethod
    def extend_port_order(port_order=None, max_length=16):
        """
        Extends the pattern of port_port order up to max_length

        Args:
            port_order (list): List of integers in an order to extend
            max_length (int): Maximum length to extend the list to
        """
        if not port_order:
            return list(range(max_length + 1))
        if len(port_order) >= max_length:
            return port_order
        extend_order = []
        order = port_order
        start_port = max(port_order) + 1
        while len(port_order) + len(extend_order) < max_length:
            for i in order:
                extend_order.append(start_port + i)
                if len(port_order) + len(extend_order) >= max_length:
                    break
            start_port = max(extend_order) + 1
        return port_order + extend_order

    def _generate_sid_prefix(self):
        """Returns a sid prefix for a node in the topology"""
        return self._get_sid_prefix(self.get_serialno(self.ports_sock, self.test_name))

    def _create_next_port(self, switch_name):
        """
        Creates and returns the next port number for a switch

        Args:
            switch_name (str): The name of the switch to generate the next port
        """
        index = 0
        if switch_name in self.ports:
            index = len(self.ports[switch_name])
        if self.hw_name and switch_name == self.hw_name and self.hw_ports:
            return self.hw_ports[self.port_order[index]]
        return self.start_port + self.port_order[index]

    def _add_host(self, host_index, vlans):
        """
        Adds a untagged/tagged host to the topology

        Args:
            sid_prefix (str): SID prefix to generate the host name
            host_index (int): Host index to generate the host name
            vlans (list/None/int): Type of host/vlans the host belongs to
        """
        sid_prefix = self._generate_sid_prefix()
        host_opts = self.host_options.get(host_index, {})
        host_name = None
        if 'cls' in host_opts:
            host_name = 'e%s%1.1u' % (sid_prefix, host_index + 1)
        else:
            if isinstance(vlans, int) or vlans is None:
                host_name = 'u%s%1.1u' % (sid_prefix, host_index + 1)
                host_opts['cls'] = FaucetHost
            elif isinstance(vlans, list):
                host_name = 't%s%1.1u' % (sid_prefix, host_index + 1)
                host_opts['vlans'] = [self.vlan_vid(vlan) for vlan in vlans]
                host_opts['cls'] = VLANHost
            else:
                raise GenerationError('Unknown host type')
        self.hosts_by_id[host_index] = host_name
        return self.addHost(
            cpu=self.CPUF,
            host_n=host_index,
            name=host_name,
            config_vlans=vlans,
            **host_opts)

    def _add_faucet_switch(self, switch_index):
        """
        Adds a Faucet switch to the topology

        Args:
            sid_prefix (str): SID prefix to generate the switch name
            switch_index (int): Switch index to generate the host name
            dpid (int): Switch DP ID
        """
        sid_prefix = self._generate_sid_prefix()
        switch_cls = FaucetSwitch
        switch_name = 's%s' % sid_prefix
        if switch_index == 0 and self.hw_dpid:
            self.hw_name = switch_name
            self.dpids_by_id[switch_index] = self.hw_dpid
            dpid = str(int(self.hw_dpid) + 1)
            output('bridging hardware switch DPID %s (%x) dataplane via OVS DPID %s (%x)\n' % (
                self.hw_dpid, int(self.hw_dpid), dpid, int(dpid)))
            switch_cls = NoControllerFaucetSwitch
        else:
            dpid = self.dp_dpid(switch_index)
            self.dpids_by_id[switch_index] = dpid
        self.switches_by_id[switch_index] = switch_name
        return self.addSwitch(
            name=switch_name,
            cls=switch_cls,
            datapath=self.ovs_type,
            dpid=mininet_test_util.mininet_dpid(dpid),
            switch_n=switch_index)

    def _add_link(self, node, peer_node, vlans):
        """
        Creates and adds a link between two nodes to the topology

        Args:
            node (str): Name of the node for the link, NOTE: should ALWAYS be a switch
            peer_node (str): Name of the peer node for the link
            vlans (list/None/int): Type of the link
        """
        port1, port2 = None, None
        opts = {}
        if self.isSwitch(node):
            # Node is a switch, create port
            port1 = self._create_next_port(node)
        if self.isSwitch(peer_node):
            # Peer node is a switch, create port
            port2 = self._create_next_port(peer_node)
        else:
            # Peer node is a host, use delay & htb options
            opts['delay'] = self.DELAY
            opts['use_htb'] = True
        return self.addLink(
            node,
            peer_node,
            port1=port1,
            port2=port2,
            **opts,
            config_vlans=vlans)

    def add_switch_topology(self, switch_links, link_vlans):
        """
        Adds the switches and switch-switch links to the network topology
        Tagged links are mapped to a list of vlan indices whereas untagged links
            are mapped to a single vlan index, stack links are mapped to None

        Args:
            switch_topology (list): List of link tuples of switch indices (u, v)
            link_vlans (dict): Link tuple of switch indices (u, v) mapping to vlans
        """
        for u_id, v_id in switch_links:
            if u_id not in self.switches_by_id:
                self._add_faucet_switch(u_id)
            if v_id not in self.switches_by_id:
                self._add_faucet_switch(v_id)
            u_name = self.switches_by_id[u_id]
            v_name = self.switches_by_id[v_id]
            self._add_link(u_name, v_name, link_vlans[(u_id, v_id)])

    def add_host_topology(self, host_links, host_vlans):
        """
        Adds the hosts and host-switch links to the network topology
        Tagged hosts are mapped to a list of vlan indices whereas untagged hosts
            are mapped to a single vlan index

        Args:
            host_links (dict): Host index key to list of dp indices
            host_vlans (dict): Host index key to vlan index/indices
        """
        for h_id, links in host_links.items():
            vlans = host_vlans[h_id]
            if h_id not in self.hosts_by_id:
                self._add_host(h_id, vlans)
            host_name = self.hosts_by_id[h_id]
            for dp_i in links:
                if dp_i not in self.switches_by_id:
                    self._add_faucet_switch(dp_i)
                switch_name = self.switches_by_id[dp_i]
                self._add_link(switch_name, host_name, vlans)

    def build(self, ovs_type, ports_sock, test_name,
              host_links, host_vlans, switch_links, link_vlans,
              hw_dpid=None, hw_ports=None,
              port_order=None, start_port=5,
              get_serialno=mininet_test_util.get_serialno, host_options=None):
        """
        Creates a Faucet mininet topology

        Args:
            ovs_type (str): The OVS switch type
            ports_sock (str): Port socket
            test_name (str): Name of the test creating the mininet topology
            host_links (dict): Host index key to list of dp indices
            host_vlans (dict): Host index key to vlan index/indices
            switch_links (list): List of link tuples of switch indices (u, v)
            link_vlans (dict): Link tuple of switch indices (u, v) mapping to vlans
            hw_dpid (int): DP ID of the hardware switch to connect to the topology
            hw_ports (list): Map of the OVS bridge port index to hardware port number
            port_order (list): List of integers in order for a switch port index order
            start_port (int): The minimum start port number for all switch port numbers
            get_serialno (func): Function to get the serial no.
            host_options (dict): Host index map to additional mininet host options
        """
        # Additional test generation information
        self.ovs_type = ovs_type  # pylint: disable=attribute-defined-outside-init
        self.ports_sock = ports_sock  # pylint: disable=attribute-defined-outside-init
        self.test_name = test_name  # pylint: disable=attribute-defined-outside-init
        self.get_serialno = get_serialno

        # Information for hardware switches
        self.hw_dpid = hw_dpid
        self.hw_ports = sorted(hw_ports) if hw_ports else []

        # Additional information for special hosts
        self.host_options = host_options if host_options else {}

        # Generate a port order for all of the switches to use
        max_ports = (len(switch_links) * 2) + len(host_links)
        self.start_port = start_port
        self.port_order = self.extend_port_order(port_order, max_length=max_ports)

        # Build the network topology
        self.add_switch_topology(switch_links, link_vlans)
        self.add_host_topology(host_links, host_vlans)

    def get_acls_config(self, acl_options):
        """Return the ACLs in dictionary format for the configuration file"""
        return acl_options.copy()

    def get_dps_config(self, dp_options, host_options, link_options):
        """Return the DPs in dictionary format for the configuration file"""
        dps_config = {}

        def get_interface_config(link_name, src_port, dst_node, dst_port, vlans, options):
            interface_config = {}
            type_ = 'switch-switch' if dst_port else 'switch-host'
            if isinstance(vlans, int):
                # Untagged link
                interface_config = {
                    'name': 'b%u' % src_port,
                    'description': 'untagged %s' % link_name,
                    'native_vlan': self.vlan_name(vlans)
                }
            elif isinstance(vlans, list):
                # Tagged link
                interface_config = {
                    'name': 'b%u' % src_port,
                    'description': 'tagged %s' % link_name,
                    'tagged_vlans': [self.vlan_name(vlan) for vlan in vlans]
                }
            elif dst_node and dst_port:
                # Stack link
                interface_config = {
                    'name': 'b%u' % src_port,
                    'description': 'stack %s' % link_name,
                    'stack': {
                        'dp': dst_node,
                        'port': dst_port
                    }
                }
            elif vlans is None:
                # output only link
                interface_config = {
                    'name': 'b%u' % src_port,
                    'description': 'output only %s' % link_name,
                    'output_only': True,
                }
            else:
                raise GenerationError('Unknown %s link type %s' % (type_, vlans))
            if options:
                for option_key, option_value in options.items():
                    interface_config[option_key] = option_value
            return interface_config

        def add_dp_config(src_node, dst_node, link_key, link_info, reverse=False):
            dp_config = dps_config[src_node]
            src_info, dst_info = self.nodeInfo(src_node), self.nodeInfo(dst_node)
            vlans = link_info['config_vlans']
            src_id = src_info['switch_n']
            dp_config.setdefault('interfaces', {})
            options = {}
            if self.isSwitch(dst_node):
                # Generate switch-switch config link
                if reverse:
                    src_port, dst_port = link_info['port2'], link_info['port1']
                else:
                    src_port, dst_port = link_info['port1'], link_info['port2']
                link_name = 'link #%s to %s:%s' % (link_key, dst_node, dst_port)
                options = {}
                dst_id = dst_info['switch_n']
                if link_options and (src_id, dst_id) in link_options:
                    options.update(link_options[(src_id, dst_id)])
            else:
                # Generate host-switch config link
                src_port, dst_port = link_info['port1'], None
                link_name = 'link #%s to %s' % (link_key, dst_node)
                host_n = dst_info['host_n']
                if host_options and host_n in host_options:
                    options = host_options[host_n]
            dp_config['interfaces'].setdefault(  # pytype: disable=attribute-error
                src_port,
                get_interface_config(link_name, src_port, dst_node, dst_port, vlans, options))

        for links in self.links(withKeys=True, withInfo=True):
            src_node, dst_node, link_key, link_info = links
            src_info = self.nodeInfo(src_node)
            dst_info = self.nodeInfo(dst_node)
            if self.isSwitch(src_node):
                dps_config.setdefault(src_node, {})
                src_dpid = self.dpids_by_id[src_info['switch_n']]
                dps_config[src_node].setdefault('dp_id', int(src_dpid))
                add_dp_config(src_node, dst_node, link_key, link_info)
            if self.isSwitch(dst_node):
                dps_config.setdefault(dst_node, {})
                dst_dpid = self.dpids_by_id[dst_info['switch_n']]
                dps_config[dst_node].setdefault('dp_id', int(dst_dpid))
                add_dp_config(dst_node, src_node, link_key, link_info, True)
        if dp_options:
            for dp, options in dp_options.items():
                switch_name = self.switches_by_id[dp]
                dps_config.setdefault(switch_name, {})
                for option_key, option_value in options.items():
                    dps_config[switch_name][option_key] = option_value
        return dps_config

    def get_vlans_config(self, n_vlans, vlan_options):
        """
        Return the VLANs in dictionary format for the YAML configuration file

        Args:
            n_vlans (int): Number of VLANs to generate
            vlan_options (dict): Additional options for each VLAN, keyed by vlan index
        """
        vlans_config = {}
        for vlan in range(n_vlans):
            vlan_name = self.vlan_name(vlan)
            vlans_config[vlan_name] = {
                'vid': self.vlan_vid(vlan)
            }
        if vlan_options:
            for vlan, options in vlan_options.items():
                vlan_name = self.vlan_name(vlan)
                for option_key, option_value in options.items():
                    vlans_config[vlan_name][option_key] = option_value
        return vlans_config

    def get_routers_config(self, routers, router_options):
        """
        Return the routers in dictionary format for the configuration file

        Args:
            routers (dict): Router index to list of VLANs in the router
            router_options (dict): Additional options for each router, keyed by router index
        """
        routers_config = {}
        for router, vlans in routers.items():
            routers_config[self.router_name(router)] = {
                'vlans': [self.vlan_name(vlan) for vlan in vlans]
            }
        if router_options:
            for router, options in router_options.items():
                router_name = self.router_name(router)
                for option_key, option_value in options.items():
                    routers_config[router_name][option_key] = option_value
        return routers_config

    def get_config(self, n_vlans, acl_options=None, dp_options=None, host_options=None,
                   link_options=None, vlan_options=None, routers=None, router_options=None,
                   include=None, include_optional=None):
        """
        Creates a Faucet YAML configuration file using the current topology

        Args:
            n_vlans (int): Number of VLANs to generate
            acl_options (dict): Acls in use in the Faucet configuration file
            dp_options (dict): Additional options for each DP, keyed by DP index
            host_options (dict): Additional options for each host, keyed by host index
            link_options (dict): Additional options for each link, keyed by indices tuple (u, v)
            vlan_options (dict): Additional options for each VLAN, keyed by vlan index
            routers (dict): Router index to list of VLANs in the router
            router_options (dict): Additional options for each router, keyed by router index
            include (list): Files to include using the the Faucet config 'include' key
            include_optional (list): File to include using the Faucet config 'include_optional' key
        """
        config = {'version': 2}
        if include:
            config['include'] = list(include)
        if include_optional:
            config['include-optional'] = list(include_optional)
        if acl_options:
            config['acls'] = self.get_acls_config(acl_options)
        config['vlans'] = self.get_vlans_config(n_vlans, vlan_options)
        if routers:
            config['routers'] = self.get_routers_config(routers, router_options)
        config['dps'] = self.get_dps_config(dp_options, host_options, link_options)
        return yaml.dump(config, default_flow_style=False)


class FaucetFakeOFTopoGenerator(FaucetTopoGenerator):
    """Generates Faucet topologies for Unittests"""

    # NOTE: For now, we dont actually create the objects for the unittests
    #   so we can leave them as they are in the FaucetTopoGenerator function

    def dp_dpid(self, i):
        """DP DPID"""
        return '%u' % (i+1)
