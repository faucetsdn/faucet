"""VLAN configuration."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
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

import collections
import ipaddress

from conf import Conf
from valve_util import btos
import valve_of


class VLAN(Conf):
    """Implement FAUCET configuration for a VLAN."""

    tagged = None
    untagged = None
    vid = None
    faucet_vips = None
    bgp_as = None
    bgp_local_address = None
    bgp_port = None
    bgp_routerid = None
    bgp_neighbor_addresses = []
    bgp_neighbour_addresses = []
    bgp_neighbor_as = None
    bgp_neighbour_as = None
    routes = None
    max_hosts = None
    unicast_flood = None
    acl_in = None
    # Define dynamic variables with prefix dyn_ to distinguish from variables set
    # configuration
    dyn_host_cache = None
    dyn_faucet_vips_by_ipv = None
    dyn_routes_by_ipv = None
    dyn_neigh_cache_by_ipv = None

    defaults = {
        'name': None,
        'description': None,
        'acl_in': None,
        'faucet_vips': None,
        'unicast_flood': True,
        'bgp_as': 0,
        'bgp_local_address': None,
        'bgp_port': 9179,
        'bgp_routerid': '',
        'bgp_neighbour_addresses': [],
        'bgp_neighbor_addresses': [],
        'bgp_neighbour_as': 0,
        'bgp_neighbor_as': None,
        'routes': None,
        'max_hosts': 255,
        # Limit number of hosts that can be learned on a VLAN.
        'vid': None,
        'proactive_arp_limit': None,
        # Don't proactively ARP for hosts if over this limit (None unlimited)
        'proactive_nd_limit': None,
        # Don't proactively ND for hosts if over this limit (None unlimited)
        }

    def __init__(self, _id, dp_id, conf=None):
        if conf is None:
            conf = {}
        self._id = _id
        self.dp_id = dp_id
        self.update(conf)
        self.set_defaults()
        self._id = _id
        self.tagged = []
        self.untagged = []
        self.dyn_host_cache = {}
        self.dyn_faucet_vips_by_ipv = collections.defaultdict(list)
        self.dyn_routes_by_ipv = collections.defaultdict(dict)
        self.dyn_neigh_cache_by_ipv = collections.defaultdict(dict)
        self.dyn_ipvs = []

        if self.faucet_vips:
            self.faucet_vips = [
                ipaddress.ip_interface(btos(ip)) for ip in self.faucet_vips]
            for faucet_vip in self.faucet_vips:
                self.dyn_faucet_vips_by_ipv[faucet_vip.version].append(
                    faucet_vip)
            self.dyn_ipvs = list(self.dyn_faucet_vips_by_ipv.keys())

        if self.bgp_as:
            assert self.bgp_port
            assert ipaddress.IPv4Address(btos(self.bgp_routerid))
            for neighbor_ip in self.bgp_neighbor_addresses:
                assert ipaddress.ip_address(btos(neighbor_ip))
            assert self.bgp_neighbor_as

        if self.routes:
            self.routes = [route['route'] for route in self.routes]
            for route in self.routes:
                ip_gw = ipaddress.ip_address(btos(route['ip_gw']))
                ip_dst = ipaddress.ip_network(btos(route['ip_dst']))
                assert ip_gw.version == ip_dst.version
                self.dyn_routes_by_ipv[ip_gw.version][ip_dst] = ip_gw

    def add_tagged(self, port):
        self.tagged.append(port)

    def add_untagged(self, port):
        self.untagged.append(port)

    def ipvs(self):
        """Return list of IP versions configured on this VLAN."""
        return self.dyn_ipvs

    def faucet_vips_by_ipv(self, ipv):
        """Return list of VIPs with specified IP version on this VLAN."""
        return self.dyn_faucet_vips_by_ipv[ipv]

    def routes_by_ipv(self, ipv):
        """Return route table for specified IP version on this VLAN."""
        return self.dyn_routes_by_ipv[ipv]

    def neigh_cache_by_ipv(self, ipv):
        """Return neighbor cache for specified IP version on this VLAN."""
        return self.dyn_neigh_cache_by_ipv[ipv]

    @property
    def host_cache(self):
        """Return host (L2) cache for this VLAN."""
        return self.dyn_host_cache

    @host_cache.setter
    def host_cache(self, value):
        self.dyn_host_cache = value

    def set_defaults(self):
        for key, value in list(self.defaults.items()):
            self._set_default(key, value)
        self._set_default('vid', self._id)
        self._set_default('name', str(self._id))
        self._set_default('faucet_vips', [])
        self._set_default('bgp_neighbor_as', self.bgp_neighbour_as)
        self._set_default(
            'bgp_neighbor_addresses', self.bgp_neighbour_addresses)

    def __str__(self):
        port_list = [str(x) for x in self.get_ports()]
        ports = ','.join(port_list)
        return 'vid:%s ports:%s' % (self.vid, ports)

    def get_ports(self):
        """Return list of all ports on this VLAN."""
        return list(self.tagged) + list(self.untagged)

    def mirrored_ports(self):
        """Return list of ports that are mirrored on this VLAN."""
        return [port for port in self.get_ports() if port.mirror]

    def mirror_destination_ports(self):
        """Return list of ports that are mirrored to, on this VLAN."""
        return [port for port in self.get_ports() if port.mirror_destination]

    def flood_ports(self, configured_ports, exclude_unicast):
        ports = []
        for port in configured_ports:
            if not port.running:
                continue
            if exclude_unicast:
                if not port.unicast_flood:
                    continue
            ports.append(port)
        return ports

    def tagged_flood_ports(self, exclude_unicast):
        return self.flood_ports(self.tagged, exclude_unicast)

    def untagged_flood_ports(self, exclude_unicast):
        return self.flood_ports(self.untagged, exclude_unicast)

    def flood_pkt(self, packet_builder, *args):
        ofmsgs = []
        for vid, ports in (
            (self.vid, self.tagged_flood_ports(False)),
            (None, self.untagged_flood_ports(False))):
            if ports:
                pkt = packet_builder(vid, *args)
                for port in ports:
                    ofmsgs.append(valve_of.packetout(port.number, pkt.data))
        return ofmsgs

    def port_is_tagged(self, port):
        """Return True if port number is an tagged port on this VLAN."""
        return port in self.tagged

    def port_is_untagged(self, port):
        """Return True if port number is an untagged port on this VLAN."""
        return port in self.untagged

    def is_faucet_vip(self, ipa):
        """Return True if IP is a VIP on this VLAN."""
        for faucet_vip in self.faucet_vips_by_ipv(ipa.version):
            if ipa == faucet_vip.ip:
                return True
        return False

    def ip_in_vip_subnet(self, ipa):
        """Return True if IP in same IP network as a VIP on this VLAN."""
        for faucet_vip in self.faucet_vips_by_ipv(ipa.version):
            if ipa in faucet_vip.network:
                return True
        return False

    def ips_in_vip_subnet(self, ips):
        """Return True if all IPs are on same subnet as VIP on this VLAN."""
        for ipa in ips:
            if not self.ip_in_vip_subnet(ipa):
                return False
        return True

    def from_connected_to_vip(self, src_ip, dst_ip):
        """Return True if src_ip in connected network and dst_ip is a VIP.

        Args:
            src_ip (ipaddress.ip_address): source IP.
            dst_ip (ipaddress.ip_address): destination IP
        Returns:
            True if local traffic for a VIP.
        """
        if self.is_faucet_vip(dst_ip) and self.ip_in_vip_subnet(src_ip):
            return True
        return False
