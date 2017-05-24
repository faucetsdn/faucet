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

import ipaddress

from conf import Conf
from valve_util import btos
import valve_util


class VLAN(Conf):

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
    dyn_ipv4_routes = None
    dyn_ipv6_routes = None
    dyn_arp_cache = None
    dyn_nd_cache = None
    dyn_host_cache = None

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
        valve_util.check_unknown_conf(conf, self.defaults)
        self.update(conf)
        self.set_defaults()
        self._id = _id
        self.tagged = []
        self.untagged = []
        self.dyn_ipv4_routes = {}
        self.dyn_ipv6_routes = {}
        self.dyn_arp_cache = {}
        self.dyn_nd_cache = {}
        self.dyn_host_cache = {}

        if self.faucet_vips:
            self.faucet_vips = [
                ipaddress.ip_interface(btos(ip)) for ip in self.faucet_vips]

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
                if ip_gw.version == 4:
                    self.ipv4_routes[ip_dst] = ip_gw
                else:
                    self.ipv6_routes[ip_dst] = ip_gw

    @property
    def ipv4_routes(self):
        return self.dyn_ipv4_routes

    @ipv4_routes.setter
    def ipv4_routes(self, value):
        self.dyn_ipv4_routes = value

    @property
    def ipv6_routes(self):
        return self.dyn_ipv6_routes

    @ipv6_routes.setter
    def ipv6_routes(self, value):
        self.dyn_ipv6_routes = value

    @property
    def arp_cache(self):
        return self.dyn_arp_cache

    @arp_cache.setter
    def arp_cache(self, value):
        self.dyn_arp_cache = value

    @property
    def nd_cache(self):
        return self.dyn_nd_cache

    @nd_cache.setter
    def nd_cache(self, value):
        self.dyn_nd_cache = value

    @property
    def host_cache(self):
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
        return self.tagged + self.untagged

    def mirrored_ports(self):
        return [port for port in self.get_ports() if port.mirror]

    def mirror_destination_ports(self):
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

    def port_is_tagged(self, port_number):
        for port in self.tagged:
            if port.number == port_number:
                return True
        return False

    def port_is_untagged(self, port_number):
        for port in self.untagged:
            if port.number == port_number:
                return True
        return False

    def is_faucet_vip(self, ip):
        for faucet_vip in self.faucet_vips:
            if ip == faucet_vip.ip:
                return True
        return False

    def ip_in_vip_subnet(self, ip):
        for faucet_vip in self.faucet_vips:
            if ip in faucet_vip.network:
                return True
        return False

    def ips_in_vip_subnet(self, ips):
        for ip in ips:
            if not self.ip_in_vip_subnet(ip):
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

    def to_conf(self):
        return self._to_conf()

    def __hash__(self):
        items = [(k, v) for k, v in list(self.__dict__.items()) if 'dyn' not in k]
        return hash(frozenset(list(map(str, items))))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not self.__eq__(other)
