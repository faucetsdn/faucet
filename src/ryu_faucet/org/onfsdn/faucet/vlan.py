# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
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

import ipaddr

from conf import Conf

class VLAN(Conf):

    tagged = None
    untagged = None
    vid = None
    controller_ips = None
    bgp_as = None
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
        'controller_ips': None,
        'unicast_flood': True,
        'bgp_as': 0,
        'bgp_port': 9179,
        'bgp_routerid': '',
        'bgp_neighbour_addresses': [],
        'bgp_neighbor_addresses': [],
        'bgp_neighbour_as': 0,
        'bgp_neighbor_as': None,
        'routes': None,
        'max_hosts': None,
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
        self.dyn_ipv4_routes = {}
        self.dyn_ipv6_routes = {}
        self.dyn_arp_cache = {}
        self.dyn_nd_cache = {}
        self.dyn_host_cache = {}

        if self.controller_ips:
            self.controller_ips = [
                ipaddr.IPNetwork(ip) for ip in self.controller_ips]

        if self.bgp_as:
            assert self.bgp_port
            assert ipaddr.IPv4Address(self.bgp_routerid)
            for neighbor_ip in self.bgp_neighbor_addresses:
                assert ipaddr.IPAddress(neighbor_ip)
            assert self.bgp_neighbor_as

        if self.routes:
            self.routes = [route['route'] for route in self.routes]
            for route in self.routes:
                ip_gw = ipaddr.IPAddress(route['ip_gw'])
                ip_dst = ipaddr.IPNetwork(route['ip_dst'])
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
        for key, value in self.defaults.iteritems():
            self._set_default(key, value)
        self._set_default('vid', self._id)
        self._set_default('name', str(self._id))
        self._set_default('controller_ips', [])
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

    def ip_in_controller_subnet(self, ip):
        for controller_ip in self.controller_ips:
            if ip in controller_ip:
                return True
        return False

    def __hash__(self):
        items = [(k,v) for k,v in self.__dict__.iteritems() if 'dyn' not in k]
        return hash(frozenset(map(str, items)))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not self.__eq__(other)
