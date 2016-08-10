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
    ipv4_routes = None
    ipv6_routes = None
    arp_cache = None
    nd_cache = None
    host_cache = None

    defaults = {
        'name': None,
        'description': None,
        'controller_ips': None,
        'unicast_flood': True,
        'bgp_as': 0,
        'bgp_port': 9179,
        'bgp_routerid': '',
        'bgp_neighbour_address': '',
        'bgp_neighbor_address': None,
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
        self.ipv4_routes = {}
        self.ipv6_routes = {}
        self.arp_cache = {}
        self.nd_cache = {}
        self.host_cache = {}

        if self.controller_ips:
            self.controller_ips = [
                ipaddr.IPNetwork(ip) for ip in self.controller_ips]

        if self.bgp_as:
            assert self.bgp_port
            assert ipaddr.IPv4Address(self.bgp_routerid)
            assert ipaddr.IPAddress(self.bgp_neighbor_address)
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

    def set_defaults(self):
        for key, value in self.defaults.iteritems():
            self._set_default(key, value)
        self._set_default('vid', self._id)
        self._set_default('name', str(self._id))
        self._set_default('controller_ips', [])
        self._set_default('bgp_neighbor_as', self.bgp_neighbour_as)
        self._set_default('bgp_neighbor_address', self.bgp_neighbour_address)

    def __str__(self):
        port_list = [str(x) for x in self.get_ports()]
        ports = ','.join(port_list)
        return 'vid:%s ports:%s' % (self.vid, ports)

    def get_ports(self):
        return self.tagged + self.untagged

    def contains_port(self, port_number):
        for port in self.get_ports():
            if port.number == port_number:
                return True
        return False

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
