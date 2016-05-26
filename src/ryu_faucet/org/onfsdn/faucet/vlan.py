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


class VLAN(object):

    vid = None
    tagged = None
    untagged = None

    def __init__(self, vid, conf=None):
        if conf is None:
            conf = {}
        self.vid = vid
        self.tagged = []
        self.untagged = []
        self.name = conf.setdefault('name', str(vid))
        self.description = conf.setdefault('description', self.name)
        self.controller_ips = conf.setdefault('controller_ips', [])
        if self.controller_ips:
            self.controller_ips = [
                ipaddr.IPNetwork(ip) for ip in self.controller_ips]
        self.unicast_flood = conf.setdefault('unicast_flood', True)
        self.routes = conf.setdefault('routes', {})
        self.ipv4_routes = {}
        self.ipv6_routes = {}
        if self.routes:
            self.routes = [route['route'] for route in self.routes]
            for route in self.routes:
                ip_gw = ipaddr.IPAddress(route['ip_gw'])
                ip_dst = ipaddr.IPNetwork(route['ip_dst'])
                assert(ip_gw.version == ip_dst.version)
                if ip_gw.version == 4:
                    self.ipv4_routes[ip_dst] = ip_gw
                else:
                    self.ipv6_routes[ip_dst] = ip_gw
        self.arp_cache = {}
        self.nd_cache = {}
        self.max_hosts = conf.setdefault('max_hosts', None)
        self.host_cache = {}

    def __str__(self):
        port_list = [str(x) for x in self.get_ports()]
        ports = ','.join(port_list)
        return 'vid:%s ports:%s' % (self.vid, ports)

    def get_ports(self):
        return self.tagged+self.untagged

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
