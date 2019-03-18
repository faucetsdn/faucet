"""Configure routing between VLANs."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
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

import pytricia

from faucet.conf import Conf, test_config_condition


class Router(Conf):
    """Implement FAUCET configuration for a router."""

    defaults = {
        'bgp_as': None,
        'bgp_connect_mode': 'passive',
        'bgp_port': 9179,
        'bgp_routerid': None,
        'bgp_neighbour_as': None,
        'bgp_neighbor_as': None,
        'bgp_server_addresses': ['0.0.0.0', '::'],
        'bgp_neighbour_addresses': [],
        'bgp_neighbor_addresses': [],
        'bgp_vlan': None,
        'vlans': None,
    }

    defaults_types = {
        'bgp_as': int,
        'bgp_connect_mode': str,
        'bgp_port': int,
        'bgp_routerid': str,
        'bgp_neighbour_as': int,
        'bgp_neighbor_as': int,
        'bgp_server_addresses': list,
        'bgp_neighbour_addresses': list,
        'bgp_neighbor_addresses': list,
        'bgp_vlan': (str, int),
        'vlans': list,
    }

    def __init__(self, _id, dp_id, conf):
        self.bgp_as = None
        self.bgp_connect_mode = None
        self.bgp_neighbor_as = None
        self.bgp_neighbour_as = None
        self.bgp_port = None
        self.bgp_routerid = None
        self.bgp_neighbour_addresses = []
        self.bgp_neighbor_addresses = []
        self.bgp_server_addresses = []
        self.bgp_vlan = None
        self.vlans = []
        self.vip_map_by_ipv = {}
        super(Router, self).__init__(_id, dp_id, conf)

    def __str__(self):
        return str(self._id)

    def set_defaults(self):
        super(Router, self).set_defaults()
        self._set_default('bgp_neighbor_as', self.bgp_neighbour_as)
        self._set_default('bgp_neighbor_addresses', self.bgp_neighbour_addresses)

    def check_config(self):
        super(Router, self).check_config()
        if self.bgp_neighbor_addresses or self.bgp_neighbour_addresses:
            neigh_addresses = frozenset(self.bgp_neighbor_addresses + self.bgp_neighbour_addresses)
            self.bgp_neighbor_addresses = frozenset([
                self._check_ip_str(ip_str) for ip_str in neigh_addresses])

        if self.bgp_server_addresses:
            self.bgp_server_addresses = frozenset([
                self._check_ip_str(ip_str) for ip_str in self.bgp_server_addresses])
            for ipv in self.bgp_ipvs():
                test_config_condition(
                    len(self.bgp_server_addresses_by_ipv(ipv)) != 1,
                    'Only one BGP server address per IP version supported')

    def vip_map(self, ipa):
        """Return VIP for IP address, if any."""
        if ipa.version in self.vip_map_by_ipv:
            result = self.vip_map_by_ipv[ipa.version].get(ipa)
            if result:
                return result
        return (None, None)

    def finalize(self):
        for vlan in self.vlans:
            for faucet_vip in vlan.faucet_vips:
                ipv = faucet_vip.version
                if ipv not in self.vip_map_by_ipv:
                    self.vip_map_by_ipv[ipv] = pytricia.PyTricia(
                        faucet_vip.ip.max_prefixlen)
                self.vip_map_by_ipv[ipv][faucet_vip.network] = (
                    vlan, faucet_vip)
        super(Router, self).finalize()

    def bgp_ipvs(self):
        """Return list of IP versions for BGP configured on this VLAN."""
        return self._ipvs(self.bgp_server_addresses)

    def bgp_neighbor_addresses_by_ipv(self, ipv):
        """Return BGP neighbor addresses with specified IP version on this VLAN."""
        return self._by_ipv(self.bgp_neighbor_addresses, ipv)

    def bgp_server_addresses_by_ipv(self, ipv):
        """Return BGP server addresses with specified IP version on this VLAN."""
        return self._by_ipv(self.bgp_server_addresses, ipv)

    def to_conf(self):
        result = super(Router, self).to_conf()
        if result is not None:
            if 'bgp_neighbor_as' in result:
                del result['bgp_neighbor_as']
            if self.bgp_neighbor_addresses:
                result['bgp_neighbor_addresses'] = [str(vip) for vip in self.bgp_neighbor_addresses]
            if self.bgp_server_addresses:
                result['bgp_server_addresses'] = [str(vip) for vip in self.bgp_server_addresses]
            if 'bgp_neighbor_addresses' in result:
                del result['bgp_neighbor_addresses']
        return result
