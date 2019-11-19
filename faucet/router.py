"""Configure routing between VLANs."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
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

import pytricia

from faucet.conf import Conf, test_config_condition


class _PyTricia(pytricia.PyTricia):
    def __repr__(self):
        return str([(k, self[k]) for k in sorted(self.keys())])


class Router(Conf):
    """Implement FAUCET configuration for a router."""

    defaults = {
        'bgp': {},
        'vlans': None,
    }

    defaults_types = {
        'bgp': dict,
        'vlans': list,
    }

    ipaddress_fields = ('neighbor_addresses', 'server_addresses')

    bgp_defaults_types = {
        'as': int,
        'connect_mode': str,
        'neighbor_addresses': list,
        'neighbor_as': int,
        'port': int,
        'routerid': str,
        'server_addresses': list,
        'vlan': (str, int),
    }

    def __init__(self, _id, dp_id, conf):
        self.bgp = {}
        self.vlans = []
        self.vip_map_by_ipv = {}
        super(Router, self).__init__(_id, dp_id, conf)

    def _sub_conf_val(self, sub_conf, key):
        try:
            return self.__dict__[sub_conf][key]
        except KeyError:
            return None

    def _bgp_val(self, key):
        return self._sub_conf_val('bgp', key)

    def __str__(self):
        return str(self._id)

    def set_defaults(self, defaults=None, conf=None):
        super(Router, self).set_defaults(defaults=defaults, conf=conf)

    def check_config(self):
        super(Router, self).check_config()
        if self.bgp:
            self._check_conf_types(self.bgp, self.bgp_defaults_types)
            self.bgp = self._set_unknown_conf(self.bgp, self.bgp_defaults_types)
            if not self.bgp_connect_mode():
                self.bgp['connect_mode'] = 'passive'
            for field in self.ipaddress_fields:
                if field in self.bgp:
                    self.bgp[field] = frozenset([
                        self._check_ip_str(ip_str) for ip_str in self.bgp[field]])
            for accessor_val, required_field in (
                    (self.bgp_ipvs(), 'server_addresses'),
                    (self.bgp_as(), 'as'),
                    (self.bgp_port(), 'port'),
                    (self.bgp_connect_mode(), 'connect_mode'),
                    (self.bgp_routerid(), 'routerid'),
                    (self.bgp_neighbor_addresses(), 'neighbor_addresses'),
                    (self.bgp_neighbor_as(), 'neighbor_as')):
                test_config_condition(not accessor_val, 'BGP %s must be specified' % required_field)
            test_config_condition(
                self.bgp_connect_mode() != 'passive', 'BGP connect_mode must be passive')
            for ipv in self.bgp_ipvs():
                test_config_condition(
                    len(self.bgp_server_addresses_by_ipv(ipv)) != 1,
                    'Only one BGP server address per IP version supported')
            if not self.bgp_vlan():
                test_config_condition(
                    len(self.vlans) != 1,
                    'If routing more than one VLAN, must specify BGP VLAN')
                self.set_bgp_vlan(self.vlans[0])
        else:
            test_config_condition(
                not self.vlans, 'A router must have least one VLAN specified at top level')

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
                    self.vip_map_by_ipv[ipv] = _PyTricia(
                        faucet_vip.ip.max_prefixlen)
                self.vip_map_by_ipv[ipv][faucet_vip.network] = (
                    vlan, faucet_vip)
        super(Router, self).finalize()

    def bgp_as(self):
        """Return BGP AS."""
        return self._bgp_val('as')

    def bgp_connect_mode(self):
        """Return BGP connect mode."""
        return self._bgp_val('connect_mode')

    def bgp_neighbor_addresses(self):
        """Return BGP neighbor addresses."""
        return self._bgp_val('neighbor_addresses')

    def bgp_neighbor_as(self):
        """Return BGP neighbor AS number."""
        return self._bgp_val('neighbor_as')

    def bgp_port(self):
        """Return BGP port."""
        return self._bgp_val('port')

    def bgp_routerid(self):
        """Return BGP router ID."""
        return self._bgp_val('routerid')

    def bgp_server_addresses(self):
        """Return BGP server addresses."""
        return self._bgp_val('server_addresses')

    def bgp_vlan(self):
        """Return BGP VLAN."""
        return self._bgp_val('vlan')

    def set_bgp_vlan(self, vlan):
        """Set BGP VLAN."""
        if self.bgp:
            self.bgp['vlan'] = vlan

    def bgp_ipvs(self):
        """Return list of IP versions for BGP configured on this VLAN."""
        return self._ipvs(self.bgp_server_addresses())

    def bgp_neighbor_addresses_by_ipv(self, ipv):
        """Return BGP neighbor addresses with specified IP version on this VLAN."""
        return self._by_ipv(self.bgp_neighbor_addresses(), ipv)

    def bgp_server_addresses_by_ipv(self, ipv):
        """Return BGP server addresses with specified IP version on this VLAN."""
        return self._by_ipv(self.bgp_server_addresses(), ipv)
