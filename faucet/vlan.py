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

from faucet.conf import Conf
from faucet.valve_util import btos
from faucet import valve_of


FAUCET_MAC = '0e:00:00:00:00:01'


class HostCacheEntry(object):

    def __init__(self, eth_src, port, cache_time):
        self.eth_src = eth_src
        self.port = port
        self.cache_time = cache_time
        self.expired = False


class VLAN(Conf):
    """Implement FAUCET configuration for a VLAN."""

    name = None
    tagged = None
    untagged = None
    vid = None
    faucet_vips = None
    faucet_mac = None
    bgp_as = None
    bgp_local_address = None
    bgp_server_addresses = []
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
    proactive_arp_limit = None
    proactive_nd_limit = None
    # Define dynamic variables with prefix dyn_ to distinguish from variables set
    # configuration
    dyn_host_cache = None
    dyn_faucet_vips_by_ipv = None
    dyn_routes_by_ipv = None
    dyn_neigh_cache_by_ipv = None
    dyn_learn_ban_count = 0

    defaults = {
        'name': None,
        'description': None,
        'acl_in': None,
        'faucet_vips': None,
        'faucet_mac': FAUCET_MAC,
        # set MAC for FAUCET VIPs on this VLAN
        'unicast_flood': True,
        'bgp_as': None,
        'bgp_local_address': None,
        'bgp_port': 9179,
        'bgp_server_addresses': ['0.0.0.0', '::'],
        'bgp_routerid': None,
        'bgp_neighbour_addresses': [],
        'bgp_neighbor_addresses': [],
        'bgp_neighbour_as': None,
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

    defaults_types = {
        'name': str,
        'description': str,
        'acl_in': (int, str),
        'faucet_vips': list,
        'faucet_mac': str,
        'unicast_flood': bool,
        'bgp_as': int,
        'bgp_local_address': str,
        'bgp_port': int,
        'bgp_server_addresses': list,
        'bgp_routerid': str,
        'bgp_neighbour_addresses': list,
        'bgp_neighbor_addresses': list,
        'bgp_neighbour_as': int,
        'bgp_neighbor_as': int,
        'routes': list,
        'max_hosts': int,
        'vid': int,
        'proactive_arp_limit': int,
        'proactive_nd_limit': int,
    }

    def __init__(self, _id, dp_id, conf=None):
        super(VLAN, self).__init__(_id, conf)
        self.dp_id = dp_id
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

    def reset_host_cache(self):
        self.dyn_host_cache = {}

    def add_tagged(self, port):
        self.tagged.append(port)

    def add_untagged(self, port):
        self.untagged.append(port)

    def add_cache_host(self, eth_src, port, cache_time):
        self.dyn_host_cache[eth_src] = HostCacheEntry(
            eth_src, port, cache_time)

    def cached_hosts_on_port(self, port):
        """Return all hosts learned on a port."""
        return [entry for entry in list(self.dyn_host_cache.values()) if port.number == entry.port.number]

    def cached_host(self, eth_src):
        if eth_src in self.dyn_host_cache:
            return self.dyn_host_cache[eth_src]
        return None

    def cached_host_on_port(self, eth_src, port):
        """Return host cache entry if host in cache and on specified port."""
        entry = self.cached_host(eth_src)
        if entry and port == entry.port:
            return entry
        return None

    def clear_cache_hosts_on_port(self, port):
        """Clear all hosts learned on a port."""
        for entry in self.cached_hosts_on_port(port):
            del self.dyn_host_cache[entry.eth_src]

    def expire_cache_hosts(self, now, learn_timeout):
        """Expire stale host entries."""
        min_cache_time = now - learn_timeout

        def entry_expired(entry):
            return (not entry.port.permanent_learn and (
                entry.cache_time < min_cache_time or entry.expired))

        expired_hosts = [
            entry.eth_src for entry in list(self.host_cache.values()) if entry_expired(entry)]
        if expired_hosts:
            for eth_src in expired_hosts:
                del self.host_cache[eth_src]
        return expired_hosts

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

    def hosts_count(self):
        """Return number of hosts learned on this VLAN."""
        return len(self.host_cache)

    @host_cache.setter
    def host_cache(self, value):
        self.dyn_host_cache = value

    def set_defaults(self):
        super(VLAN, self).set_defaults()
        self._set_default('vid', self._id)
        self._set_default('name', str(self._id))
        self._set_default('faucet_vips', [])
        self._set_default('bgp_neighbor_as', self.bgp_neighbour_as)
        self._set_default(
            'bgp_neighbor_addresses', self.bgp_neighbour_addresses)

    def __str__(self):
        port_list = [str(x) for x in self.get_ports()]
        ports = ','.join(port_list)
        return 'VLAN %s vid:%s ports:%s' % (self.name, self.vid, ports)

    def __repr__(self):
        return self.__str__()

    def get_ports(self):
        """Return list of all ports on this VLAN."""
        return list(self.tagged) + list(self.untagged)

    def hairpin_ports(self):
        """Return all ports with hairpin enabled."""
        return [port for port in self.get_ports() if port.hairpin]

    def mirrored_ports(self):
        """Return list of ports that are mirrored on this VLAN."""
        return [port for port in self.get_ports() if port.mirror]

    def mirror_destination_ports(self):
        """Return list of ports that are mirrored to, on this VLAN."""
        return [port for port in self.get_ports() if port.mirror_destination]

    def lags(self):
        """Return dict of LAGs mapped to member ports."""
        lacp_ports = [port for port in self.get_ports() if port.lacp]
        lags = collections.defaultdict(list)
        for port in lacp_ports:
            lags[port.lacp].append(port)
        return lags

    def flood_ports(self, configured_ports, exclude_unicast):
        if exclude_unicast:
            return [port for port in configured_ports if port.unicast_flood]
        return configured_ports

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
                pkt = packet_builder(self, vid, *args)
                flood_ofmsgs = [valve_of.packetout(port.number, pkt.data) for port in ports if port.running()]
                ofmsgs.extend(flood_ofmsgs)
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
        """Return faucet_vip if IP in same IP network as a VIP on this VLAN."""
        for faucet_vip in self.faucet_vips_by_ipv(ipa.version):
            if ipa in faucet_vip.network:
                if ipa not in (
                        faucet_vip.network.network_address,
                        faucet_vip.network.broadcast_address):
                    return faucet_vip
        return None

    def ips_in_vip_subnet(self, ips):
        """Return True if all IPs are on same subnet as VIP on this VLAN."""
        for ipa in ips:
            if self.ip_in_vip_subnet(ipa) is None:
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
