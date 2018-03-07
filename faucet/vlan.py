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
import netaddr

from faucet import valve_of
from faucet.conf import Conf
from faucet.valve_util import btos
from faucet.valve_packet import FAUCET_MAC


class HostCacheEntry(object):
    """Association of a host with a port."""

    def __init__(self, eth_src, port, cache_time):
        self.eth_src = eth_src
        self.port = port
        self.cache_time = cache_time
        self.eth_src_int = int(eth_src.replace(':', ''), 16)

    def __hash__(self):
        return hash((self.eth_src_int, self.port.number))

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __lt__(self, other):
        return self.__hash__() < other.__hash__()


class VLAN(Conf):
    """Contains state for one VLAN, including its configuration."""

# Note: while vlans are configured once for each datapath, there will be a
# separate vlan object created for each datapath that the vlan appears on

    name = None
    dp_id = None
    tagged = None
    untagged = None
    vid = None
    faucet_vips = None
    faucet_mac = None
    bgp_as = None
    bgp_connect_mode = None
    bgp_local_address = None
    bgp_server_addresses = [] # type: list
    bgp_port = None
    bgp_routerid = None
    bgp_neighbor_addresses = [] # type: list
    bgp_neighbour_addresses = [] # type: list
    bgp_neighbor_as = None
    bgp_neighbour_as = None
    routes = None
    max_hosts = None
    unicast_flood = None
    acl_in = None
    acls_in = None
    targeted_gw_resolution = None
    proactive_arp_limit = None
    proactive_nd_limit = None
    # Define dynamic variables with prefix dyn_ to distinguish from variables set
    # configuration
    dyn_host_cache = None
    dyn_host_cache_by_port = None
    dyn_faucet_vips_by_ipv = None
    dyn_routes_by_ipv = None
    dyn_gws_by_ipv = None
    dyn_neigh_cache_by_ipv = None
    dyn_learn_ban_count = 0
    dyn_last_time_hosts_expired = None
    dyn_oldest_host_time = None

    defaults = {
        'name': None,
        'description': None,
        'acl_in': None,
        'acls_in': None,
        'faucet_vips': None,
        'faucet_mac': FAUCET_MAC,
        # set MAC for FAUCET VIPs on this VLAN
        'unicast_flood': True,
        'bgp_as': None,
        'bgp_connect_mode': 'both',
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
        'targeted_gw_resolution': False,
        # If True, and a gateway has been resolved, target the first re-resolution attempt to the same port rather than flooding.
        'minimum_ip_size_check': True,
        # If False, don't check that IP packets have a payload (must be False for OVS trace/tutorial to work)
        }

    defaults_types = {
        'name': str,
        'description': str,
        'acl_in': (int, str),
        'acls_in': list,
        'faucet_vips': list,
        'faucet_mac': str,
        'unicast_flood': bool,
        'bgp_as': int,
        'bgp_connect_mode': str,
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
        'targeted_gw_resolution': bool,
        'minimum_ip_size_check': bool,
    }

    def __init__(self, _id, dp_id, conf=None):
        self.tagged = []
        self.untagged = []
        self.dyn_faucet_vips_by_ipv = collections.defaultdict(list)
        self.dyn_routes_by_ipv = collections.defaultdict(dict)
        self.dyn_gws_by_ipv = collections.defaultdict(dict)
        self.dyn_ipvs = []
        self.reset_caches()
        super(VLAN, self).__init__(_id, dp_id, conf)

    def set_defaults(self):
        super(VLAN, self).set_defaults()
        self._set_default('vid', self._id)
        self._set_default('name', str(self._id))
        self._set_default('faucet_vips', [])
        self._set_default('bgp_neighbor_as', self.bgp_neighbour_as)
        self._set_default(
            'bgp_neighbor_addresses', self.bgp_neighbour_addresses)

    @staticmethod
    def _vid_valid(vid):
        """Return True if VID valid."""
        if isinstance(vid, int) and vid >= valve_of.MIN_VID and vid <= valve_of.MAX_VID:
            return True
        return False

    def check_config(self):
        super(VLAN, self).check_config()
        assert self.vid_valid(self.vid), 'invalid VID %s' % self.vid
        assert netaddr.valid_mac(self.faucet_mac), 'invalid MAC address %s' % self.faucet_mac

        if self.faucet_vips:
            try:
                self.faucet_vips = [
                    ipaddress.ip_interface(btos(ip)) for ip in self.faucet_vips]
            except (ValueError, AttributeError, TypeError) as err:
                assert False, 'Invalid IP address in faucet_vips: %s' % err
            for faucet_vip in self.faucet_vips:
                self.dyn_faucet_vips_by_ipv[faucet_vip.version].append(
                    faucet_vip)
            self.dyn_ipvs = list(self.dyn_faucet_vips_by_ipv.keys())

        if self.bgp_as:
            assert self.bgp_port
            assert self.bgp_connect_mode in ('active', 'passive', 'both')
            assert ipaddress.IPv4Address(btos(self.bgp_routerid))
            assert self.bgp_neighbor_as
            assert self.bgp_neighbor_addresses
            neighbor_ips = [ipaddress.ip_address(btos(ip)) for ip in self.bgp_neighbor_addresses]
            assert len(neighbor_ips) == len(self.bgp_neighbor_addresses)
            peer_versions = [ip.version for ip in neighbor_ips]
            assert len(peer_versions) == 1 or self.bgp_connect_mode == 'active', (
                'if using multiple address families bgp_connect_mode must be active')

        if self.routes:
            try:
                self.routes = [route['route'] for route in self.routes]
                for route in self.routes:
                    try:
                        ip_gw = ipaddress.ip_address(btos(route['ip_gw']))
                        ip_dst = ipaddress.ip_network(btos(route['ip_dst']))
                    except (ValueError, AttributeError, TypeError) as err:
                        assert False, 'Invalid IP address in route: %s' % err
                    assert ip_gw.version == ip_dst.version
                    self.add_route(ip_dst, ip_gw)
            except KeyError:
                assert False, 'missing route config'
            except TypeError:
                assert False, '%s is not a valid routes value' % self.routes
        if self.acl_in and self.acls_in:
            assert False, 'found both acl_in and acls_in, use only acls_in'
        if self.acl_in and not isinstance(self.acl_in, list):
            self.acls_in = [self.acl_in,]
            self.acl_in = None
        if self.acls_in:
            for acl in self.acls_in:
                assert isinstance(acl, (int, str)), 'acl names must be int or str'

    @staticmethod
    def vid_valid(vid):
        """Return True if VID valid."""
        if isinstance(vid, int) and vid >= valve_of.MIN_VID and vid <= valve_of.MAX_VID:
            return True
        return False

    def reset_caches(self):
        self.dyn_host_cache = {}
        self.dyn_host_cache_by_port = {}
        self.dyn_neigh_cache_by_ipv = collections.defaultdict(dict)

    def reset_ports(self, ports):
        self.tagged = [port for port in ports if self in port.tagged_vlans]
        self.untagged = [port for port in ports if self == port.native_vlan]

    def add_cache_host(self, eth_src, port, cache_time):
        existing_entry = self.cached_host(eth_src)
        if existing_entry is not None:
            self.dyn_host_cache_by_port[existing_entry.port.number].remove(
                existing_entry)
        entry = HostCacheEntry(eth_src, port, cache_time)
        if port.number not in self.dyn_host_cache_by_port:
            self.dyn_host_cache_by_port[port.number] = set()
        self.dyn_host_cache_by_port[port.number].add(entry)
        self.dyn_host_cache[eth_src] = entry

    def expire_cache_host(self, eth_src):
        entry = self.cached_host(eth_src)
        if entry is not None:
            self.dyn_host_cache_by_port[entry.port.number].remove(entry)
            del self.dyn_host_cache[eth_src]

    def cached_hosts_on_port(self, port):
        """Return all hosts learned on a port."""
        if port.number in self.dyn_host_cache_by_port:
            return list(self.dyn_host_cache_by_port[port.number])
        return []

    def cached_hosts_count_on_port(self, port):
        """Return count of all hosts learned on a port."""
        hosts_count = 0
        if port.number in self.dyn_host_cache_by_port:
            hosts_count = len(self.dyn_host_cache_by_port[port.number])
        return hosts_count

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
            self.expire_cache_host(entry.eth_src)

    def expire_cache_hosts(self, now, learn_timeout):
        """Expire stale host entries."""
        expired_hosts = []

        if self.dyn_oldest_host_time is None or now - self.dyn_oldest_host_time > learn_timeout:
            min_cache_time = now - learn_timeout
            self.dyn_oldest_host_time = now
            for entry in list(self.dyn_host_cache.values()):
                if (not entry.port.permanent_learn and entry.cache_time < min_cache_time):
                    expired_hosts.append(entry.eth_src)
                else:
                    self.dyn_oldest_host_time = min(entry.cache_time, self.dyn_oldest_host_time)
            for eth_src in expired_hosts:
                self.expire_cache_host(eth_src)
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

    def route_count_by_ipv(self, ipv):
        """Return route table count for specified IP version on this VLAN."""
        return len(self.dyn_routes_by_ipv[ipv])

    def add_route(self, ip_dst, ip_gw):
        """Add an IP route."""
        self.dyn_routes_by_ipv[ip_gw.version][ip_dst] = ip_gw
        if ip_gw not in self.dyn_gws_by_ipv[ip_gw.version]:
            self.dyn_gws_by_ipv[ip_gw.version][ip_gw] = set()
        self.dyn_gws_by_ipv[ip_gw.version][ip_gw].add(ip_dst)

    def del_route(self, ip_dst):
        """Delete an IP route."""
        ip_gw = self.dyn_routes_by_ipv[ip_dst.version][ip_dst]
        del self.dyn_routes_by_ipv[ip_dst.version][ip_dst]
        self.dyn_gws_by_ipv[ip_gw.version][ip_gw].remove(ip_dst)
        if not self.dyn_gws_by_ipv[ip_gw.version][ip_gw]:
            del self.dyn_gws_by_ipv[ip_gw.version][ip_gw]

    def ip_dsts_for_ip_gw(self, ip_gw):
        """Return list of IP destinations, for specified gateway."""
        if ip_gw in self.dyn_gws_by_ipv[ip_gw.version]:
            return list(self.dyn_gws_by_ipv[ip_gw.version][ip_gw])
        return []

    def all_ip_gws(self, ipv):
        """Return list of all IP gateways for specified IP version."""
        return list(self.dyn_gws_by_ipv[ipv].keys())

    def neigh_cache_by_ipv(self, ipv):
        """Return neighbor cache for specified IP version on this VLAN."""
        return self.dyn_neigh_cache_by_ipv[ipv]

    def neigh_cache_count_by_ipv(self, ipv):
        """Return number of hosts in neighbor cache for specified IP version on this VLAN."""
        return len(self.neigh_cache_by_ipv(ipv))

    def hosts_count(self):
        """Return number of hosts learned on this VLAN."""
        return len(self.dyn_host_cache)

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

    def output_port(self, port, hairpin=False):
        actions = port.mirror_actions()
        if self.port_is_untagged(port):
            actions.append(valve_of.pop_vlan())
        if hairpin:
            actions.append(valve_of.output_port(valve_of.OFP_IN_PORT))
        else:
            actions.append(valve_of.output_port(port.number))
        return actions

    def pkt_out_port(self, packet_builder, port, *args):
        vid = None
        if self.port_is_tagged(port):
            vid = self.vid
        pkt = packet_builder(vid, *args)
        return valve_of.packetout(port.number, pkt.data)

    def flood_pkt(self, packet_builder, *args):
        ofmsgs = []
        for vid, ports in (
                (self.vid, self.tagged_flood_ports(False)),
                (None, self.untagged_flood_ports(False))):
            if ports:
                pkt = packet_builder(vid, *args)
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
