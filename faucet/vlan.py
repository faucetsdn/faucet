"""VLAN configuration."""

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

import collections
import ipaddress
import random
import netaddr

from faucet import valve_of
from faucet.conf import Conf, test_config_condition, InvalidConfigError
from faucet.valve_packet import FAUCET_MAC


class NullVLAN:
    """Placeholder null VLAN."""

    name = 'Null VLAN'
    vid = valve_of.ofp.OFPVID_NONE


# TODO: not well supported by any hardware, so not used.
class AnyVLAN:
    """Placeholder any tagged VLAN."""

    name = 'Any VLAN'
    vid = valve_of.ofp.OFPVID_PRESENT


class HostCacheEntry:
    """Association of a host with a port."""

    __slots__ = [
        'cache_time',
        'eth_src',
        'eth_src_int',
        'port',
    ]

    def __init__(self, eth_src, port, cache_time):
        self.eth_src = eth_src
        self.port = port
        self.cache_time = cache_time
        self.eth_src_int = int(eth_src.replace(':', ''), 16)

    def __hash__(self):
        return hash((self.eth_src_int, self.port.number))

    def __str__(self):
        return '%s on %s' % (self.eth_src, self.port)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __lt__(self, other):
        return self.__hash__() < other.__hash__()


class VLAN(Conf):
    """Contains state for one VLAN, including its configuration."""

# Note: while vlans are configured once for each datapath, there will be a
# separate vlan object created for each datapath that the vlan appears on

    mutable_attrs = frozenset(['tagged', 'untagged'])

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
        'bgp_connect_mode': 'passive',
        'bgp_local_address': None,
        'bgp_port': 9179,
        'bgp_server_addresses': ['0.0.0.0', '::'],
        'bgp_routerid': None,
        'bgp_neighbour_addresses': [],
        'bgp_neighbor_addresses': [],
        'bgp_neighbour_as': None,
        'bgp_neighbor_as': None,
        'routes': None,
        'max_hosts': 256,
        # Limit number of hosts that can be learned on a VLAN.
        'vid': None,
        'proactive_arp_limit': 0,
        # Don't proactively ARP for hosts if over this limit (default 2*max_hosts)
        'proactive_nd_limit': 0,
        # Don't proactively ND for hosts if over this limit (default 2*max_hosts)
        'targeted_gw_resolution': True,
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
        self.acl_in = None
        self.acls_in = None
        self.bgp_as = None
        self.bgp_connect_mode = None
        self.bgp_local_address = None
        self.bgp_neighbor_addresses = None
        self.bgp_neighbor_as = None
        self.bgp_neighbour_addresses = None
        self.bgp_neighbour_as = None
        self.bgp_port = None
        self.bgp_routerid = None
        self.bgp_server_addresses = None
        self.description = None
        self.dp_id = None
        self.faucet_mac = None
        self.faucet_vips = None
        self.max_hosts = None
        self.minimum_ip_size_check = None
        self.name = None
        self.proactive_arp_limit = None
        self.proactive_nd_limit = None
        self.routes = None
        self.tagged = None
        self.targeted_gw_resolution = None
        self.unicast_flood = None
        self.untagged = None
        self.vid = None

        self.acls = {}
        self.tagged = []
        self.untagged = []
        self.bgp_server_addresses = []
        self.bgp_neighbour_addresses = []
        self.bgp_neighbor_addresses = []

        self.dyn_host_cache = None
        self.dyn_host_cache_by_port = None
        self.dyn_host_cache_stats_stale = None
        self.dyn_last_time_hosts_expired = None
        self.dyn_learn_ban_count = 0
        self.dyn_neigh_cache_by_ipv = None
        self.dyn_oldest_host_time = None
        self.dyn_last_updated_metrics_sec = None

        self.dyn_routes_by_ipv = collections.defaultdict(dict)
        self.dyn_gws_by_ipv = collections.defaultdict(dict)
        self.dyn_host_gws_by_ipv = collections.defaultdict(set)
        self.dyn_route_gws_by_ipv = collections.defaultdict(set)
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
    def _check_ip_str(ip_str, ip_method=ipaddress.ip_address):
        try:
            return ip_method(ip_str)
        except (ValueError, AttributeError, TypeError) as err:
            raise InvalidConfigError('Invalid IP address %s: %s' % (ip_str, err))

    def check_config(self):
        super(VLAN, self).check_config()
        test_config_condition(not self.vid_valid(self.vid), 'invalid VID %s' % self.vid)
        test_config_condition(not netaddr.valid_mac(self.faucet_mac), (
            'invalid MAC address %s' % self.faucet_mac))

        test_config_condition(self.acl_in and self.acls_in, 'found both acl_in and acls_in, use only acls_in')
        if self.acl_in and not isinstance(self.acl_in, list):
            self.acls_in = [self.acl_in,]
            self.acl_in = None
        if self.acls_in:
            for acl in self.acls_in:
                test_config_condition(not isinstance(acl, (int, str)), 'acl names must be int or str')

        if self.max_hosts:
            if not self.proactive_arp_limit:
                self.proactive_arp_limit = 2 * self.max_hosts
            if not self.proactive_nd_limit:
                self.proactive_nd_limit = 2 * self.max_hosts

        if self.faucet_vips:
            self.faucet_vips = frozenset([
                self._check_ip_str(ip_str, ip_method=ipaddress.ip_interface) for ip_str in self.faucet_vips])

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

        if self.bgp_as:
            test_config_condition(not isinstance(self.bgp_port, int), (
                'BGP port must be %s not %s' % (int, type(self.bgp_port))))
            test_config_condition(self.bgp_connect_mode not in ('passive'), (
                'BGP connect mode %s must be passive' % self.bgp_connect_mode))
            test_config_condition(not ipaddress.IPv4Address(self.bgp_routerid), (
                '%s is not a valid IPv4 address' % (self.bgp_routerid)))
            test_config_condition(not self.bgp_neighbor_as, 'No BGP neighbor AS')
            test_config_condition(not self.bgp_neighbor_addresses, 'No BGP neighbor addresses')
            test_config_condition(len(self.bgp_neighbor_addresses) != len(self.bgp_neighbor_addresses), (
                'Must be as many BGP neighbor addresses as BGP server addresses'))

        if self.routes:
            test_config_condition(not isinstance(self.routes, list), 'invalid VLAN routes format')
            try:
                self.routes = [route['route'] for route in self.routes]
            except TypeError:
                raise InvalidConfigError('%s is not a valid routes value' % self.routes)
            except KeyError:
                pass
            for route in self.routes:
                test_config_condition(not isinstance(route, dict), 'invalid VLAN route format')
                test_config_condition('ip_gw' not in route, 'missing ip_gw in VLAN route')
                test_config_condition('ip_dst' not in route, 'missing ip_dst in VLAN route')
                ip_gw = self._check_ip_str(route['ip_gw'])
                ip_dst = self._check_ip_str(route['ip_dst'], ip_method=ipaddress.ip_network)
                test_config_condition(
                    ip_gw.version != ip_dst.version,
                    'ip_gw version does not match the ip_dst version')
                self.add_route(ip_dst, ip_gw)

    @staticmethod
    def vid_valid(vid):
        """Return True if VID valid."""
        if isinstance(vid, int) and vid >= valve_of.MIN_VID and vid <= valve_of.MAX_VID:
            return True
        return False

    def reset_caches(self):
        """Reset dynamic caches."""
        self.dyn_host_cache = {}
        self.dyn_host_cache_by_port = {}
        self.dyn_host_cache_stats_stale = {}
        self.dyn_neigh_cache_by_ipv = collections.defaultdict(dict)
        self.dyn_unresolved_route_ip_gws = collections.defaultdict(list)
        self.dyn_unresolved_host_ip_gws = collections.defaultdict(list)

    def reset_ports(self, ports):
        """Reset tagged and untagged port lists."""
        sorted_ports = sorted(ports, key=lambda i: i.number)
        self.tagged = tuple([port for port in sorted_ports if self in port.tagged_vlans])
        self.untagged = tuple([port for port in sorted_ports if self == port.native_vlan])

    def add_cache_host(self, eth_src, port, cache_time):
        """Add/update a host to the cache on a port at at time."""
        existing_entry = self.cached_host(eth_src)
        if existing_entry is None:
            self.dyn_host_cache_stats_stale[port.number] = True
        else:
            self.dyn_host_cache_by_port[existing_entry.port.number].remove(
                existing_entry)
        entry = HostCacheEntry(eth_src, port, cache_time)
        if port.number not in self.dyn_host_cache_by_port:
            self.dyn_host_cache_by_port[port.number] = set()
        self.dyn_host_cache_by_port[port.number].add(entry)
        self.dyn_host_cache[eth_src] = entry

    def expire_cache_host(self, eth_src):
        """Expire a host from caches."""
        entry = self.cached_host(eth_src)
        if entry is not None:
            self.dyn_host_cache_stats_stale[entry.port.number] = True
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
        """Return host from cache or None."""
        return self.dyn_host_cache.get(eth_src, None)

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
        min_cache_time = now - learn_timeout

        if self.dyn_oldest_host_time is None or self.dyn_oldest_host_time < min_cache_time:
            expired_hosts = [
                entry for entry in self.dyn_host_cache.values()
                if entry.cache_time < min_cache_time and not entry.port.permanent_learn]
            for entry in expired_hosts:
                self.expire_cache_host(entry.eth_src)
            self.dyn_oldest_host_time = now
            if self.dyn_host_cache:
                self.dyn_oldest_host_time = min(
                    [entry.cache_time for entry in self.dyn_host_cache.values()])
        return expired_hosts

    @staticmethod
    def _ipvs(ipas):
        return frozenset([ipa.version for ipa in ipas])

    @staticmethod
    def _by_ipv(ipas, ipv):
        return frozenset([ipa for ipa in ipas if ipa.version == ipv])

    def faucet_vips_by_ipv(self, ipv):
        """Return VIPs with specified IP version on this VLAN."""
        return self._by_ipv(self.faucet_vips, ipv)

    def link_and_other_vips(self, ipv):
        """Return link local and non-link local VIPs."""
        vips = self.faucet_vips_by_ipv(ipv)
        link_local_vips = frozenset([vip for vip in vips if vip.is_link_local])
        other_vips = vips - link_local_vips
        return (link_local_vips, other_vips)

    def bgp_neighbor_addresses_by_ipv(self, ipv):
        """Return BGP neighbor addresses with specified IP version on this VLAN."""
        return self._by_ipv(self.bgp_neighbor_addresses, ipv)

    def bgp_server_addresses_by_ipv(self, ipv):
        """Return BGP server addresses with specified IP version on this VLAN."""
        return self._by_ipv(self.bgp_server_addresses, ipv)

    def ipvs(self):
        """Return IP versions configured on this VLAN."""
        return self._ipvs(self.faucet_vips)

    def bgp_ipvs(self):
        """Return list of IP versions for BGP configured on this VLAN."""
        return self._ipvs(self.bgp_server_addresses)

    def routes_by_ipv(self, ipv):
        """Return route table for specified IP version on this VLAN."""
        return self.dyn_routes_by_ipv[ipv]

    def route_count_by_ipv(self, ipv):
        """Return route table count for specified IP version on this VLAN."""
        return len(self.dyn_routes_by_ipv[ipv])

    def is_host_fib_route(self, host_ip):
        """Return True if IP destination is a host FIB route.

        Args:
            host_ip: (ipaddress.ip_address): potential host FIB route.
        Returns:
            True if a host FIB route (and not used as a gateway).
        """
        ip_dsts = self.ip_dsts_for_ip_gw(host_ip)
        if (len(ip_dsts) == 1 and
                ip_dsts[0].prefixlen == ip_dsts[0].max_prefixlen and
                ip_dsts[0].network_address == host_ip):
            return True
        return False

    def _update_gw_types(self, ip_gw):
        if self.is_host_fib_route(ip_gw):
            self.dyn_host_gws_by_ipv[ip_gw.version].add(ip_gw)
            self.dyn_route_gws_by_ipv[ip_gw.version] -= set([ip_gw])
        else:
            self.dyn_route_gws_by_ipv[ip_gw.version].add(ip_gw)
            self.dyn_host_gws_by_ipv[ip_gw.version] -= set([ip_gw])

    def add_route(self, ip_dst, ip_gw):
        """Add an IP route."""
        self.dyn_routes_by_ipv[ip_gw.version][ip_dst] = ip_gw
        if ip_gw not in self.dyn_gws_by_ipv[ip_gw.version]:
            self.dyn_gws_by_ipv[ip_gw.version][ip_gw] = set()
        self.dyn_gws_by_ipv[ip_gw.version][ip_gw].add(ip_dst)
        self._update_gw_types(ip_gw)

    def del_route(self, ip_dst):
        """Delete an IP route."""
        ip_gw = self.dyn_routes_by_ipv[ip_dst.version][ip_dst]
        del self.dyn_routes_by_ipv[ip_dst.version][ip_dst]
        self.dyn_gws_by_ipv[ip_gw.version][ip_gw].remove(ip_dst)
        if not self.dyn_gws_by_ipv[ip_gw.version][ip_gw]:
            del self.dyn_gws_by_ipv[ip_gw.version][ip_gw]
        self._update_gw_types(ip_gw)

    def ip_dsts_for_ip_gw(self, ip_gw):
        """Return list of IP destinations, for specified gateway."""
        if ip_gw in self.dyn_gws_by_ipv[ip_gw.version]:
            return list(self.dyn_gws_by_ipv[ip_gw.version][ip_gw])
        return []

    def all_ip_gws(self, ipv):
        """Return all IP gateways for specified IP version."""
        return frozenset(self.dyn_gws_by_ipv[ipv].keys())

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
        str_ports = []
        if self.tagged:
            str_ports.append('tagged: %s' % ','.join([str(p) for p in self.tagged]))
        if self.untagged:
            str_ports.append('untagged: %s' % ','.join([str(p) for p in self.untagged]))
        return 'VLAN %s vid:%s %s' % (self.name, self.vid, ' '.join(str_ports))

    def __repr__(self):
        return self.__str__()

    def get_ports(self):
        """Return all ports on this VLAN."""
        return self.tagged + self.untagged

    def hairpin_ports(self):
        """Return all ports with hairpin enabled."""
        return tuple([port for port in self.get_ports() if port.hairpin])

    def mirrored_ports(self):
        """Return ports that are mirrored on this VLAN."""
        return tuple([port for port in self.get_ports() if port.mirror])

    def lacp_ports(self):
        """Return ports that have LACP on this VLAN."""
        return tuple([port for port in self.get_ports() if port.lacp])

    def lacp_up_ports(self):
        """Return ports that have LACP up on this VLAN."""
        return tuple([port for port in self.lacp_ports() if port.dyn_lacp_up])

    def lags(self):
        """Return dict of LAGs mapped to member ports."""
        lags = collections.defaultdict(list)
        for port in self.lacp_ports():
            lags[port.lacp].append(port)
        return lags

    def lags_up(self):
        """Return dict of LAGs mapped to member ports that have LACP up."""
        lags = collections.defaultdict(list)
        for port in self.lacp_up_ports():
            lags[port.lacp].append(port)
        return lags

    def exclude_same_lag_member_ports(self, in_port=None):
        """Ensure output on only one member of a LAG."""
        exclude_ports = set()
        lags = self.lags()
        if lags:
            lags_up = self.lags_up()
            if in_port is not None and in_port.lacp:
                # Don't flood from one LACP bundle member, to another.
                exclude_ports.update(lags[in_port.lacp])
            # Pick one up bundle member to flood to.
            for lag, ports in lags.items():
                ports_up = lags_up[lag]
                if ports_up:
                    exclude_ports.update(ports[1:])
                else:
                    exclude_ports.update(ports)
        return exclude_ports

    @staticmethod
    def flood_ports(configured_ports, exclude_unicast):
        if exclude_unicast:
            return tuple([port for port in configured_ports if port.unicast_flood])
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

    def flood_pkt(self, packet_builder, multi_out=True, *args):
        ofmsgs = []
        for vid, ports in (
                (self.vid, self.tagged_flood_ports(False)),
                (None, self.untagged_flood_ports(False))):
            if ports:
                pkt = packet_builder(vid, *args)
                exclude_ports = self.exclude_same_lag_member_ports()
                running_ports = [
                    port for port in ports if port.running() and port not in exclude_ports]
                random.shuffle(running_ports)
                if multi_out:
                    ofmsgs.append(valve_of.packetouts(
                        [port.number for port in running_ports], pkt.data))
                else:
                    ofmsgs.extend(
                        [valve_of.packetout(port.number, pkt.data)
                         for port in running_ports])
        return ofmsgs

    def port_is_tagged(self, port):
        """Return True if port number is an tagged port on this VLAN."""
        return port in self.tagged

    def port_is_untagged(self, port):
        """Return True if port number is an untagged port on this VLAN."""
        return port in self.untagged

    def vip_map(self, ipa):
        for faucet_vip in self.faucet_vips:
            if ipa in faucet_vip.network:
                return faucet_vip
        return None

    def is_faucet_vip(self, ipa, faucet_vip=None):
        """Return True if IP is a VIP on this VLAN."""
        if faucet_vip is None:
            faucet_vip = self.vip_map(ipa)
        return faucet_vip and ipa == faucet_vip.ip

    def ip_in_vip_subnet(self, ipa, faucet_vip=None):
        """Return faucet_vip if IP in same IP network as a VIP on this VLAN."""
        if faucet_vip is None:
            faucet_vip = self.vip_map(ipa)
        if faucet_vip:
            if ipa not in (
                    faucet_vip.network.network_address,
                    faucet_vip.network.broadcast_address):
                return faucet_vip
        return None

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
        result = super(VLAN, self).to_conf()
        if result is not None:
            if self.routes:
                result['routes'] = [{'route': route} for route in self.routes]
            if self.faucet_vips:
                result['faucet_vips'] = [str(vip) for vip in self.faucet_vips]
            if self.bgp_neighbor_addresses:
                result['bgp_neighbor_addresses'] = [str(vip) for vip in self.bgp_neighbor_addresses]
            if self.bgp_server_addresses:
                result['bgp_server_addresses'] = [str(vip) for vip in self.bgp_server_addresses]
            if 'bgp_neighbor_as' in result:
                del result['bgp_neighbor_as']
            if 'bgp_neighbor_addresses' in result:
                del result['bgp_neighbor_addresses']
        return result
