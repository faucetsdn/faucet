"""VLAN configuration."""

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

import collections
import ipaddress
import random
import netaddr

from faucet import valve_of
from faucet.conf import Conf, test_config_condition, InvalidConfigError
from faucet.valve_packet import FAUCET_MAC


class OFVLAN:

    def __init__(self, name, vid):
        self.name = name
        self.vid = vid


class NullVLAN:
    """Placeholder null VLAN."""

    name = 'Null VLAN'
    vid = valve_of.ofp.OFPVID_NONE


class AnyVLAN:
    """Placeholder any tagged VLAN. NOTE: Not used, not well supported by hardware"""

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

    mutable_attrs = frozenset(['tagged', 'untagged', 'dot1x_untagged'])

    defaults = {
        'name': None,
        'description': None,
        'acl_in': None,
        'acls_in': None,
        'acl_out': None,
        'acls_out': None,
        'faucet_vips': None,
        'faucet_mac': FAUCET_MAC,
        # set MAC for FAUCET VIPs on this VLAN
        'unicast_flood': True,
        'routes': None,
        'max_hosts': 256,
        # Limit number of hosts that can be learned on a VLAN.
        'vid': None,
        'proactive_arp_limit': 0,
        # Don't proactively ARP for hosts if over this limit (default 2*max_hosts)
        'proactive_nd_limit': 0,
        # Don't proactively ND for hosts if over this limit (default 2*max_hosts)
        'targeted_gw_resolution': True,
        # If True, target the first re-resolution attempt to last known port only.
        'minimum_ip_size_check': True,
        # If False, don't check that IP packets have a payload (OVS trace/tutorial requires False).
        'reserved_internal_vlan': False,
        # If True, forward packets from the VLAN table to the VLAN_ACL table matching the VID
        'dot1x_assigned': False,
        # If True, this VLAN may be dynamically added withTunnel-Private-Group-ID radius attribute.
        'edge_learn_stack_root': True,
        # If True, this VLAN will learn flows through the stack root, following forwarding path.
        }

    defaults_types = {
        'name': str,
        'description': str,
        'acl_in': (int, str),
        'acls_in': list,
        'acl_out': (int, str),
        'acls_out': list,
        'faucet_vips': list,
        'faucet_mac': str,
        'unicast_flood': bool,
        'routes': list,
        'max_hosts': int,
        'vid': int,
        'proactive_arp_limit': int,
        'proactive_nd_limit': int,
        'targeted_gw_resolution': bool,
        'minimum_ip_size_check': bool,
        'reserved_internal_vlan': bool,
        'dot1x_assigned': bool,
        'edge_learn_stack_root': bool,
    }

    def __init__(self, _id, dp_id, conf=None):
        self.acl_in = None
        self.acls_in = None
        self.acl_out = None
        self.acls_out = None
        self.description = None
        self.dot1x_assigned = None
        self.dot1x_untagged = None
        self.dp_id = None
        self.edge_learn_stack_root = None
        self.faucet_mac = None
        self.faucet_vips = None
        self.max_hosts = None
        self.minimum_ip_size_check = None
        self.reserved_internal_vlan = None
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
        self.dot1x_untagged = []

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

    def check_config(self):
        super(VLAN, self).check_config()
        test_config_condition(not self.vid_valid(self.vid), 'invalid VID %s' % self.vid)
        test_config_condition(not netaddr.valid_mac(self.faucet_mac), (
            'invalid MAC address %s' % self.faucet_mac))

        test_config_condition(
            self.acl_in and self.acls_in, 'found both acl_in and acls_in, use only acls_in')
        test_config_condition(
            self.acl_out and self.acls_out, 'found both acl_out and acls_out, use only acls_out')
        if self.acl_in and not isinstance(self.acl_in, list):
            self.acls_in = [self.acl_in,]
            self.acl_in = None
        if self.acl_out and not isinstance(self.acl_out, list):
            self.acls_out = [self.acl_out,]
            self.acl_out = None
        all_acls = []
        if self.acls_in:
            all_acls.extend(self.acls_in)
        if self.acls_out:
            all_acls.extend(self.acls_out)
        for acl in all_acls:
            test_config_condition(
                not isinstance(acl, (int, str)), 'acl names must be int or str')

        if self.max_hosts:
            if not self.proactive_arp_limit:
                self.proactive_arp_limit = 2 * self.max_hosts
            if not self.proactive_nd_limit:
                self.proactive_nd_limit = 2 * self.max_hosts

        if self.faucet_vips:
            self.faucet_vips = frozenset([
                self._check_ip_str(ip_str, ip_method=ipaddress.ip_interface)
                for ip_str in self.faucet_vips])
            for faucet_vip in self.faucet_vips:
                test_config_condition(
                    faucet_vip.network.prefixlen == faucet_vip.max_prefixlen,
                    'VIP cannot be a host address')

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
        return isinstance(vid, int) and vid >= valve_of.MIN_VID and vid <= valve_of.MAX_VID

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
        self.untagged = tuple([port for port in sorted_ports
                               if self == port.native_vlan and port.dyn_dot1x_native_vlan is None])
        self.dot1x_untagged = tuple([port for port in sorted_ports
                                     if self == port.dyn_dot1x_native_vlan])

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

    def faucet_vips_by_ipv(self, ipv):
        """Return VIPs with specified IP version on this VLAN."""
        return self._by_ipv(self.faucet_vips, ipv)

    def link_and_other_vips(self, ipv):
        """Return link local and non-link local VIPs."""
        vips = self.faucet_vips_by_ipv(ipv)
        link_local_vips = frozenset([vip for vip in vips if vip.is_link_local])
        other_vips = vips - link_local_vips
        return (link_local_vips, other_vips)

    def ipvs(self):
        """Return IP versions configured on this VLAN."""
        return self._ipvs(self.faucet_vips)

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
        """Update dyn host/route gw information to a different ip version"""
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
        if self.dot1x_untagged:
            str_ports.append('dot1x_untagged: %s' % ','.join([str(p) for p in self.dot1x_untagged]))
        return 'VLAN %s vid:%s %s' % (self.name, self.vid, ' '.join(str_ports))

    def __repr__(self):
        return self.__str__()

    def get_ports(self):
        """Return all ports on this VLAN."""
        return self.tagged + self.untagged + self.dot1x_untagged

    def restricted_bcast_arpnd_ports(self):
        """Return all ports with restricted broadcast enabled."""
        return tuple([port for port in self.get_ports() if port.restricted_bcast_arpnd])

    def hairpin_ports(self):
        """Return all ports with hairpin enabled."""
        return tuple([port for port in self.get_ports() if port.hairpin])

    def mirrored_ports(self):
        """Return ports that are mirrored on this VLAN."""
        return tuple([port for port in self.get_ports() if port.mirror])

    def loop_protect_external_ports(self):
        """Return ports wth external loop protection set."""
        return tuple([port for port in self.get_ports() if port.loop_protect_external])

    def loop_protect_external_ports_up(self):
        """Return up ports with external loop protection set."""
        return tuple([port for port in self.loop_protect_external_ports() if port.dyn_phys_up])

    def lacp_ports(self):
        """Return ports that have LACP on this VLAN."""
        return tuple([port for port in self.get_ports() if port.lacp])

    def lacp_up_selected_ports(self):
        """Return LACP ports that have been SELECTED and are UP"""
        return tuple([
            port for port in self.lacp_ports() if port.is_port_selected() and port.is_actor_up()])

    def lags(self):
        """Return dict of LAGs mapped to member ports."""
        lags = collections.defaultdict(list)
        for port in self.lacp_ports():
            lags[port.lacp].append(port)
        return lags

    def selected_up_lags(self):
        """Return dict of LAGs mapped to member ports that have been selected"""
        lags = collections.defaultdict(list)
        for port in self.lacp_up_selected_ports():
            lags[port.lacp].append(port)
        return lags

    def excluded_lag_ports(self, in_port=None):
        """Ensure output to SELECTED LAG ports & only one LAG member"""
        exclude_ports = set()
        lags = self.lags()
        if lags:
            # Need lags that have actor UP & are SELECTED
            selected_ports = self.selected_up_lags()
            if in_port is not None and in_port.lacp:
                # Don't flood to same LAG
                exclude_ports.update(lags[in_port.lacp])
            # Pick a bundle member to flood to
            for lag, ports in lags.items():
                selected_lag = selected_ports[lag]
                if selected_lag:
                    ports.remove(selected_lag[0])
                exclude_ports.update(ports)
        return exclude_ports

    def exclude_native_if_dot1x(self):
        """Don't output on native vlan, if dynamic (1x) vlan is in use"""
        exclude_ports = set()
        for port in self.untagged:
            if port.dyn_dot1x_native_vlan is None:
                continue
            if port.dyn_dot1x_native_vlan != self:
                exclude_ports.add(port)
        return exclude_ports

    @staticmethod
    def flood_ports(configured_ports, exclude_unicast):
        """Return configured ports that allow flooding"""
        if exclude_unicast:
            return tuple([port for port in configured_ports if port.unicast_flood])
        return configured_ports

    def tagged_flood_ports(self, exclude_unicast):
        return self.flood_ports(self.tagged, exclude_unicast)

    def untagged_flood_ports(self, exclude_unicast):
        return self.flood_ports(self.untagged + self.dot1x_untagged, exclude_unicast)

    def output_port(self, port, hairpin=False, output_table=None, external_forwarding_requested=None):
        actions = []
        if self.port_is_untagged(port):
            actions.append(valve_of.pop_vlan())
            # Packet is mirrored, as the receiving host sees it (without a tag).
            actions.extend(port.mirror_actions())
        else:
            actions.extend(port.mirror_actions())
            if external_forwarding_requested is not None:
                if external_forwarding_requested:
                    actions.append(output_table.set_external_forwarding_requested())
                else:
                    actions.append(output_table.set_no_external_forwarding_requested())
        if hairpin:
            actions.append(valve_of.output_port(valve_of.OFP_IN_PORT))
        else:
            actions.append(valve_of.output_port(port.number))
        return actions

    def pkt_out_port(self, packet_builder, port, *args):
        """Return packet-out actions with VLAN tag if port is tagged"""
        vid = None
        if self.port_is_tagged(port):
            vid = self.vid
        pkt = packet_builder(vid, *args)
        return valve_of.packetout(port.number, bytes(pkt.data))

    def flood_pkt(self, packet_builder, multi_out=True, *args):
        """Return Packet-out actions via flooding"""
        ofmsgs = []
        for vid, ports in (
                (self.vid, self.tagged_flood_ports(False)),
                (None, self.untagged_flood_ports(False))):
            if ports:
                pkt = packet_builder(vid, *args)
                exclude_ports = self.excluded_lag_ports()
                running_port_nos = [
                    port.number for port in ports if port.running() and port not in exclude_ports]
                if running_port_nos:
                    random.shuffle(running_port_nos)
                    if multi_out:
                        ofmsgs.append(valve_of.packetouts(running_port_nos, pkt.data))
                    else:
                        ofmsgs.extend(
                            [valve_of.packetout(port_no, pkt.data) for port_no in running_port_nos])
        return ofmsgs

    def port_is_tagged(self, port):
        """Return True if port number is an tagged port on this VLAN."""
        return port in self.tagged

    def port_is_untagged(self, port):
        """Return True if port number is an untagged port on this VLAN."""
        return port in self.untagged or port in self.dot1x_untagged

    def vip_map(self, ipa):
        """Return the vip containing ipa"""
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
