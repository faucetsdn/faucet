"""BGP implementation for FAUCET."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import ipaddress

from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker
from ryu.services.protocols.bgp.api.base import CoreNotStarted

from faucet.valve_util import btos


class FaucetBgpPeer(object):
    """Associate BGP peer with datapath/VLAN."""

    def __init__(self, bgp_neighbor_address, dp_id, vlan_vid):
        self.bgp_neighbor_address = bgp_neighbor_address
        self.dp_id = dp_id
        self.vlan_vid = vlan_vid

    def __eq__(self, other):
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return False

    def __hash__(self):
        return hash(tuple(sorted(self.__dict__.items())))


class FaucetBgp(object):
    """Wrap Ryu BGP speaker implementation."""
    # TODO: Ryu BGP supports only one speaker
    # (https://sourceforge.net/p/ryu/mailman/message/32699012/)
    # TODO: Ryu BGP cannot be restarted cleanly (so config can't warm start change)

    def __init__(self, logger, metrics, send_flow_msgs):
        self.logger = logger
        self.metrics = metrics
        self._send_flow_msgs = send_flow_msgs
        self._bgp_speaker = None
        self._valves = None
        self._peers = {}

    def _neighbor_states(self):
        if self._bgp_speaker:
            try:
                return list(json.loads(
                    self._bgp_speaker.neighbor_state_get()).items())
            except CoreNotStarted:
                pass
        return []

    def _bgp_route_handler(self, path_change):
        """Handle a BGP change event.

        Args:
            path_change (ryu.services.protocols.bgp.bgpspeaker.EventPrefix): path change
        """
        if not self._valves:
            return

        source = path_change.path.source.ip_address
        if not source in self._peers:
            return

        peer = self._peers[source]
        if not peer.dp_id in self._valves:
            return
        valve = self._valves[peer.dp_id]
        if not peer.vlan_vid in valve.dp.vlans:
            return
        vlan = valve.dp.vlans[peer.vlan_vid]

        prefix = ipaddress.ip_network(btos(path_change.prefix))
        nexthop = ipaddress.ip_address(btos(path_change.nexthop))

        if vlan.is_faucet_vip(nexthop):
            self.logger.error(
                'BGP nexthop %s for prefix %s cannot be us',
                nexthop, prefix)
            return
        if vlan.ip_in_vip_subnet(nexthop) is None:
            self.logger.error(
                'BGP nexthop %s for prefix %s is not a connected network',
                nexthop, prefix)
            return

        valve = self._valves[vlan.dp_id]
        flowmods = []
        if path_change.is_withdraw:
            self.logger.info(
                'BGP withdraw %s nexthop %s', prefix, nexthop)
            flowmods = valve.del_route(vlan, prefix)
        else:
            self.logger.info(
                'BGP add %s nexthop %s', prefix, nexthop)
            flowmods = valve.add_route(vlan, nexthop, prefix)
        if flowmods:
            self._send_flow_msgs(vlan.dp_id, flowmods)

    @staticmethod
    def _bgp_vlans(valves):
        bgp_vlans = set()
        if valves:
            for valve in list(valves.values()):
                for vlan in valve.dp.bgp_vlans():
                    bgp_vlans.add(vlan)
        return bgp_vlans

    def _bgp_peers(self, valves):
        peers = {}
        for vlan in self._bgp_vlans(valves):
            for bgp_neighbor_address in vlan.bgp_neighbor_addresses:
                peers[bgp_neighbor_address] = FaucetBgpPeer(
                    bgp_neighbor_address, vlan.dp_id, vlan.vid)
        return peers

    @staticmethod
    def _vlan_prefixes(vlan):
        vlan_prefixes = []
        for faucet_vip in vlan.faucet_vips:
            vlan_prefixes.append((str(faucet_vip), str(faucet_vip.ip)))
            for ipv in vlan.ipvs():
                routes = vlan.routes_by_ipv(ipv)
                for ip_dst, ip_gw in list(routes.items()):
                    vlan_prefixes.append((str(ip_dst), str(ip_gw)))
        return vlan_prefixes

    def reset(self, valves):
        """Set up a BGP speaker for every VLAN that requires it."""
        # TODO: port status changes should cause us to withdraw a route.
        # TODO: BGP speaker library does not cleanly handle del/add of same BGP peer address
        new_bgp_peers = self._bgp_peers(valves)
        deconfigured_bgp_peers = set(self._peers.values()) - set(new_bgp_peers.values())
        new_configured_bgp_peers = set(new_bgp_peers.values()) - set(self._peers.values())

        if self._bgp_speaker:
            for peer in deconfigured_bgp_peers:
                valve = self._valves[peer.dp_id]
                vlan = valve.dp.vlans[peer.vlan_vid]
                self._bgp_speaker.neighbor_del(peer.bgp_neighbor_address)
                self.logger.info('deconfiguring BGP peer %s' % peer.bgp_neighbor_address)
                for ip_dst, _ in self._vlan_prefixes(vlan):
                    self._bgp_speaker.prefix_del(ip_dst)

        for peer in new_configured_bgp_peers:
            valve = valves[peer.dp_id]
            vlan = valve.dp.vlans[peer.vlan_vid]
            if not self._bgp_speaker:
                self._bgp_speaker = BGPSpeaker(
                    as_number=0,
                    router_id=vlan.bgp_routerid,
                    bgp_server_port=vlan.bgp_port,
                    bgp_server_hosts=vlan.bgp_server_addresses,
                    best_path_change_handler=self._bgp_route_handler)
            for ip_dst, ip_gw in self._vlan_prefixes(vlan):
                self._bgp_speaker.prefix_add(prefix=ip_dst, next_hop=ip_gw)
            self._bgp_speaker.neighbor_add(
                address=peer.bgp_neighbor_address,
                local_as=vlan.bgp_as,
                remote_as=vlan.bgp_neighbor_as,
                local_address=vlan.bgp_local_address,
                enable_ipv4=True,
                enable_ipv6=True)
            self.logger.info('configuring BGP peer %s' % peer.bgp_neighbor_address)

        self._peers = new_bgp_peers
        self._valves = valves

    def update_metrics(self):
        """Update BGP metrics."""
        neighbor_states = self._neighbor_states()
        for neighbor, neighbor_state in neighbor_states:
            if not neighbor in self._peers:
                continue
            peer = self._peers[neighbor]
            valve = self._valves[peer.dp_id]
            vlan = valve.dp.vlans[peer.vlan_vid]
            self.metrics.bgp_neighbor_uptime_seconds.labels( # pylint: disable=no-member
                **dict(valve.base_prom_labels, vlan=vlan.vid, neighbor=neighbor)).set(
                    neighbor_state['info']['uptime'])
            for ipv in vlan.ipvs():
                self.metrics.bgp_neighbor_routes.labels( # pylint: disable=no-member
                    **dict(valve.base_prom_labels, vlan=vlan.vid, neighbor=neighbor, ipv=ipv)).set(
                        len(vlan.routes_by_ipv(ipv)))
