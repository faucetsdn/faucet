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


class FaucetBgp(object):
    """Wrapper for Ryu BGP speaker."""

    def __init__(self, logger, metrics, send_flow_msgs):
        self.logger = logger
        self.metrics = metrics
        self._send_flow_msgs = send_flow_msgs
        self._dp_bgp_speakers = {}
        self._valves = None

    @staticmethod
    def _neighbor_states(bgp_speaker):
        """Return state of each neighbor for a BGP speaker as a list."""
        neighbor_states = []
        if bgp_speaker is not None:
            try:
                neighbor_states = list(json.loads(
                    bgp_speaker.neighbor_state_get()).items())
            except CoreNotStarted:
                pass
        return neighbor_states

    def _bgp_up_handler(self, remote_ip, remote_as):
        self.logger.info('BGP peer router ID %s AS %s up' % (remote_ip, remote_as))

    def _bgp_down_handler(self, remote_ip, remote_as):
        self.logger.info('BGP peer router ID %s AS %s down' % (remote_ip, remote_as))

    def _bgp_route_handler(self, path_change, dp_id, vlan_vid):
        """Handle a BGP change event.

        Args:
            path_change (ryu.services.protocols.bgp.bgpspeaker.EventPrefix): path change
            dp_id (int): Datapath ID this path change was received for.
            vlan_vid (vlan_vid): VLAN VID this path change was received for.
        """
        if not self._valves or dp_id not in self._valves:
            return
        valve = self._valves[dp_id]
        if not vlan_vid in valve.dp.vlans:
            return

        vlan = valve.dp.vlans[vlan_vid]
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

    def _create_bgp_speaker_for_vlan(self, vlan, dp_id, vlan_vid):
        """Set up BGP speaker for an individual VLAN if required.

        Args:
            vlan (valve VLAN): VLAN for BGP speaker.
            dp_id (int): Datapath ID for BGP speaker.
            vlan_vid (vlan_vid): VLAN VID for BGP speaker.
        Returns:
            ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker: BGP speaker.
        """
        handler = lambda x: self._bgp_route_handler(x, dp_id, vlan_vid)
        bgp_speaker = BGPSpeaker(
            as_number=vlan.bgp_as,
            router_id=vlan.bgp_routerid,
            bgp_server_port=vlan.bgp_port,
            bgp_server_hosts=vlan.bgp_server_addresses,
            best_path_change_handler=handler,
            peer_up_handler=self._bgp_up_handler,
            peer_down_handler=self._bgp_down_handler)
        for ip_dst, ip_gw in self._vlan_prefixes(vlan):
            bgp_speaker.prefix_add(prefix=ip_dst, next_hop=ip_gw)
        for bgp_neighbor_address in vlan.bgp_neighbor_addresses:
            bgp_speaker.neighbor_add(
                connect_mode=vlan.bgp_connect_mode,
                address=bgp_neighbor_address,
                remote_as=vlan.bgp_neighbor_as,
                local_address=vlan.bgp_local_address,
                enable_ipv4=True,
                enable_ipv6=True)
        return bgp_speaker

    def reset(self, valves):
        """Set up a BGP speaker for every VLAN that requires it."""
        self._valves = valves
        # TODO: port status changes should cause us to withdraw a route.
        # TODO: BGP speaker library does not cleanly handle del/add of same peer
        # TODO: BGP speaker can listen only on one address family at once
        # TODO: Ryu BGP supports only one speaker
        # (https://sourceforge.net/p/ryu/mailman/message/32699012/)
        # TODO: Ryu BGP cannot be restarted cleanly (so config cannot change at runtime)
        if self._dp_bgp_speakers:
            self.logger.warning(
                'not updating existing BGP speaker, runtime BGP changes not supported')
            return
        bgp_vlans = self._bgp_vlans(self._valves)
        if not bgp_vlans:
            return
        if len(bgp_vlans) > 1:
            self.logger.warning(
                'only one BGP VLAN currently supported')
        bgp_vlan = sorted(bgp_vlans)[0]
        dp_id = bgp_vlan.dp_id
        vlan_vid = bgp_vlan.vid
        self._dp_bgp_speakers[dp_id] = {
            vlan_vid: self._create_bgp_speaker_for_vlan(bgp_vlan, dp_id, vlan_vid)}

    def update_metrics(self):
        """Update BGP metrics."""
        for dp_id, bgp_speakers in list(self._dp_bgp_speakers.items()):
            valve = self._valves[dp_id]
            for vlan_vid, bgp_speaker in list(bgp_speakers.items()):
                vlan = valve.dp.vlans[vlan_vid]
                neighbor_states = self._neighbor_states(bgp_speaker)
                for neighbor, neighbor_state in neighbor_states:
                    neighbor_labels = dict(
                        valve.base_prom_labels, vlan=vlan.vid, neighbor=neighbor)
                    self.metrics.bgp_neighbor_uptime_seconds.labels( # pylint: disable=no-member
                        **neighbor_labels).set(neighbor_state['info']['uptime'])
                    for ipv in vlan.ipvs():
                        self.metrics.bgp_neighbor_routes.labels( # pylint: disable=no-member
                            **dict(neighbor_labels, ipv=ipv)).set(vlan.route_count_by_ipv(ipv))
