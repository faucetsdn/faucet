"""BGP implementation for FAUCET."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ipaddress

from ryu.lib import hub
from beka.beka import Beka
from faucet.valve_util import kill_on_exception


class BgpSpeakerKey:
    """Uniquely describe a BGP speaker."""

    def __init__(self, dp_id, vlan_vid, ipv):
        self.dp_id = dp_id
        self.vlan_vid = vlan_vid
        self.ipv = ipv

    def __str__(self):
        return f'BGP speaker key DP ID: {self.dp_id}, VLAN VID: {self.vlan_vid}, IP version: {self.ipv}'

    def __repr__(self):
        return self.__str__()

    def __hash__(self):
        return hash(self.__str__())

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()


class FaucetBgp:
    """Wrapper for Ryu BGP speaker."""

    exc_logname = None

    def __init__(self, logger, exc_logname, metrics, send_flow_msgs):
        self.logger = logger
        self.exc_logname = exc_logname
        self.metrics = metrics
        self._send_flow_msgs = send_flow_msgs
        self._dp_bgp_speakers = {}
        self._dp_bgp_rib = {}
        self._valves = None
        self.thread = None

    def _valve_vlan(self, dp_id, vlan_vid):
        valve = None
        vlan = None
        if dp_id in self._valves:
            if vlan_vid in self._valves[dp_id].dp.vlans:
                valve = self._valves[dp_id]
                vlan = valve.dp.vlans[vlan_vid]
        return (valve, vlan)

    @staticmethod
    def _neighbor_states(bgp_speaker):
        """Return state of each neighbor for a BGP speaker as a list."""
        neighbor_states = []
        if bgp_speaker is not None:
            neighbor_states = bgp_speaker.neighbor_states()
        return neighbor_states

    @kill_on_exception(exc_logname)
    def _bgp_up_handler(self, remote_ip, remote_as):
        self.logger.info(f'BGP peer router ID {remote_ip} AS {remote_as} up')

    @kill_on_exception(exc_logname)
    def _bgp_down_handler(self, remote_ip, remote_as):
        self.logger.info(f'BGP peer router ID {remote_ip} AS {remote_as} down')
        # TODO: delete RIB routes for down peer.

    @kill_on_exception(exc_logname)
    def _bgp_route_handler(self, path_change, bgp_speaker_key):
        """Handle a BGP change event.

        Args:
            path_change (ryu.services.protocols.bgp.bgpspeaker.EventPrefix): path change
        """
        dp_id = bgp_speaker_key.dp_id
        vlan_vid = bgp_speaker_key.vlan_vid
        valve, vlan = self._valve_vlan(dp_id, vlan_vid)
        if vlan is None:
            return
        prefix = ipaddress.ip_network(str(path_change.prefix))
        route_str = f'BGP route {prefix}'

        if path_change.next_hop:
            nexthop = ipaddress.ip_address(str(path_change.next_hop))
            route_str = f'BGP route {prefix} nexthop {nexthop}'

            if vlan.is_faucet_vip(nexthop):
                self.logger.error(
                    f'Skipping {route_str} because nexthop cannot be us')
                return

            if valve.router_vlan_for_ip_gw(vlan, nexthop) is None:
                self.logger.info(
                    f'Skipping {route_str} because nexthop not in {vlan}')
                return

        if bgp_speaker_key not in self._dp_bgp_rib:
            self._dp_bgp_rib[bgp_speaker_key] = {}

        flowmods = []
        if path_change.is_withdraw:
            self.logger.info('withdraw %s', route_str)
            if prefix in self._dp_bgp_rib[bgp_speaker_key]:
                del self._dp_bgp_rib[bgp_speaker_key][prefix]
            flowmods = valve.del_route(vlan, prefix)
        else:
            self.logger.info('add %s', route_str)
            self._dp_bgp_rib[bgp_speaker_key][prefix] = nexthop
            flowmods = valve.add_route(vlan, nexthop, prefix)
        if flowmods:
            self._send_flow_msgs(valve, flowmods)

    @staticmethod
    def _vlan_prefixes_by_ipv(vlan, ipv):
        vlan_prefixes = [
            (str(faucet_vip), str(faucet_vip.ip)) for faucet_vip in vlan.faucet_vips_by_ipv(ipv)]
        vlan_prefixes.extend([
            (str(ip_dst), str(ip_gw)) for ip_dst, ip_gw in vlan.routes_by_ipv(ipv).items()])
        return vlan_prefixes

    def _create_bgp_speaker_for_vlan(self, bgp_speaker_key, bgp_router):
        """Set up BGP speaker for an individual VLAN if required.

        Args:
            bgp_speaker_key (BgpSpeakerKey): BGP speaker key.
            bgp_router: Router.
        Returns:
            ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker: BGP speaker.
        """
        server_address = sorted(bgp_router.bgp_server_addresses_by_ipv(bgp_speaker_key.ipv))[0]
        beka = Beka(
            local_address=str(server_address),
            bgp_port=bgp_router.bgp_port(),
            local_as=bgp_router.bgp_as(),
            router_id=bgp_router.bgp_routerid(),
            peer_up_handler=self._bgp_up_handler,
            peer_down_handler=self._bgp_down_handler,
            route_handler=lambda x: self._bgp_route_handler(x, bgp_speaker_key),
            error_handler=self.logger.warning)
        for ip_dst, ip_gw in self._vlan_prefixes_by_ipv(bgp_router.bgp_vlan(), bgp_speaker_key.ipv):
            beka.add_route(prefix=str(ip_dst), next_hop=str(ip_gw))
        for bgp_neighbor_address in bgp_router.bgp_neighbor_addresses_by_ipv(bgp_speaker_key.ipv):
            beka.add_neighbor(
                connect_mode=bgp_router.bgp_connect_mode(),
                peer_ip=str(bgp_neighbor_address),
                peer_as=bgp_router.bgp_neighbor_as())
        self.thread = hub.spawn(beka.run)
        self.thread.name = 'beka'
        return beka

    def shutdown_bgp_speakers(self):
        """Shutdown any active BGP speakers."""
        for bgp_speaker in self._dp_bgp_speakers.values():
            bgp_speaker.shutdown()
        self._dp_bgp_speakers = {}

    def _add_bgp_speaker(self, valve, bgp_speaker_key, bgp_router):
        if bgp_speaker_key in self._dp_bgp_speakers:
            self.logger.info(f'Skipping re/configuration of existing {bgp_speaker_key}')
            bgp_speaker = self._dp_bgp_speakers[bgp_speaker_key]
            if bgp_speaker_key in self._dp_bgp_rib:
                # Re-add routes (to avoid flapping BGP even when VLAN cold starts).
                for prefix, nexthop in self._dp_bgp_rib[bgp_speaker_key].items():
                    self.logger.info(f'Re-adding {prefix} via {nexthop}')
                    bgp_vlan = bgp_router.bgp_vlan()
                    flowmods = valve.add_route(bgp_vlan, nexthop, prefix)
                    if flowmods:
                        self._send_flow_msgs(valve, flowmods)
        else:
            self.logger.info(f'Adding {bgp_speaker_key}')
            bgp_speaker = self._create_bgp_speaker_for_vlan(bgp_speaker_key, bgp_router)
        return {bgp_speaker_key: bgp_speaker}

    def _add_valve_bgp_speakers(self, valve):
        bgp_speakers = {}
        bgp_routers = valve.dp.bgp_routers()
        if bgp_routers:
            dp_id = valve.dp.dp_id
            for bgp_router in bgp_routers:
                bgp_vlan = bgp_router.bgp_vlan()
                vlan_vid = bgp_vlan.vid
                for ipv in bgp_router.bgp_ipvs():
                    bgp_speaker_key = BgpSpeakerKey(dp_id, vlan_vid, ipv)
                    bgp_speakers.update(self._add_bgp_speaker(valve, bgp_speaker_key, bgp_router))
        return bgp_speakers

    def reset(self, valves):
        """Set up a BGP speaker for every VLAN that requires it."""
        # TODO: port status changes should cause us to withdraw a route.
        new_dp_bgp_speakers = {}
        if valves:
            for valve in valves.values():
                new_dp_bgp_speakers.update(self._add_valve_bgp_speakers(valve))
        # TODO: shutdown and remove deconfigured BGP speakers.
        for bgp_speaker_key, old_bgp_speaker in self._dp_bgp_speakers.items():
            if bgp_speaker_key not in new_dp_bgp_speakers:
                new_dp_bgp_speakers[bgp_speaker_key] = old_bgp_speaker
        self._dp_bgp_speakers = new_dp_bgp_speakers
        self._valves = valves

    def update_metrics(self, _now):
        """Update BGP metrics."""
        for bgp_speaker_key, bgp_speaker in self._dp_bgp_speakers.items():
            dp_id = bgp_speaker_key.dp_id
            vlan_vid = bgp_speaker_key.vlan_vid
            ipv = bgp_speaker_key.ipv
            valve, vlan = self._valve_vlan(dp_id, vlan_vid)
            if vlan is None:
                continue
            neighbor_states = self._neighbor_states(bgp_speaker)
            for neighbor, neighbor_state in neighbor_states:
                neighbor_labels = dict(
                    valve.dp.base_prom_labels(), vlan=vlan.vid, neighbor=neighbor)
                self.metrics.bgp_neighbor_uptime_seconds.labels(  # pylint: disable=no-member
                    **neighbor_labels).set(neighbor_state['info']['uptime'])
                self.metrics.bgp_neighbor_routes.labels(  # pylint: disable=no-member
                    **dict(neighbor_labels, ipv=ipv)).set(vlan.route_count_by_ipv(ipv))
