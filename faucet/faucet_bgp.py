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
from valve_util import btos


class FaucetBgp(object):

    def __init__(self, logger, send_flow_msgs):
        self._dp_bgp_speakers = {}
        self._metrics = None
        self._valves = None
        self.logger = logger
        self._send_flow_msgs = send_flow_msgs

    def _bgp_route_handler(self, path_change, vlan):
        """Handle a BGP change event.

        Args:
            path_change (ryu.services.protocols.bgp.bgpspeaker.EventPrefix): path change
            vlan (vlan): Valve VLAN this path change was received for.
        """
        prefix = ipaddress.ip_network(btos(path_change.prefix))
        nexthop = ipaddress.ip_address(btos(path_change.nexthop))
        withdraw = path_change.is_withdraw
        flowmods = []
        valve = self._valves[vlan.dp_id]
        if vlan.is_faucet_vip(nexthop):
            self.logger.error(
                'BGP nexthop %s for prefix %s cannot be us',
                nexthop, prefix)
            return
        if not vlan.ip_in_vip_subnet(nexthop):
            self.logger.error(
                'BGP nexthop %s for prefix %s is not a connected network',
                nexthop, prefix)
            return

        if withdraw:
            self.logger.info(
                'BGP withdraw %s nexthop %s', prefix, nexthop)
            flowmods = valve.del_route(vlan, prefix)
        else:
            self.logger.info(
                'BGP add %s nexthop %s', prefix, nexthop)
            flowmods = valve.add_route(vlan, nexthop, prefix)
        if flowmods:
            self._send_flow_msgs(vlan.dp_id, flowmods)

    def _create_bgp_speaker_for_vlan(self, vlan):
        """Set up BGP speaker for an individual VLAN if required.

        Args:
            vlan (vlan): VLAN associated with this speaker.
        Returns:
            ryu.services.protocols.bgp.bgpspeaker.BGPSpeaker: BGP speaker.
        """
        handler = lambda x: self._bgp_route_handler(x, vlan)
        bgp_speaker = BGPSpeaker(
            as_number=vlan.bgp_as,
            router_id=vlan.bgp_routerid,
            bgp_server_port=vlan.bgp_port,
            best_path_change_handler=handler)
        for faucet_vip in vlan.faucet_vips:
            bgp_speaker.prefix_add(
                prefix=str(faucet_vip), next_hop=str(faucet_vip.ip))
        for ipv in vlan.ipvs():
            routes = vlan.routes_by_ipv(ipv)
            for ip_dst, ip_gw in list(routes.items()):
                bgp_speaker.prefix_add(
                    prefix=str(ip_dst), next_hop=str(ip_gw))
        for bgp_neighbor_address in vlan.bgp_neighbor_addresses:
            bgp_speaker.neighbor_add(
                address=bgp_neighbor_address,
                remote_as=vlan.bgp_neighbor_as,
                local_address=vlan.bgp_local_address,
                enable_ipv4=True,
                enable_ipv6=True)
        return bgp_speaker

    def reset(self, valves, metrics):
        """Set up a BGP speaker for every VLAN that requires it."""
        self._valves = valves
        self._metrics = metrics
        # TODO: port status changes should cause us to withdraw a route.
        for dp_id, valve in list(self._valves.items()):
            if dp_id not in self._dp_bgp_speakers:
                self._dp_bgp_speakers[dp_id] = {}
            bgp_speakers = self._dp_bgp_speakers[dp_id]
            for bgp_speaker in list(bgp_speakers.values()):
                bgp_speaker.shutdown()
            for vlan in list(valve.dp.vlans.values()):
                if vlan.bgp_as:
                    bgp_speakers[vlan] = self._create_bgp_speaker_for_vlan(vlan)

    def update_metrics(self):
        """Update BGP metrics."""
        for dp_id, bgp_speakers in list(self._dp_bgp_speakers.items()):
            for vlan, bgp_speaker in list(bgp_speakers.items()):
                if bgp_speaker is not None:
                    neighbor_states = list(json.loads(bgp_speaker.neighbor_state_get()).items())
                    for neighbor, neighbor_state in neighbor_states:
                        # pylint: disable=no-member
                        self._metrics.bgp_neighbor_uptime_seconds.labels(
                            dpid=hex(dp_id), vlan=vlan.vid, neighbor=neighbor).set(
                                neighbor_state['info']['uptime'])
                        for ipv in vlan.ipvs():
                            # pylint: disable=no-member
                            self._metrics.bgp_neighbor_routes.labels(
                                dpid=hex(dp_id), vlan=vlan.vid, neighbor=neighbor, ipv=ipv).set(
                                    len(vlan.routes_by_ipv(ipv)))
