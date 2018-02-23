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

from ryu.lib import hub
from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker
from ryu.services.protocols.bgp.api.base import CoreNotStarted

from faucet.valve_util import btos


class FaucetBgp(object):
    """Wrap Ryu BGP speaker implementation."""
    # TODO: Ryu BGP supports only one speaker
    # (https://sourceforge.net/p/ryu/mailman/message/32699012/)
    # TODO: Ryu BGP cannot be restarted cleanly (so config can't warm start change)

    def __init__(self, logger, metrics, send_flow_msgs):
        self.logger = logger
        self.metrics = metrics
        self._send_flow_msgs = send_flow_msgs
        self._valves = None
        self._neighbor_to_vlan = {}
        self._bgp_speaker = None

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
        if not source in self._neighbor_to_vlan:
            return

        vlan = self._neighbor_to_vlan[source]
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

    def _deconfigure_neighbors(self):
        for vlan in list(self._neighbor_to_vlan.values()):
            for faucet_vip in vlan.faucet_vips:
                self._bgp_speaker.prefix_del(prefix=str(faucet_vip))
            for ipv in vlan.ipvs():
                routes = vlan.routes_by_ipv(ipv)
                for ip_dst in list(routes.keys()):
                    self._bgp_speaker.prefix_del(prefix=str(ip_dst))
            for bgp_neighbor_address in vlan.bgp_neighbor_addresses:
                self._bgp_speaker.neighbor_reset(bgp_neighbor_address)
                self._bgp_speaker.neighbor_del(bgp_neighbor_address)
        # TODO: need a better way to synchronize with BGP speaker to
        # ensure all neighbors have actually been deleted.
        while self._neighbor_states():
            hub.sleep(0.1)

    def _configure_neighbors(self):
        for valve in list(self._valves.values()):
            for vlan in list(valve.dp.vlans.values()):
                if not vlan.bgp_as:
                    continue
                if not self._bgp_speaker:
                    self._bgp_speaker = BGPSpeaker(
                        as_number=0,
                        router_id=vlan.bgp_routerid,
                        bgp_server_port=vlan.bgp_port,
                        bgp_server_hosts=vlan.bgp_server_addresses,
                        best_path_change_handler=self._bgp_route_handler)
                for faucet_vip in vlan.faucet_vips:
                    self._bgp_speaker.prefix_add(
                        prefix=str(faucet_vip), next_hop=str(faucet_vip.ip))
                for ipv in vlan.ipvs():
                    routes = vlan.routes_by_ipv(ipv)
                    for ip_dst, ip_gw in list(routes.items()):
                        self._bgp_speaker.prefix_add(
                            prefix=str(ip_dst), next_hop=str(ip_gw))
                for bgp_neighbor_address in vlan.bgp_neighbor_addresses:
                    self._bgp_speaker.neighbor_add(
                        address=bgp_neighbor_address,
                        local_as=vlan.bgp_as,
                        remote_as=vlan.bgp_neighbor_as,
                        local_address=vlan.bgp_local_address,
                        enable_ipv4=True,
                        enable_ipv6=True)
                    self._neighbor_to_vlan[bgp_neighbor_address] = vlan

    def reset(self, valves):
        """Set up a BGP speaker for every VLAN that requires it."""
        # TODO: port status changes should cause us to withdraw a route.
        # TODO: handle warm starts where BGP/neighbor config did not change.
        if self._bgp_speaker:
            self._deconfigure_neighbors()
        self._valves = valves
        self._configure_neighbors()

    def update_metrics(self):
        """Update BGP metrics."""
        neighbor_states = self._neighbor_states()
        for neighbor, neighbor_state in neighbor_states:
            if not neighbor in self._neighbor_to_vlan:
                continue
            vlan = self._neighbor_to_vlan[neighbor]
            valve = self._valves[vlan.dp_id]
            self.metrics.bgp_neighbor_uptime_seconds.labels( # pylint: disable=no-member
                **dict(valve.base_prom_labels, vlan=vlan.vid, neighbor=neighbor)).set(
                    neighbor_state['info']['uptime'])
            for ipv in vlan.ipvs():
                self.metrics.bgp_neighbor_routes.labels( # pylint: disable=no-member
                    **dict(valve.base_prom_labels, vlan=vlan.vid, neighbor=neighbor, ipv=ipv)).set(
                        len(vlan.routes_by_ipv(ipv)))
