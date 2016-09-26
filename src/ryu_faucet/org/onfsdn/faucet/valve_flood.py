# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASISo
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import valve_of

from ryu.lib import mac
from ryu.ofproto import ofproto_v1_3 as ofp


class ValveFloodManager(object):

    def __init__(self, flood_table, flood_priority, mirror_from_port,
                 valve_in_match, valve_flowmod):
        self.flood_table = flood_table
        self.flood_priority = flood_priority
        self.mirror_from_port = mirror_from_port
        self.valve_in_match = valve_in_match
        self.valve_flowmod = valve_flowmod

    def build_flood_rule_actions(self, vlan, exclude_unicast, exclude_ports=[]):
        flood_acts = []
        tagged_ports = vlan.tagged_flood_ports(exclude_unicast)
        untagged_ports = vlan.untagged_flood_ports(exclude_unicast)
        for port in tagged_ports:
            if port not in exclude_ports:
                flood_acts.append(valve_of.output_port(port.number))
        if untagged_ports:
            flood_acts.append(valve_of.pop_vlan())
            for port in untagged_ports:
                if port not in exclude_ports:
                    flood_acts.append(valve_of.output_port(port.number))
        return flood_acts

    def build_flood_rules(self, vlan, modify=False):
        """Add flows to flood packets to unknown destinations on a VLAN."""
        # TODO: not all vendors implement groups well.
        # That means we need flood rules for each input port, outputting
        # to all ports except the input port. When all vendors implement
        # groups correctly we can use them.
        command = ofp.OFPFC_ADD
        if modify:
            command = ofp.OFPFC_MODIFY_STRICT
        flood_priority = self.flood_priority
        flood_eth_dst_matches = []
        if vlan.unicast_flood:
            flood_eth_dst_matches.extend([(None, None)])
        flood_eth_dst_matches.extend([
            ('01:80:C2:00:00:00', '01:80:C2:00:00:00'), # 802.x
            ('01:00:5E:00:00:00', 'ff:ff:ff:00:00:00'), # IPv4 multicast
            ('33:33:00:00:00:00', 'ff:ff:00:00:00:00'), # IPv6 multicast
            (mac.BROADCAST_STR, None), # flood on ethernet broadcasts
        ])
        ofmsgs = []
        vlan_all_ports = vlan.flood_ports(vlan.get_ports(), False)
        mirrored_ports = vlan.mirrored_ports()
        for eth_dst, eth_dst_mask in flood_eth_dst_matches:
            for port in vlan_all_ports:
                if eth_dst is None:
                    flood_acts = self.build_flood_rule_actions(
                        vlan, False, exclude_ports=[port])
                else:
                    flood_acts = self.build_flood_rule_actions(
                        vlan, True, exclude_ports=[port])
                ofmsgs.append(self.valve_flowmod(
                    self.flood_table,
                    match=self.valve_in_match(
                        self.flood_table, in_port=port.number, vlan=vlan,
                        eth_dst=eth_dst, eth_dst_mask=eth_dst_mask),
                    command=command,
                    inst=[valve_of.apply_actions(flood_acts)],
                    priority=flood_priority))
            flood_priority += 1
            for port in mirrored_ports:
                mirror_port = self.mirror_from_port[port.number]
                if eth_dst is None:
                    flood_acts = self.build_flood_rule_actions(vlan, False)
                else:
                    flood_acts = self.build_flood_rule_actions(vlan, True)
                mirror_acts = [
                    valve_of.output_port(mirror_port)] + flood_acts
                ofmsgs.append(self.valve_flowmod(
                    self.flood_table,
                    match=self.valve_in_match(
                        self.flood_table,
                        vlan=vlan,
                        in_port=port.number,
                        eth_dst=eth_dst,
                        eth_dst_mask=eth_dst_mask),
                    command=command,
                    inst=[valve_of.apply_actions(mirror_acts)],
                    priority=flood_priority))
            flood_priority += 1
        return ofmsgs
