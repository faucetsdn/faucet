"""Manage LLDP."""

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
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from faucet import valve_of
from faucet import valve_packet
from faucet.valve_manager_base import ValveManagerBase


class ValveLLDPManager(ValveManagerBase):
    """Manage LLDP."""

    def __init__(self, vlan_table, highest_priority):
        self.vlan_table = vlan_table
        self.highest_priority = highest_priority

    def add_port(self, port):
        ofmsgs = []
        if port.receive_lldp:
            ofmsgs.append(self.vlan_table.flowcontroller(
                match=self.vlan_table.match(
                    in_port=port.number,
                    eth_dst=valve_packet.LLDP_MAC_NEAREST_BRIDGE,
                    eth_dst_mask=valve_packet.BRIDGE_GROUP_MASK,
                    eth_type=valve_of.ether.ETH_TYPE_LLDP),
                priority=self.highest_priority,
                max_len=128))
        return ofmsgs
