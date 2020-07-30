"""Implementation of Valve coprocessor."""

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
from faucet.valve_manager_base import ValveManagerBase
from faucet.vlan import OFVLAN


class CoprocessorManager(ValveManagerBase):
    """Implementation of Valve coprocessor."""

    def __init__(self, ports, copro_table, vlan_table, eth_src_table,  # pylint: disable=too-many-arguments
                 output_table, low_priority, high_priority):
        self.ports = ports
        self.copro_table = copro_table
        self.vlan_table = vlan_table
        self.eth_src_table = eth_src_table
        self.output_table = output_table
        self.low_priority = low_priority
        self.high_priority = high_priority

    def add_port(self, port):
        """Add flows to allow coprocessor to inject or output packets."""
        ofmsgs = []
        if port.coprocessor:
            ofmsgs.append(self.vlan_table.flowmod(
                self.vlan_table.match(in_port=port.number),
                priority=self.low_priority,
                inst=(self.vlan_table.goto(self.copro_table),)))
            ofmsgs.append(self.eth_src_table.flowmod(
                match=self.eth_src_table.match(in_port=port.number),
                priority=self.high_priority,
                inst=(self.eth_src_table.goto(self.output_table),)))
            # TODO: add additional output port strategies (eg. MPLS) and tagged ports
            vlan_vid_base = port.coprocessor.get('vlan_vid_base', 0)
            for port_number in self.ports:
                inst = (valve_of.apply_actions((
                    valve_of.pop_vlan(),
                    valve_of.output_port(port_number))),)
                vid = vlan_vid_base + port_number
                vlan = OFVLAN(str(vid), vid)
                match = self.copro_table.match(vlan=vlan)
                ofmsgs.append(self.copro_table.flowmod(
                    match=match, priority=self.high_priority, inst=inst))
        return ofmsgs
