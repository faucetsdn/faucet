"""Implementation of Valve output only."""

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

from faucet.valve_manager_base import ValveManagerBase


class OutputOnlyManager(ValveManagerBase):
    """Implementation of Valve output only."""

    def __init__(self, vlan_table, highest_priority):
        self.vlan_table = vlan_table
        self.highest_priority = highest_priority

    def add_port(self, port):
        ofmsgs = []
        if port.output_only:
            ofmsgs.append(self.vlan_table.flowdrop(
                match=self.vlan_table.match(in_port=port.number),
                priority=self.highest_priority))
        return ofmsgs

    def del_port(self, port):
        ofmsgs = []
        if port.output_only:
            ofmsgs.append(self.vlan_table.flowdel(
                match=self.vlan_table.match(in_port=port.number),
                priority=self.highest_priority))
        return ofmsgs
