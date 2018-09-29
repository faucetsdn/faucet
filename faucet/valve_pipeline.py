"""Manages movement of packets through the faucet pipeline."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
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


class ValvePipeline:
    """Responsible for maintaing the integrity of the Faucet pipeline for a
    single valve.

    Controls what packets a module sees in its tables and how it can pass
    packets through the pipeline.

    Responsible for installing flows in the vlan, egress and classification
    tables"""

    def __init__(self, dp):
        self.dp = dp
        self.classification_table = dp.classification_table()
        self.output_table = dp.output_table()
        self.egress_table = None
        if dp.egress_pipeline:
            self.egress_table = dp.tables['egress']
        self.filter_priority = dp.highest_priority + 1
        self.select_priority = dp.highest_priority

    def accept_to_l2_forwarding(self, actions=None):
        """Get instructions to forward packet through the pipeline to l2
        forwarding.
        args:
            actions: (optional) list of actions to apply to packet.
        returns:
            list of instructions
        """
        inst = [self.output_table.goto_this()]
        if actions is not None:
            inst.append(valve_of.apply_actions(actions))
        return inst

    def filter_packets(self, _target_table, match_dict):
        """get a list of flow modification messages to filter packets from
        the pipeline.
        args:
            _target_table: the table requesting the filtering
            match_dict: a dictionary specifying the match fields
        """
        return [self.classification_table.flowdrop(
            self.classification_table.match(**match_dict),
            priority=(self.filter_priority))]

    def select_packets(self, target_table, match_dict, actions=None):
        """retrieve rules to redirect packets matching match_dict to table"""
        inst = [target_table.goto_this()]
        if actions is not None:
            inst.append(valve_of.apply_actions(actions))
        return [self.classification_table.flowmod(
            self.classification_table.match(**match_dict),
            priority=self.select_priority,
            inst=inst)]
