"""Manages movement of packets through the faucet pipeline."""

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

import copy
import functools
import faucet.faucet_metadata as faucet_md
from faucet import valve_of
from faucet.valve_manager_base import ValveManagerBase


class ValvePipeline(ValveManagerBase):
    """Responsible for maintaing the integrity of the Faucet pipeline for a
    single valve.

    Controls what packets a module sees in its tables and how it can pass
    packets through the pipeline.

    Responsible for installing flows in the vlan, egress and classification
    tables"""

    def __init__(self, dp):
        self.dp = dp
        self.vlan_table = dp.tables['vlan']
        self.classification_table = dp.classification_table()
        self.output_table = dp.output_table()
        self.egress_table = None
        self.egress_acl_table = None
        if dp.egress_pipeline:
            self.egress_table = dp.tables['egress']
            self.egress_acl_table = dp.tables.get('egress_acl')
        self.filter_priority = self._FILTER_PRIORITY
        self.select_priority = self._HIGH_PRIORITY

    @staticmethod
    @functools.lru_cache()
    def _accept_to_table(table, actions):
        inst = [table.goto_this()]
        if actions:
            inst.append(valve_of.apply_actions(actions))
        return tuple(inst)

    @functools.lru_cache()
    def accept_to_vlan(self, actions=None):
        """Get instructions to forward packet through the pipeline to
        vlan table.
        args:
            actions: (optional) list of actions to apply to packet.
        returns:
            list of instructions
        """
        return self._accept_to_table(self.vlan_table, actions)

    @functools.lru_cache()
    def accept_to_classification(self, actions=None):
        """Get instructions to forward packet through the pipeline to
        classification table.
        args:
            actions: (optional) list of actions to apply to packet.
        returns:
            list of instructions
        """
        return self._accept_to_table(self.classification_table, actions)

    @functools.lru_cache()
    def accept_to_l2_forwarding(self, actions=None):
        """Get instructions to forward packet through the pipeline to l2
        forwarding.
        args:
            actions: (optional) list of actions to apply to packet.
        returns:
            list of instructions
        """
        return self._accept_to_table(self.output_table, actions)

    @functools.lru_cache()
    def accept_to_egress(self, actions=None):
        """Get instructions to forward packet through the pipeline to egress
        table

        Raises an assertion error if egress pipeline is not configured

        args:
            actions: (optional) list of actions to apply to the packet
        returns:
            list of instructions:
        """
        assert self.egress_table is not None
        return self._accept_to_table(self.egress_table, actions)

    def output(self, port, vlan, hairpin=False, external_forwarding_requested=None):
        """Get instructions list to output a packet through the regular
        pipeline.

        args:
            port: Port object of port to output packet to
            vlan: Vlan object of vlan to output packet on
            hairpin: if True, hairpinning is required
            apply_egress_acl: if True the packet will be sent to the egress acl
                table before being output
        returns:
            list of Instructions
        """
        instructions = []
        if self.egress_table:
            metadata, metadata_mask = faucet_md.get_egress_metadata(
                port.number, vlan.vid)
            if self.egress_acl_table:
                instructions.extend(valve_of.metadata_goto_table(
                    metadata, metadata_mask, self.egress_acl_table))
            else:
                instructions.extend(valve_of.metadata_goto_table(
                    metadata, metadata_mask, self.egress_table))
        else:
            instructions.append(valve_of.apply_actions(vlan.output_port(
                port, hairpin=hairpin, output_table=self.output_table,
                external_forwarding_requested=external_forwarding_requested)))
        return tuple(instructions)

    def initialise_tables(self):
        """Install rules to initialise the classification_table"""
        ofmsgs = []
        # drop broadcast sources
        if self.dp.drop_broadcast_source_address:
            ofmsgs.extend(self.filter_packets(
                {'eth_src': valve_of.mac.BROADCAST_STR}
                ))

        ofmsgs.extend(self.filter_packets(
            {'eth_type': valve_of.ECTP_ETH_TYPE}, priority_offset=10))

        return ofmsgs

    def _add_egress_table_rule(self, port, vlan, pop_vlan=True):
        metadata, metadata_mask = faucet_md.get_egress_metadata(
            port.number, vlan.vid)
        actions = copy.copy(port.mirror_actions())
        if pop_vlan:
            actions.append(valve_of.pop_vlan())
        actions.append(valve_of.output_port(port.number))
        inst = (valve_of.apply_actions(tuple(actions)),)
        return self.egress_table.flowmod(
            self.egress_table.match(
                vlan=vlan,
                metadata=metadata,
                metadata_mask=metadata_mask
                ),
            priority=self.dp.high_priority,
            inst=inst
            )

    def add_port(self, port):
        ofmsgs = []
        if self.egress_table is None:
            return ofmsgs
        for vlan in port.tagged_vlans:
            ofmsgs.append(self._add_egress_table_rule(
                port, vlan, pop_vlan=False))
        if port.native_vlan is not None:
            ofmsgs.append(self._add_egress_table_rule(
                port, port.native_vlan))
        return ofmsgs

    def del_port(self, port):
        ofmsgs = []
        if self.egress_table:
            mask = faucet_md.PORT_METADATA_MASK
            ofmsgs.append(self.egress_table.flowdel(self.egress_table.match(
                metadata=port.number & mask,
                metadata_mask=mask
                )))
        return ofmsgs

    def filter_packets(self, match_dict, priority_offset=0):
        """get a list of flow modification messages to filter packets from
        the pipeline.
        args:
            match_dict: a dictionary specifying the match fields
            priority_offset: used to prevent overlapping entries
        """
        return [self.classification_table.flowdrop(
            self.classification_table.match(**match_dict),
            priority=self.filter_priority + priority_offset)]

    def select_packets(self, target_table, match_dict, actions=None,
                       priority_offset=0):
        """retrieve rules to redirect packets matching match_dict to table"""
        inst = [target_table.goto_this()]
        if actions is not None:
            inst.append(valve_of.apply_actions(actions))
        return [self.classification_table.flowmod(
            self.classification_table.match(**match_dict),
            priority=self.select_priority + priority_offset,
            inst=tuple(inst))]

    def remove_filter(self, match_dict, strict=True, priority_offset=0):
        """retrieve flow mods to remove a filter from the classification table
        """
        priority = None
        if strict:
            priority = self.filter_priority + priority_offset
        return [self.classification_table.flowdel(
            self.classification_table.match(**match_dict),
            priority=priority,
            strict=strict)]
