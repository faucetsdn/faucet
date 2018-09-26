import copy
import faucet.faucet_metadata as faucet_metadata
from faucet import valve_of
from faucet.valve_manager_base import ValveManagerBase

class ValvePipeline(ValveManagerBase):
    """Responsible for maintaing the integrity of the Faucet pipeline for a
    single valve.

    Controls what packets a module sees in its tables and how it can pass
    packets through the pipeline.

    Responsible for installing flows in the vlan, egress and classification
    tables"""

    # TODO: initialise tables
    def __init__(self, dp):
        self.dp = dp
        self.classification_table = dp.classification_table()
        self.output_table = dp.output_table()
        self.egress_table = None
        if dp.egress_pipeline:
            self.egress_table = dp.tables['egress']
        self.vlan_table = dp.tables['vlan']
        self.use_group_table = dp.group_table
        self.filter_priority = dp.highest_priority + 1
        self.select_priority = dp.highest_priority

    def dp_connect(self):
        pass

    def output(self, port, vlan, actions=None):
        if actions is not None:
            actions = copy.copy(actions)
        else:
            actions = []
        instructions = []
        instructions.append(valve_of.apply_actions(actions))
        if self.egress_table:
            metadata, metadata_mask = faucet_metadata.get_egress_metadata(
                port.number, vlan.vid)
            instructions.extend(valve_of.metadata_goto_table(
                metadata, metadata_mask, self.egress_table))
        else:
            instructions.append(valve_of.apply_actions(vlan.output_port(port)))
        return instructions

    def _accept_to_table(self, table, actions):
        inst = [table.goto_this()]
        if actions is not None:
            inst.append(valve_of.apply_actions(actions))
        return inst

    def accept_to_classification(self, actions=None):
        return self._accept_to_table(self.classification_table, actions)

    def accept_to_l2_forwarding(self, actions=None):
        return self._accept_to_table(self.output_table, actions)

    def initialise_tables(self):
        ofmsgs = []
        # drop broadcast sources
        if self.dp.drop_broadcast_source_address:
            ofmsgs.extend(self.filter_packets(
                self.classification_table,
                {'eth_src': valve_of.mac.BROADCAST_STR}
                ))

        ofmsgs.extend(self.filter_packets(
            self.classification_table, {'eth_type': valve_of.ECTP_ETH_TYPE}))

        # antispoof for FAUCET's MAC address
        # TODO: antispoof for controller IPs on this VLAN, too.
        if self.dp.drop_spoofed_faucet_mac:
            for vlan in list(self.dp.vlans.values()):
                ofmsgs.extend(self.filter_packets(
                    self.classification_table, {'eth_src': vlan.faucet_mac}))

        return ofmsgs

    def _add_egress_table_rule(self, port, vlan, pop_vlan=True):
        metadata, metadata_mask = faucet_metadata.get_egress_metadata(
            port.number, vlan.vid)
        actions = copy.copy(port.mirror_actions())
        if pop_vlan:
            actions.append(valve_of.pop_vlan())
        actions.append(valve_of.output_port(port.number))
        inst = [valve_of.apply_actions(actions)]
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
            mask = faucet_metadata.PORT_METADATA_MASK
            ofmsgs.extend(self.egress_table.flowdel(self.egress_table.match(
                metadata=port.number & mask,
                metadata_mask = mask
                )))
        return ofmsgs

    def filter_packets(self, target_table, match_dict):
        # TODO: if you have an overlapping match here then it shouldnt matter
        # since these are always explicit drop rules, but it would be good to
        # validate this. It is possible the rules wont get accepted if they
        # overlap.

        # possibly we could have a hierarchy of modules that determines the
        # priority for rules from that module
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

    def remove_filter(self, target_table, match_dict, strict=True):
        #TODO: We need a mechanism to stop a module from removing filters added
        #by another module. Cookies seems like the logical approach. For now
        # modules are trusted
        priority = None
        if strict:
            priorty = self.filter_priority
        return self.classification_table.flowdel(
            self.classification_table.match(**match_dict),
            priority=priority,
            strict=strict)

    def remove_selection(self, target_table, match_dict, strict=True):
        priority = None
        if strict:
            priorty = self.select_priority
        return self.classification_table.flowdel(
            self.classification_table.match(**match_dict),
            priority=priority,
            strict=strict)
