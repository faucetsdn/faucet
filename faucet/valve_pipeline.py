import copy
from faucet import valve_of
from faucet.faucet_metadata import get_egress_metadata

class ValvePipeline(object):
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
        self.high_priority = dp.high_priority
        self.low_priority = dp.low_priority

    def dp_connect(self):
        pass

    def output(self, output_port, vlan, actions=None):
        if actions is not None:
            actions = copy.copy(actions)
        else:
            actions = []
        instructions = []
        if self.egress_pipeline:
            metadata, metadata_mask = get_egress_metadata(
                output_port.number, vlan.vid)
            instructions.append(valve_of.metadata_goto_table(
                metadata, metadata_mask, self.egress_table))
        return instructions

    def accept_to_l2_forwarding(self, actions=None):
        inst = [self.output_table.goto_this()]
        if actions is not None:
            inst.append(valve_of.apply_actions(actions))
        return inst

    def filter_packets(self, match):
        # TODO: if you have an overlapping match here then it shouldnt matter
        # since these are always explicit drop rules, but it would be good to
        # validate this. It is possible the rules wont get accepted if they
        # overlap.

        # possibly we could have a hierarchy of modules that determines the
        # priority for rules from that module
        return [self.classification_table.flowdrop(
            self.classification_table.match(match),
            priority=(self.high_priority))]

    def select_packets(self, target_table, match, actions=None):
        """retrieve rules to redirect packets matching match_dict to table"""
        inst = [self.target_table.goto_this()]
        if actions is not None:
            inst.append(valve_of.apply_actions(actions))
        return [self.classification_table.flowmod(
            self.classification_table.match(match),
            priority=self.low_priority,
            inst=inst)]

