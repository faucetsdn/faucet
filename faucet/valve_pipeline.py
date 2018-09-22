"""Manages movement of packets through the faucet pipeline"""
from faucet import valve_of

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
        self.filter_priority = dp.highest_priority + 1
        self.select_priority = dp.highest_priority

    # pylint: disable=W0613
    def filter_packets(self, target_table, match_dict):
        """get a list of flow modification messages to filter packets from
        the pipeline.
        args:
            target_table: the table requesting the filtering
            match_dict: a dictionary specifying the match fields
        """
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

