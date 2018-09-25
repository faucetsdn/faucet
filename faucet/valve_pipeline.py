"""Manages movement of packets through the faucet pipeline"""
import copy
from faucet import valve_of
from faucet.faucet_metadata import get_egress_metadata

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
        self.vlan_table = dp.tables['vlan']
        self.filter_priority = dp.highest_priority + 1
        self.select_priority = dp.highest_priority

    def output(self, output_port, vlan, actions=None):
        """Get instructions list to output a packet through the regular
        pipeline.
        args:
            port: Port object of port to output packet to
            vlan: Vlan object of vlan to output packet on
            actions: list of actions to apply to packet before outputting
        returns:
            list of Instructions
        """
        if actions is not None:
            actions = copy.copy(actions)
        else:
            actions = []
        instructions = []
        instructions.append(valve_of.apply_actions(actions))
        if self.egress_table:
            metadata, metadata_mask = get_egress_metadata(
                port.number, vlan.vid)
            instructions.extend(valve_of.metadata_goto_table(
                metadata, metadata_mask, self.egress_table))
        else:
            instructions.append(valve_of.apply_actions(vlan.output_port(port)))
        return instructions

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

    # pylint: disable=W0613
    def filter_packets(self, target_table, match_dict):
        """get a list of flow modification messages to filter packets from
        the pipeline.
        args:
            target_table: the table requesting the filtering
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
