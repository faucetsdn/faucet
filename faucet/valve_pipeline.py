"""Manager movement of packets through the faucet pipeline"""
import copy
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
        self.classification_table = dp.classification_table()
        self.output_table = dp.output_table()
        self.egress_table = None
        if dp.egress_pipeline:
            self.egress_table = dp.tables['egress']
        self.vlan_table = dp.tables['vlan']
        self.use_group_table = dp.group_table

    def output(self, port, vlan, actions=None):
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
        if self.egress_table:
            metadata, metadata_mask = faucet_md.get_egress_metadata(
                port.number, vlan.vid)
            instructions.extend(valve_of.metadata_goto_table(
                metadata, metadata_mask, self.egress_table))
        else:
            actions.extend(vlan.output_port(port))
        instructions.append(valve_of.apply_actions(actions))
        return instructions

    def _get_offset(self, table):
        result = 0
        if table.name in ('ipv4_fib', 'ipv6_fib', 'vip'):
            result = 0x300
        elif table.name in ('eth_src', 'eth_dst'):
            result = 0x200
        elif table.name == 'flood':
            result = 0x100
        return result

    def _accept_to_table(self, table, actions):
        inst = [table.goto_this()]
        if actions is not None:
            inst.append(valve_of.apply_actions(actions))
        return inst

    def accept_to_classification(self, actions=None):
        """Get instructions to forward packet to the classification table.

        args:
            actions: (optional) list of actions to apply to packet.
        returns:
            list of instructions
        """
        return self._accept_to_table(self.classification_table, actions)

    def accept_to_l2_forwarding(self, actions=None):
        """Get instructions to forward packet through the pipeline to l2
        forwarding.

        args:
            actions: (optional) list of actions to apply to packet.
        returns:
            list of instructions
        """
        return self._accept_to_table(self.output_table, actions)

    def initialise_tables(self):
        """initialise the classification table

        returns:
            list of ofmsgs"""
        ofmsgs = []
        # drop broadcast sources
        if self.dp.drop_broadcast_source_address:
            ofmsgs.extend(self.filter_packets(
                self.classification_table,
                {'eth_src': valve_of.mac.BROADCAST_STR}
                ))

        ofmsgs.extend(self.filter_packets(
            self.classification_table,
            {'eth_type': valve_of.ECTP_ETH_TYPE},
            priority_offset=0x5))

        # antispoof for FAUCET's MAC address
        # TODO: antispoof for controller IPs on this VLAN, too.
        if self.dp.drop_spoofed_faucet_mac:
            for vlan in list(self.dp.vlans.values()):
                ofmsgs.extend(self.filter_packets(
                    self.classification_table,
                    {'eth_src': vlan.faucet_mac},
                    priority_offset=0x80
                    ))

        return ofmsgs

    def _add_egress_table_rule(self, port, vlan, pop_vlan=True):
        metadata, metadata_mask = faucet_md.get_egress_metadata(
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
            priority=self._STATIC_MATCH_PRIORITY,
            inst=inst
            )

    def add_port(self, port):
        """get flow messages to install when a new port comes up.

        args:
            port: a Port object
        returns:
            list of openflow messages
        """
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
        """get flow messages in response to a port going down

        args:
            port: a Port object
        returns:
            list of openflow messages
        """
        ofmsgs = []
        if self.egress_table:
            mask = faucet_md.PORT_METADATA_MASK
            ofmsgs.extend(self.egress_table.flowdel(self.egress_table.match(
                metadata=port.number & mask,
                metadata_mask=mask
                )))
        return ofmsgs

    def filter_packets(self, target_table, match_dict, priority_offset=0):
        """get a list of flow modification messages to filter packets from
        the pipeline.

        Any packets filtered here will be filtered for all modules, not just
        the module requesting the filter. So be careful what you filter.

        You can specify overlapping filters (IE filters that can match the same
        packets) by using the priority offset so that your filters will not
        have the same priority. Priority offsets should be between 1 and 127.
        (128+ is reserved for this module)

        args:
            target_table: the table requesting the filtering
            match_dict: a dictionary specifying the match fields
            priority_offset: an offset for the flow_mod priority to avoid
            overlapping flows
        """
        priority = self._get_offset(target_table) + self._FILTER_PRIORITY
        return [self.classification_table.flowdrop(
            self.classification_table.match(**match_dict),
            priority=priority + priority_offset)]

    def select_packets(self, target_table, match_dict, actions=None,
                       priority_offset=0):
        """retrieve rules to redirect packets matching match_dict to table

        notes:
            - there is a hierarchy of modules as to who will receive packets
            when two modules give the same rules. The hierarchy is 1st:
            routing, 2nd: host, 3rd: flood, 4th: anything else
        args:
            target_table: the table to direct packets to
            match_dict: a dictionary specifying the match fields
            priority_offset: an offset for the flow_mod priority to avoid
            overlapping flows"""
        inst = [target_table.goto_this()]
        priority = self._get_offset(target_table) + self._HIGH_PRIORITY
        if actions is not None:
            inst.append(valve_of.apply_actions(actions))
        return [self.classification_table.flowmod(
            self.classification_table.match(**match_dict),
            priority=priority + priority_offset,
            inst=inst)]

    def remove_filter(self, target_table, match_dict, strict=True,
                      priority_offset=0):
        """retrieve rules to remove a filter from the classification table

        args:
            target_table: the table requesting the filter
            match_dict: a dictionary specifying the match fields
            strict: use a delete strict rather than delete
            priority_offset: an offset for the flow_mod priority for use with
            strict matching
        returns:
            list of flow mod messages"""
        #TODO: We need a mechanism to stop a module from removing filters added
        #by another module. Cookies seems like the logical approach. For now
        # modules are trusted to be careful with their approach.
        priority = None
        if strict:
            priority = self._get_offset(target_table)\
                + self._FILTER_PRIORITY + priority_offset
        return self.classification_table.flowdel(
            self.classification_table.match(**match_dict),
            priority=priority,
            strict=strict)

    def remove_selection(self, target_table, match_dict, strict=True,
                         priority_offset=0):
        """retrieve rules to remove a select from the classification table

        args:
            target_table: the table to direct packets to
            match_dict: a dictionary specifying the match fields
            strict: use a delete strict rather than delete
            priority_offset: an offset for the flow_mod priority for use with
            strict matching
        returns:
            list of flow mod messages"""
        priority = None
        if strict:
            priority = self._get_offset(target_table)\
                + self._HIGH_PRIORITY + priority_offset
        return self.classification_table.flowdel(
            self.classification_table.match(**match_dict),
            priority=priority,
            strict=strict)
