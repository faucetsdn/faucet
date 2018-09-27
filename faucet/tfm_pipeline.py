"""Configure switch tables with TFM messages."""

from faucet import valve_of


def load_tables(dp, valve_cl): # pylint: disable=invalid-name
    """Configure switch tables with TFM messages."""
    table_array = []
    active_table_ids = sorted([valve_table.table_id for valve_table in dp.tables.values()])
    for table_id in active_table_ids:
        valve_table = dp.table_by_id(table_id)
        table_attr = {
            'config': 3,
            'max_entries': valve_table.table_config.size,
            'metadata_match': valve_table.metadata_match,
            'metadata_write': valve_table.metadata_write,
            'name': valve_table.name.encode('utf-8'),
            'properties': [],
            'table_id': table_id,
        }
        if valve_table.metadata_match:
            table_attr.update({'metadata_match': valve_table.metadata_match})
        if valve_table.metadata_write:
            table_attr.update({'metadata_write': valve_table.metadata_write})
        new_table = valve_of.parser.OFPTableFeaturesStats(**table_attr)
        # Match types
        if valve_table.match_types:
            oxm_ids = [
                valve_of.parser.OFPOxmId(type_=match_type, hasmask=hasmask)
                for match_type, hasmask in valve_table.match_types.items()]
            new_table.properties.append(
                valve_of.parser.OFPTableFeaturePropOxm(
                    oxm_ids=oxm_ids, type_=valve_of.ofp.OFPTFPT_MATCH))
            # Not an exact match table, assume all fields wildcarded.
            if not valve_table.exact_match:
                new_table.properties.append(
                    valve_of.parser.OFPTableFeaturePropOxm(
                        oxm_ids=oxm_ids, type_=valve_of.ofp.OFPTFPT_WILDCARDS))
        insts = set([valve_of.ofp.OFPIT_APPLY_ACTIONS])
        # Next tables
        if valve_table.next_tables:
            new_table.properties.append(valve_of.parser.OFPTableFeaturePropNextTables(
                table_ids=valve_table.next_tables,
                type_=valve_of.ofp.OFPTFPT_NEXT_TABLES))
            insts.add(valve_of.ofp.OFPIT_GOTO_TABLE)
        # Instructions
        if valve_table.table_config.meter:
            insts.add(valve_of.ofp.OFPIT_METER)
        inst_ids = [valve_of.parser.OFPInstructionId(type_) for type_ in insts]
        new_table.properties.append(
            valve_of.parser.OFPTableFeaturePropInstructions(
                type_=valve_of.ofp.OFPTFPT_INSTRUCTIONS, instruction_ids=inst_ids))
        apply_actions = set()
        if valve_table.table_config.dec_ttl and valve_cl.DEC_TTL:
            apply_actions.add(valve_of.ofp.OFPAT_DEC_NW_TTL)
        # Set fields and apply actions
        if valve_table.set_fields:
            apply_actions.add(valve_of.ofp.OFPAT_SET_FIELD)
            # TODO: only select push_vlan when VLAN VID in set_fields.
            apply_actions.add(valve_of.ofp.OFPAT_PUSH_VLAN)
            oxm_ids = [
                valve_of.parser.OFPOxmId(type_=field, hasmask=False)
                for field in valve_table.set_fields]
            new_table.properties.append(
                valve_of.parser.OFPTableFeaturePropOxm(
                    oxm_ids=oxm_ids, type_=valve_of.ofp.OFPTFPT_APPLY_SETFIELD))
        if valve_table.table_config.output:
            apply_actions.add(valve_of.ofp.OFPAT_OUTPUT)
            apply_actions.add(valve_of.ofp.OFPAT_POP_VLAN)
            if valve_cl.GROUPS:
                apply_actions.add(valve_of.ofp.OFPAT_GROUP)
        if apply_actions:
            action_ids = [
                valve_of.parser.OFPActionId(type_) for type_ in apply_actions]
            new_table.properties.append(
                valve_of.parser.OFPTableFeaturePropActions(
                    type_=valve_of.ofp.OFPTFPT_APPLY_ACTIONS, action_ids=action_ids))
        # Miss goto table option.
        if valve_table.table_config.miss_goto:
            miss_table_id = dp.tables[valve_table.table_config.miss_goto].table_id
            new_table.properties.append(
                valve_of.parser.OFPTableFeaturePropNextTables(
                    table_ids=[miss_table_id], type_=valve_of.ofp.OFPTFPT_NEXT_TABLES_MISS))
            inst_ids = [valve_of.parser.OFPInstructionId(valve_of.ofp.OFPIT_GOTO_TABLE)]
            new_table.properties.append(
                valve_of.parser.OFPTableFeaturePropInstructions(
                    type_=valve_of.ofp.OFPTFPT_INSTRUCTIONS_MISS, instruction_ids=inst_ids))

        table_array.append(new_table)
    return table_array
