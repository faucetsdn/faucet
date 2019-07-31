"""Configure switch tables with TFM messages."""

from faucet import valve_of

REQUIRED_PROPERTIES = set([
    valve_of.ofp.OFPTFPT_WRITE_ACTIONS,
    valve_of.ofp.OFPTFPT_WRITE_ACTIONS_MISS,
    valve_of.ofp.OFPTFPT_APPLY_ACTIONS,
    valve_of.ofp.OFPTFPT_APPLY_ACTIONS_MISS,
    valve_of.ofp.OFPTFPT_WRITE_SETFIELD,
    valve_of.ofp.OFPTFPT_WRITE_SETFIELD_MISS,
    valve_of.ofp.OFPTFPT_MATCH,
    valve_of.ofp.OFPTFPT_WILDCARDS,
    valve_of.ofp.OFPTFPT_APPLY_SETFIELD_MISS,
    valve_of.ofp.OFPTFPT_APPLY_SETFIELD,
    valve_of.ofp.OFPTFPT_NEXT_TABLES,
    valve_of.ofp.OFPTFPT_NEXT_TABLES_MISS,
    valve_of.ofp.OFPTFPT_APPLY_SETFIELD,
    valve_of.ofp.OFPTFPT_INSTRUCTIONS,
    valve_of.ofp.OFPTFPT_INSTRUCTIONS_MISS])


def fill_required_properties(new_table):
    """Ensure TFM has all required properties."""
    configured_props = {prop.type for prop in new_table.properties}
    missing_props = REQUIRED_PROPERTIES - configured_props
    for prop in missing_props:
        new_table.properties.append(
            valve_of.parser.OFPTableFeaturePropOxm(type_=prop))


def init_table(table_id, name, max_entries, metadata_match, metadata_write):
    """Initialize a TFM."""
    if not metadata_match:
        metadata_match = 0
    if not metadata_write:
        metadata_write = 0
    table_attr = {
        'config': 3,
        'max_entries': max_entries,
        'metadata_match': metadata_match,
        'metadata_write': metadata_write,
        'name': name.encode('utf-8'),
        'properties': [],
        'table_id': table_id,
    }
    return valve_of.parser.OFPTableFeaturesStats(**table_attr)


# pylint: disable=invalid-name
# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals
def load_tables(dp, valve_cl, max_table_id, min_max_flows, use_oxm_ids, fill_req):
    """Configure switch tables with TFM messages."""
    table_array = []
    active_table_ids = sorted([valve_table.table_id for valve_table in dp.tables.values()])
    for table_id in active_table_ids:
        valve_table = dp.table_by_id(table_id)
        max_entries = max(min_max_flows, valve_table.table_config.size)
        new_table = init_table(
            table_id, valve_table.name, max_entries,
            valve_table.metadata_match, valve_table.metadata_write)
        # Match types
        if valve_table.match_types:
            oxm_ids = []
            if use_oxm_ids:
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
            if 'vlan_vid' in valve_table.set_fields:
                apply_actions.add(valve_of.ofp.OFPAT_PUSH_VLAN)
            oxm_ids = []
            if use_oxm_ids:
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
        if fill_req:
            fill_required_properties(new_table)
        table_array.append(new_table)

    tfm_table_ids = {table.table_id for table in table_array}
    for missing_table_id in set(range(max_table_id+1)) - tfm_table_ids:
        new_table = init_table(
            missing_table_id, str(missing_table_id), min_max_flows, 0, 0)
        if fill_req:
            fill_required_properties(new_table)
        table_array.append(new_table)

    return table_array
