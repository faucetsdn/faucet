"""Parse JSON for TFM based table config."""

import json
import os

from faucet import valve_of


class LoadRyuTables:
    """Serialize table features messages from JSON."""

    _CLASS_NAME_TO_NAME_IDS = {
        'OFPTableFeaturePropInstructions': 'instruction_ids',
        'OFPTableFeaturePropNextTables': 'table_ids',
        'OFPTableFeaturePropActions': 'action_ids',
        'OFPTableFeaturePropOxm': 'oxm_ids'}

    def __init__(self, cfgpath, pipeline_conf):
        self.ryu_table_translator = OpenflowToRyuTranslator(
            cfgpath, pipeline_conf)

    def load_tables(self, dp): # pylint: disable=invalid-name
        try:
            tables = self.ryu_table_translator.create_ryu_structure()
            return self._create_tables(tables, dp)
        except (ValueError, IOError) as err:
            print(err)
        return []

    def _create_tables(self, tables_information, dp): # pylint: disable=invalid-name
        active_table_ids = frozenset([table.table_id for table in dp.tables.values()])
        table_array = []
        for table in tables_information:
            for table_class_name, table_attr in list(table.items()):
                table_class = getattr(valve_of.parser, table_class_name)
                new_table = table_class(**table_attr)
                if new_table.table_id not in active_table_ids:
                    continue
                valve_table = dp.table_by_id(new_table.table_id)
                table_attr['properties'] = []
                table_attr['name'] = valve_table.name.encode('utf-8')
                new_table = table_class(**table_attr)
                # Match types
                if valve_table.match_types:
                    oxm_ids = [
                        valve_of.parser.OFPOxmId(type_=match_type, hasmask=hasmask)
                        for match_type, hasmask in list(valve_table.match_types.items())]
                    new_table.properties.append(
                        valve_of.parser.OFPTableFeaturePropOxm(
                            oxm_ids=oxm_ids, type_=valve_of.ofp.OFPTFPT_MATCH))
                    # Not an exact match table, assume all fields wildcarded.
                    if not valve_table.exact_match:
                        new_table.properties.append(
                            valve_of.parser.OFPTableFeaturePropOxm(
                                oxm_ids=oxm_ids, type_=valve_of.ofp.OFPTFPT_WILDCARDS))
                # Next tables
                next_tables = sorted(
                    [table_id for table_id in active_table_ids if table_id > new_table.table_id])
                if next_tables:
                    new_table.properties.append(
                        valve_of.parser.OFPTableFeaturePropNextTables(
                            table_ids=next_tables, type_=valve_of.ofp.OFPTFPT_NEXT_TABLES))
                # Instructions
                insts = set([valve_of.ofp.OFPIT_APPLY_ACTIONS])
                if next_tables:
                    insts.add(valve_of.ofp.OFPIT_GOTO_TABLE)
                if valve_table.table_config.meter:
                    insts.add(valve_of.ofp.OFPIT_METER)
                inst_ids = [
                    valve_of.parser.OFPInstructionId(type_) for type_ in insts]
                new_table.properties.append(
                    valve_of.parser.OFPTableFeaturePropInstructions(
                        type_=valve_of.ofp.OFPTFPT_INSTRUCTIONS, instruction_ids=inst_ids))
                apply_actions = set()
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
                    if dp.group_table or dp.group_table_routing:
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


class OpenflowToRyuTranslator:
    """Translate JSON description of OF class, to Ryu OF class."""

    openflow_to_ryu = json.loads("""
{
    "tables" : {
        "OFPTFPT_INSTRUCTIONS": {
            "name" : "OFPTableFeaturePropInstructions",
            "action_tag" : "instruction_ids"
        },
        "OFPTFPT_INSTRUCTIONS_MISS": {
            "name" : "OFPTableFeaturePropInstructions",
            "action_tag" : "instruction_ids"
        },
        "OFPTFPT_NEXT_TABLES": {
            "name" : "OFPTableFeaturePropNextTables",
            "action_tag" : "table_ids"
        },
        "OFPTFPT_NEXT_TABLES_MISS": {
            "name" : "OFPTableFeaturePropNextTables",
            "action_tag" : "table_ids"
        },
        "OFPTFPT_WRITE_ACTIONS": {
            "name" : "OFPTableFeaturePropActions",
            "action_tag" : "action_ids"
        },
        "OFPTFPT_WRITE_ACTIONS_MISS": {
            "name" : "OFPTableFeaturePropActions",
            "action_tag" : "action_ids"
        },
        "OFPTFPT_APPLY_ACTIONS": {
            "name" : "OFPTableFeaturePropActions",
            "action_tag" : "action_ids"
        },
        "OFPTFPT_APPLY_ACTIONS_MISS": {
            "name" : "OFPTableFeaturePropActions",
            "action_tag" : "action_ids"
        },
        "OFPTFPT_MATCH": {
            "name" : "OFPTableFeaturePropOxm",
            "action_tag" : "oxm_ids"
        },
        "OFPTFPT_WILDCARDS": {
            "name" : "OFPTableFeaturePropOxm",
            "action_tag" : "oxm_ids"
        },
        "OFPTFPT_WRITE_SETFIELD": {
            "name" : "OFPTableFeaturePropOxm",
            "action_tag" : "oxm_ids"
        },
        "OFPTFPT_WRITE_SETFIELD_MISS": {
            "name" : "OFPTableFeaturePropOxm",
            "action_tag" : "oxm_ids"
        },
        "OFPTFPT_APPLY_SETFIELD": {
            "name" : "OFPTableFeaturePropOxm",
            "action_tag" : "oxm_ids"
        },
        "OFPTFPT_APPLY_SETFIELD_MISS": {
            "name" : "OFPTableFeaturePropOxm",
            "action_tag" : "oxm_ids"
        }
    },
    "content" : {
        "instruction_ids": "OFPInstructionId",
        "table_ids": [],
        "action_ids": "OFPActionId",
        "oxm_ids": "OFPOxmId"
    },
    "table_tag": "OFPTableFeaturesStats"
}
""")

    def __init__(self, cfgpath, pipeline_conf):
        with open(os.path.join(cfgpath, pipeline_conf)) as pipeline_file:
            self.pipeline_conf = json.loads(pipeline_file.read())

    def create_ryu_structure(self):
        tables = []
        for openflow_table in self.pipeline_conf:
            tables.append(
                self._create_table(
                    table_id=openflow_table['table_id'],
                    name=str(openflow_table['table_id']),
                    config=3,
                    max_entries=openflow_table['max_entries'],
                    metadata_match=0,
                    metadata_write=0,
                    properties=[]))
        return tables

    def _create_table(self, table_id, name, config, max_entries,
                      metadata_match, metadata_write, properties):
        return {
            self.openflow_to_ryu['table_tag']: {
                'config': config,
                'max_entries': max_entries,
                'metadata_match': metadata_match,
                'metadata_write': metadata_write,
                'name': name,
                'properties': properties,
                'table_id': table_id}}
