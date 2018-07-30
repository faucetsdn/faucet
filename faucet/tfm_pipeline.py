"""Parse JSON for TFM based table config."""

import json
import os

from faucet import valve_of


class LoadRyuTables:
    """Serialize table features messages from JSON."""

    _DYNAMIC_FEATURES = frozenset([
        'OFPTFPT_NEXT_TABLES',
        'OFPTFPT_MATCH',
        'OFPTFPT_WILDCARDS',
        'OFPTFPT_INSTRUCTIONS',
        'OFPTFPT_APPLY_SETFIELD',
    ])

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
                properties = self._create_features(
                    table_attr['properties'], self._DYNAMIC_FEATURES)
                table_attr['properties'] = properties
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
                # Set fields
                if valve_table.set_fields:
                    oxm_ids = [
                        valve_of.parser.OFPOxmId(type_=field, hasmask=False)
                        for field in valve_table.set_fields]
                    new_table.properties.append(
                        valve_of.parser.OFPTableFeaturePropOxm(
                            oxm_ids=oxm_ids, type_=valve_of.ofp.OFPTFPT_APPLY_SETFIELD))
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
                inst_ids = [
                    valve_of.parser.OFPInstructionId(type_) for type_ in insts]
                new_table.properties.append(
                    valve_of.parser.OFPTableFeaturePropInstructions(
                        type_=valve_of.ofp.OFPTFPT_INSTRUCTIONS, instruction_ids=inst_ids))
                table_array.append(new_table)
        return table_array

    def _create_features(self, table_features_information, dynamic_features):
        features_array = []
        for feature in table_features_information:
            for feature_class_name, feature_attr in list(feature.items()):
                if feature_class_name in dynamic_features:
                    continue
                name_id = self._CLASS_NAME_TO_NAME_IDS[feature_class_name]
                feature_class = getattr(valve_of.parser, feature_class_name)
                instruction_ids = self._create_instructions(feature_attr[name_id])
                feature_attr[name_id] = instruction_ids
                feature_attr['type_'] = feature_attr.pop('type')
                new_feature = feature_class(**feature_attr)
                features_array.append(new_feature)
        return features_array

    @staticmethod
    def _create_instructions(instruction_ids_information):
        instruction_array = []
        for instruction in instruction_ids_information:
            if isinstance(instruction, dict):
                for instruction_class_name, instruction_attr in list(instruction.items()):
                    instruction_class = getattr(valve_of.parser, instruction_class_name)
                    instruction_attr['type_'] = instruction_attr.pop('type')
                    new_instruction = instruction_class(**instruction_attr)
                    instruction_array.append(new_instruction)
            else:
                instruction_array = instruction_ids_information
                break
        return instruction_array


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
            table_properties = []
            for property_item in openflow_table['properties']:
                fields_tag = self.openflow_to_ryu['tables'][property_item['name']]['action_tag']
                actions_ids = property_item[fields_tag]
                table_properties.append(
                    self._create_table_feature(
                        property_item['name'],
                        actions_ids,
                        property_item['type']))
            tables.append(
                self._create_table(
                    table_id=openflow_table['table_id'],
                    name=str(openflow_table['table_id']),
                    config=3,
                    max_entries=openflow_table['max_entries'],
                    metadata_match=0,
                    metadata_write=0,
                    properties=table_properties))
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

    def _create_table_feature(self, name, actions, type_id):
        table_feature_name = self.openflow_to_ryu['tables'][name]['name']
        instruction_id_name = self.openflow_to_ryu['tables'][name]['action_tag']
        action_id_name = self.openflow_to_ryu['content'][instruction_id_name]

        if action_id_name:
            new_array_instructions = []
            for action in actions:
                if 'name' in action:
                    action.pop('name')
                new_array_instructions.append({action_id_name: action})
        else:
            new_array_instructions = actions

        new_table_feature = {
            table_feature_name: {
                instruction_id_name: new_array_instructions,
                'type': type_id}}

        return new_table_feature
