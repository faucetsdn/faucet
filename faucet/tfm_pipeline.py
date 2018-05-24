"""Parse JSON for TFM based table config."""

import json
import os

from faucet import valve_of


class LoadRyuTables(object):
    """Serialize table features messages from JSON."""

    _CLASS_NAME_TO_NAME_IDS = {
        'OFPTableFeaturePropInstructions': 'instruction_ids',
        'OFPTableFeaturePropNextTables': 'table_ids',
        'OFPTableFeaturePropActions': 'action_ids',
        'OFPTableFeaturePropOxm': 'oxm_ids'}

    _SKIP_PROPERTIES = set([
        'OFPTableFeaturePropNextTables',
    ])

    def __init__(self, cfgpath, pipeline_conf):
        self.ryu_table_translator = OpenflowToRyuTranslator(
            cfgpath, pipeline_conf)

    def load_tables(self, active_table_ids):
        try:
            tables = self.ryu_table_translator.create_ryu_structure()
            return self._create_tables(tables, active_table_ids)
        except (ValueError, IOError) as err:
            print(err)
        return []

    def _create_tables(self, tables_information, active_table_ids):
        table_array = []
        for table in tables_information:
            for table_class_name, table_attr in list(table.items()):
                table_class = getattr(valve_of.parser, table_class_name,)
                properties = self._create_features(table_attr['properties'])
                table_attr['properties'] = properties
                table_attr['name'] = table_attr['name'].encode('utf-8')
                new_table = table_class(**table_attr)
                next_tables = sorted(
                    [table_id for table_id in active_table_ids if table_id > new_table.table_id])
                if next_tables:
                    new_table.properties.append(
                        valve_of.parser.OFPTableFeaturePropNextTables(table_ids=next_tables, type_=2))
                if new_table.table_id in active_table_ids:
                    table_array.append(new_table)
        return table_array

    def _create_features(self, table_features_information):
        features_array = []
        for feature in table_features_information:
            for feature_class_name, feature_attr in list(feature.items()):
                name_id = self._CLASS_NAME_TO_NAME_IDS[feature_class_name]
                if feature_class_name in self._SKIP_PROPERTIES:
                    continue
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


class OpenflowToRyuTranslator(object):

    def __init__(self, cfgpath, pipeline_conf):
        with open(os.path.join(cfgpath, 'ofproto_to_ryu.json')) as ofproto_file:
            self.openflow_to_ryu = json.loads(ofproto_file.read())
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
                    name=openflow_table['name'],
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
