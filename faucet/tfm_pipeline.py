import json
import os

from ryu.ofproto import ofproto_v1_3_parser as parser


class LoadRyuTables(object):

    _CLASS_NAME_TO_NAME_IDS = {
        'OFPTableFeaturePropInstructions': 'instruction_ids',
        'OFPTableFeaturePropNextTables': 'table_ids',
        'OFPTableFeaturePropActions': 'action_ids',
        'OFPTableFeaturePropOxm': 'oxm_ids'}

    def __init__(self, cfgpath, pipeline_conf):
        self.ryu_table_translator = OpenflowToRyuTranslator(
            cfgpath, pipeline_conf)

    def load_tables(self):
        tables = None
        try:
            tables = self.ryu_table_translator.create_ryu_structure()
        except (ValueError, IOError) as e:
            print(e)
        if tables is None:
            return
        return self._create_tables(tables)

    def _create_tables(self, tables_information):
        table_array = []
        for table in tables_information:
            for k, v in list(table.items()):
                table_class = getattr(parser, k)
                properties = self._create_features(v['properties'])
                v['properties'] = properties
                v['name'] = v['name'].encode('utf-8')
                new_table = table_class(**v)
                table_array.append(new_table)
        return table_array

    def _create_features(self, table_features_information):
        features_array = []
        for feature in table_features_information:
            for k, v in list(feature.items()):
                name_id = self._CLASS_NAME_TO_NAME_IDS[k]
                feature_class = getattr(parser, k)
                instruction_ids = self._create_instructions(v[name_id])
                v[name_id] = instruction_ids
                v['type_'] = v.pop('type')
                new_feature = feature_class(**v)
                features_array.append(new_feature)
        return features_array

    def _create_instructions(self, instruction_ids_information):
        instruction_array = []
        for instruction in instruction_ids_information:
            if isinstance(instruction, dict):
                for k, v in list(instruction.items()):
                    instruction_class = getattr(parser, k)
                    v['type_'] = v.pop('type')
                    new_instruction = instruction_class(**v)
                    instruction_array.append(new_instruction)
            else:
                instruction_array = instruction_ids_information
                break
        return instruction_array


class OpenflowToRyuTranslator(object):

    def __init__(self, cfgpath, pipeline_conf):
        self.openflow_to_ryu = json.loads(
            open(os.path.join(cfgpath, 'ofproto_to_ryu.json')).read())
        self.pipeline_conf = json.loads(
            open(os.path.join(cfgpath, pipeline_conf)).read())

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
