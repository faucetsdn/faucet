import inspect
import json
import os

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser

# TODO: move configuration to separate directory
CFG_PATH = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))


class LoadRyuTables(object):

    def __init__(self):
        self._ofproto_parser = None
        self.ryu_tables = []
        self._class_name_to_name_ids = {
            "OFPTableFeaturePropInstructions": "instruction_ids",
            "OFPTableFeaturePropNextTables": "table_ids",
            "OFPTableFeaturePropActions": "action_ids",
            "OFPTableFeaturePropOxm": "oxm_ids"}
        self.ryu_table_translator = OpenflowToRyuTranslator()

    def _read_json_document(self, filename):
        try:
            python_object_result = 0
            json_string = (open(filename))
            python_object_result = json.load(json_string)
            self.ryu_table_translator.set_json_document(filename)
            self.ryu_table_translator.create_ryu_structure()
            python_object_result = self.ryu_table_translator.tables
        except (ValueError, IOError) as e:
            print(e)
            python_object_result = None
        return python_object_result

    # method that will load the json file with the information of the tables
    # to convert a json file into a ryu object with all the tables
    #    ofproto: it is the protocol used by the library.
    #       Also, this library was test with ofproto_v1_3_parser
    def load_tables(self, filename, ofproto_parser):
        self.ryu_tables = []
        self._ofproto_parser = ofproto_parser
        self.tables = self._read_json_document(filename)
        if self.tables is None:
            return
        self.ryu_tables = self._create_tables(self.tables)

    # this method will create a table with all the stuff that ryu needs
    # like name, config, max entries, id, and properties. Note that it is only
    # processes tables, properties are processed by the function create_features
    def _create_tables(self, tables_information):
        table_array = []
        for table in tables_information:
            #items is used to iterate a dictionary
            for key, value in table.items():
                #getattr will get a function of the object entered, this function
                #is used to create the table with ryu classes
                table_class = getattr(self._ofproto_parser, key)
                properties = self._create_features(value["properties"])
                value["properties"] = properties
                value["name"] = str(value["name"])
                # value is a dictionary, with ** it will expand
                # it content to arguments
                new_table = table_class(**value)
                table_array.append(new_table)
        return table_array

    # same as create_tables, but it will process the properties of each table
    def _create_features(self, table_features_information):
        features_array = []
        for feature in table_features_information:
            for key, value in feature.items():
                name_id = self._class_name_to_name_ids[key]
                feature_class = getattr(self._ofproto_parser, key)
                instruction_ids = self._create_instructions(value[name_id])
                value[name_id] = instruction_ids
                value["type_"] = value.pop("type")
                new_feature = feature_class(**value)
                features_array.append(new_feature)
        return features_array

    # it will process the instructions or fields of each property
    def _create_instructions(self, instruction_ids_information):
        instruction_array = []
        for instruction in instruction_ids_information:
            if isinstance(instruction, dict):
                for key, value in instruction.items():
                    instruction_class = getattr(self._ofproto_parser, key)
                    if isinstance(value["type"], unicode):
                        value["type"] = str(value["type"])
                    value["type_"] = value.pop("type")
                    new_instruction = instruction_class(**value)
                    instruction_array.append(new_instruction)
            else:
                instruction_array = instruction_ids_information
                break
        return instruction_array


"""
This script allows dynamically create a set of tables. Each table has a set of properties that allows take some actions
depended of the incoming package. Those properties are defined ine th file "openflow_structure_tables.json", which are based on
the openflow protocol version 1.3. Also, the fields allowed in each property are written in this file, each of those fields
are accepted by the switch 5400.
The output of this script is an json file with the tables well structure. This structure is converted from openflow structure
to ryu structure using the file "ofproto_to_ryu.json", so the json file generated will be to the SDN ryu framework. But, if is
necessary convert the structure to another sdn framework, you will only have to change the file ofproto_to_ryu.
"""

class OpenflowToRyuTranslator(object):

    def __init__(self):
        self.custom_json = CustomJson()
        # file with the variables in openflow to map them into Ryu variables
        self.openflow_to_ryu = CFG_PATH  + "/ofproto_to_ryu.json"
        self.openflow_to_ryu = self.custom_json.read_json_document(
            self.openflow_to_ryu)
        # variable used to save the ryu structure tables
        self.tables = []

    def set_json_document(self, filepath):
        self.document_with_openflow_tables = filepath
        self.document_with_openflow_tables = self.custom_json.read_json_document(
            self.document_with_openflow_tables)

    # The following functions are used to create the final structure
    # (same structure that use ryu library)
    def create_ryu_structure(self):
        table_properties = []
        self.tables = []
        for openflow_table in self.document_with_openflow_tables:
            table_properties = []
            for property_item in openflow_table["properties"]:
                fields_tag = self.openflow_to_ryu["tables"][property_item["name"]]["action_tag"]
                actions_ids = property_item[fields_tag]
                table_properties.append(
                    self.create_table_feature(
                        property_item["name"],
                        actions_ids,
                        property_item["type"]))

            self.tables.append(
                self.create_table(
                    table_id=openflow_table["table_id"],
                    name=openflow_table["name"],
                    config=3,
                    max_entries=openflow_table["max_entries"],
                    metadata_match=0,
                    metadata_write=0,
                    properties=table_properties))


    def create_table(self, table_id, name, config, max_entries,
                     metadata_match, metadata_write, properties):
        return {
            self.openflow_to_ryu["table_tag"]: {
                "config": config,
                "max_entries": max_entries,
                "metadata_match": metadata_match,
                "metadata_write": metadata_write,
                "name": name,
                "properties": properties,
                "table_id": table_id}}

    def create_table_feature(self, name, actions, type_id):
        new_table_feature = {}
        new_array_instructions = []

        table_feature_name = self.openflow_to_ryu["tables"][name]["name"]
        instruction_id_name = self.openflow_to_ryu["tables"][name]["action_tag"]
        action_id_name = self.openflow_to_ryu["content"][instruction_id_name]

        if action_id_name == []:
            new_array_instructions = actions
        else:
            for action in actions:
                if "name" in action:
                    action.pop("name")
                new_array_instructions.append({action_id_name: action})

        new_table_feature = {
            table_feature_name: {
                instruction_id_name: new_array_instructions,
                "type": type_id}}

        return new_table_feature


class CustomJson(object):

    def __init__(self):
        self.json = ""

    def read_json_document(self, filename):
        python_object_result = []
        try:
            python_object_result = 0
            with open(filename) as data_file:
                python_object_result = json.load(data_file)
        except (ValueError, IOError) as e:
            print('Error found: %s' % e)
            python_object_result = []

        return python_object_result

    def save_document(self, filepath, information):
        open(filepath, 'w+').write(information)
