#!/usr/bin/env python3

"""Dynamically generate config fuzzer configuration & dict examples"""

import os

import networkx
from networkx.generators.atlas import graph_atlas_g

from clib.config_generator import FaucetFakeOFTopoGenerator

from faucet.acl import ACL
from faucet.meter import Meter
from faucet.port import Port
from faucet.router import Router
from faucet.dp import DP
from faucet.vlan import VLAN
from faucet.config_parser import V2_TOP_CONFS


class ConfigDictGenerator:
    """Generate config fuzzer dict"""

    serial = 0

    @staticmethod
    def create_config_dict(file_name):
        """Generate YAML dictionary via obtaining possible variables from Faucet CONF objects"""
        with open(file_name, 'r+', encoding='utf-8') as config_file:
            # Read set of bogus values already currently in the config.dict file
            bogus_values = []
            for value in config_file.readlines():
                # Remove quotes and \n from bogus value to get the true bogus value
                bogus_values.append(fr'{value[1:2]}')
            # Make sure to add head values into the dictionary
            for value in V2_TOP_CONFS:
                for bogus in bogus_values:
                    to_write = fr'{value}{bogus}'
                    rev_to_write = fr'{bogus}{value}'
                    if (to_write in bogus_values
                            or rev_to_write in bogus_values
                            or value in bogus_values):
                        continue
                    config_file.write(f'\n"{to_write}"')
                    config_file.write(f'\n"{rev_to_write}"')
            # Find CONF objects config file options
            for conf_obj in [ACL, Meter, Port, Router, DP, VLAN]:
                for value in conf_obj.defaults:
                    for bogus in bogus_values:
                        to_write = fr'{value}{bogus}'
                        rev_to_write = fr'{bogus}{value}'
                        if (to_write in bogus_values
                                or rev_to_write in bogus_values
                                or value in bogus_values):
                            continue
                        config_file.write(f'\n"{to_write}"')
                        config_file.write(f'\n"{rev_to_write}"')

    def create_examples(self, file_base, file_name):
        """Generate some initial starting configs by generating them via the config_generator"""
        ex_curr = 0

        num_hosts = 1
        num_vlans = 2

        def get_serialno(*_args, **_kwargs):
            """"Return mock serial number"""
            self.serial += 1
            return self.serial

        def create_config(network_graph, stack=True):
            """Return topo object and a simple stack config generated from network_graph"""
            host_links = {}
            host_vlans = {}
            dp_options = {}
            host_n = 0
            for dp_i in network_graph.nodes():
                for _ in range(num_hosts):
                    for v_i in range(num_vlans):
                        host_links[host_n] = [dp_i]
                        host_vlans[host_n] = v_i
                        host_n += 1
                dp_options[dp_i] = {'hardware': 'GenericTFM'}
                if dp_i == 0 and stack:
                    dp_options[dp_i]['stack'] = {'priority': 1}
            switch_links = list(network_graph.edges()) * 2
            if stack:
                link_vlans = {link: None for link in switch_links}
            else:
                link_vlans = {link: list(range(num_vlans)) for link in switch_links}
            topo = FaucetFakeOFTopoGenerator(
                'ovstype', 'portsock', 'testname',
                len(network_graph.nodes()), False,
                host_links, host_vlans, switch_links, link_vlans,
                start_port=1, port_order=[0, 1, 2, 3],
                get_serialno=get_serialno)
            config = topo.get_config(num_vlans, dp_options=dp_options)
            return config

        configs = []
        topologies = graph_atlas_g()
        for graph in topologies:
            if not graph or not networkx.is_connected(graph):
                continue
            if len(graph.nodes()) > 4:
                break
            for stack in (True, False):
                configs.append(create_config((graph), stack=stack))
        for config in configs:
            ex_fn = os.path.join(file_base, f'{file_name}_{ex_curr}')
            with open(ex_fn, 'w+', encoding='utf-8') as ex_file:
                ex_file.write(config)
            ex_curr += 1


if __name__ == '__main__':
    generator = ConfigDictGenerator()
    generator.create_config_dict('config.dict')
    generator.create_examples('examples/', 'ex')
