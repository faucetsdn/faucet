"""Implement configuration file parsing."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import re

from faucet import config_parser_util
from faucet.acl import ACL
from faucet.conf import test_config_condition, InvalidConfigError
from faucet.dp import DP
from faucet.meter import Meter
from faucet.port import Port
from faucet.router import Router
from faucet.vlan import VLAN
from faucet.watcher_conf import WatcherConf


V2_TOP_CONFS = (
    'acls',
    'dps',
    'meters',
    'routers',
    'vlans')


def dp_parser(config_file, logname):
    """Parse a config file into DP configuration objects with hashes of config include/files."""
    conf = config_parser_util.read_config(config_file, logname)
    config_hashes = None
    dps = None

    test_config_condition(conf is None, 'Config file is empty')
    test_config_condition(not isinstance(conf, dict), 'Config file does not have valid syntax')
    version = conf.pop('version', 2)
    test_config_condition(version != 2, 'Only config version 2 is supported')
    config_hashes, dps = _config_parser_v2(config_file, logname)
    test_config_condition(dps is None, 'no DPs are not defined')

    return config_hashes, dps


def _dp_parser_v2(acls_conf, dps_conf, meters_conf,
                  routers_conf, vlans_conf):
    dps = []

    def _get_vlan_by_key(dp_id, vlan_key, vlans):
        test_config_condition(not isinstance(vlan_key, (str, int)), (
            'VLAN key must not be type %s' % type(vlan_key)))
        if vlan_key in vlans:
            return vlans[vlan_key]
        for vlan in list(vlans.values()):
            if vlan_key == str(vlan.vid):
                return vlan
        # Create VLAN with VID, if not defined.
        return vlans.setdefault(vlan_key, VLAN(vlan_key, dp_id))

    def _dp_parse_port(dp_id, port_key, port_conf, vlans):
        port = Port(port_key, dp_id, port_conf)
        test_config_condition(str(port_key) not in (str(port.number), port.name), (
            'Port key %s match port name or port number' % port_key))

        def _dp_parse_native_port_vlan():
            if port.native_vlan is not None:
                vlan = _get_vlan_by_key(dp_id, port.native_vlan, vlans)
                port.native_vlan = vlan

        def _dp_parse_tagged_port_vlans():
            if port.tagged_vlans:
                port_tagged_vlans = [
                    _get_vlan_by_key(dp_id, vlan_key, vlans) for vlan_key in port.tagged_vlans]
                port.tagged_vlans = port_tagged_vlans

        _dp_parse_native_port_vlan()
        _dp_parse_tagged_port_vlans()
        return port

    def _dp_add_ports(dp, dp_conf, dp_id, vlans):
        ports_conf = dp_conf.get('interfaces', {})
        port_ranges_conf = dp_conf.get('interface_ranges', {})
        # as users can config port vlan by using vlan name, we store vid in
        # Port instance instead of vlan name for data consistency
        test_config_condition(not isinstance(ports_conf, dict), (
            'Invalid syntax in interface config'))
        test_config_condition(not isinstance(port_ranges_conf, dict), (
            'Invalid syntax in interface ranges config'))
        port_num_to_port_conf = {}
        for port_key, port_conf in list(ports_conf.items()):
            test_config_condition(not isinstance(port_conf, dict), 'Invalid syntax in port config')
            if 'number' in port_conf:
                port_num = port_conf['number']
            else:
                port_num = port_key
            try:
                port_num_to_port_conf[port_num] = (port_key, port_conf)
            except TypeError:
                raise InvalidConfigError('Invalid syntax in port config')
        for port_range, port_conf in list(port_ranges_conf.items()):
            # port range format: 1-6 OR 1-6,8-9 OR 1-3,5,7-9
            test_config_condition(not isinstance(port_conf, dict), 'Invalid syntax in port config')
            port_nums = set()
            if 'number' in port_conf:
                del port_conf['number']
            for range_ in re.findall(r'(\d+-\d+)', str(port_range)):
                start_num, end_num = [int(num) for num in range_.split('-')]
                test_config_condition(start_num >= end_num, (
                    'Incorrect port range (%d - %d)' % (start_num, end_num)))
                port_nums.update(list(range(start_num, end_num + 1)))
                port_range = re.sub(range_, '', port_range)
            other_nums = [int(p) for p in re.findall(r'\d+', str(port_range))]
            port_nums.update(other_nums)
            test_config_condition(not port_nums, 'interface-ranges contain invalid config')
            for port_num in port_nums:
                if port_num in port_num_to_port_conf:
                    # port range config has lower priority than individual port config
                    for attr, value in list(port_conf.items()):
                        port_num_to_port_conf[port_num][1].setdefault(attr, value)
                else:
                    port_num_to_port_conf[port_num] = (port_num, port_conf)
        for port_num, port_conf in list(port_num_to_port_conf.values()):
            port = _dp_parse_port(dp_id, port_num, port_conf, vlans)
            dp.add_port(port)
        dp.reset_refs(vlans=vlans)

    for dp_key, dp_conf in list(dps_conf.items()):
        test_config_condition(not isinstance(dp_conf, dict), '')
        dp = DP(dp_key, dp_conf.get('dp_id', None), dp_conf)
        test_config_condition(dp.name != dp_key, (
            'DP key %s and DP name must match' % dp_key))
        dp_id = dp.dp_id

        vlans = {}
        for vlan_key, vlan_conf in list(vlans_conf.items()):
            vlan = VLAN(vlan_key, dp_id, vlan_conf)
            vlans[vlan_key] = vlan
            test_config_condition(str(vlan_key) not in (str(vlan.vid), vlan.name), (
                'VLAN %s key must match VLAN name or VLAN VID' % vlan_key))
        for acl_key, acl_conf in list(acls_conf.items()):
            acl = ACL(acl_key, dp_id, acl_conf)
            dp.add_acl(acl_key, acl)
        for router_key, router_conf in list(routers_conf.items()):
            router = Router(router_key, dp_id, router_conf)
            dp.add_router(router_key, router)
        for meter_key, meter_conf in list(meters_conf.items()):
            meter = Meter(meter_key, dp_id, meter_conf)
            dp.meters[meter_key] = meter
        _dp_add_ports(dp, dp_conf, dp_id, vlans)
        dps.append(dp)

    for dp in dps:
        dp.finalize_config(dps)
    for dp in dps:
        dp.resolve_stack_topology(dps)

    router_ref_dps = collections.defaultdict(set)
    for dp in dps:
        for router in list(dp.routers.keys()):
            router_ref_dps[router].add(dp)
    for router in list(routers_conf.keys()):
        test_config_condition(not router_ref_dps[router], (
            'router %s configured but not used by any DP' % router))

    return dps


def _config_parser_v2(config_file, logname):
    config_path = config_parser_util.dp_config_path(config_file)
    top_confs = {}
    config_hashes = {}
    dps = None
    for top_conf in V2_TOP_CONFS:
        top_confs[top_conf] = {}

    if not config_parser_util.dp_include(
            config_hashes, config_path, logname, top_confs):
        raise InvalidConfigError('Error found while loading config file: %s' % config_path)
    elif not top_confs['dps']:
        raise InvalidConfigError('DPs not configured in file: %s' % config_path)
    else:
        dps = _dp_parser_v2(
            top_confs['acls'],
            top_confs['dps'],
            top_confs['meters'],
            top_confs['routers'],
            top_confs['vlans'])
    return (config_hashes, dps)


def get_config_for_api(valves):
    """Return config as dict for all DPs."""
    config = {}
    for i in V2_TOP_CONFS:
        config[i] = {}
    for valve in list(valves.values()):
        valve_conf = valve.get_config_dict()
        for i in V2_TOP_CONFS:
            if i in valve_conf:
                config[i].update(valve_conf[i])
    return config


def watcher_parser(config_file, logname, prom_client):
    """Return Watcher instances from config."""
    conf = config_parser_util.read_config(config_file, logname)
    return _watcher_parser_v2(conf, logname, prom_client)


def _watcher_parser_v2(conf, logname, prom_client):
    logger = config_parser_util.get_logger(logname)
    result = []

    if conf is None:
        conf = {}

    dps = {}
    if 'faucet_configs' in conf:
        for faucet_file in conf['faucet_configs']:
            _, dp_list = dp_parser(faucet_file, logname)
            if dp_list:
                for dp in dp_list:
                    dps[dp.name] = dp

    if 'faucet' in conf:
        faucet_conf = conf['faucet']
        acls = faucet_conf.get('acls', {})
        fct_dps = faucet_conf.get('dps', {})
        meters = faucet_conf.get('meters', {})
        routers = faucet_conf.get('routers', {})
        vlans = faucet_conf.get('vlans', {})
        for dp in _dp_parser_v2(acls, fct_dps, meters, routers, vlans):
            dps[dp.name] = dp

    if not dps:
        raise InvalidConfigError(
            'Gauge configured without any FAUCET configuration'
            )

    dbs = conf.pop('dbs')

    # pylint: disable=fixme
    for watcher_name, watcher_conf in list(conf['watchers'].items()):
        if watcher_conf.get('all_dps', False):
            watcher_dps = list(dps.keys())
        else:
            watcher_dps = watcher_conf['dps']
        # Watcher config has a list of DPs, but actually a WatcherConf is
        # created for each DP.
        # TODO: refactor watcher_conf as a container.
        for dp_name in watcher_dps:
            if dp_name not in dps:
                logger.error('DP %s in Gauge but not configured in FAUCET', dp_name)
                continue
            dp = dps[dp_name]
            if 'dbs' in watcher_conf:
                watcher_dbs = watcher_conf['dbs']
            elif 'db' in watcher_conf:
                watcher_dbs = [watcher_conf['db']]
            else:
                raise InvalidConfigError('Watcher configured without DB')
            for db in watcher_dbs:
                watcher = WatcherConf(watcher_name, dp.dp_id, watcher_conf, prom_client)
                watcher.add_db(dbs[db])
                watcher.add_dp(dp)
                result.append(watcher)

    return result
