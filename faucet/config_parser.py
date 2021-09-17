#!/usr/bin/env python3

"""Implement configuration file parsing."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
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

import copy
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


def dp_parser(config_file, logname, meta_dp_state=None):
    """Parse a config file into DP configuration objects with hashes of config include/files."""
    conf, _ = config_parser_util.read_config(config_file, logname)
    config_hashes = None
    dps = None

    test_config_condition(conf is None, 'Config file is empty')
    test_config_condition(
        not isinstance(conf, dict),
        'Config file does not have valid syntax')
    version = conf.pop('version', 2)
    test_config_condition(version != 2, 'Only config version 2 is supported')
    config_hashes, config_contents, dps, top_conf = _config_parser_v2(
        config_file, logname, meta_dp_state)
    test_config_condition(dps is None, 'no DPs are not defined')

    return config_hashes, config_contents, dps, top_conf


def _get_vlan_by_key(dp_id, vlan_key, vlans):
    try:
        if vlan_key in vlans:
            return vlans[vlan_key]
    except TypeError as err:
        raise InvalidConfigError(err) from err
    for vlan in vlans.values():
        if vlan_key == vlan.vid:
            return vlan
    test_config_condition(not isinstance(vlan_key, int), (
        f'Implicitly created VLAN {vlan_key} must be an int (not {type(vlan_key)})'))
    # Create VLAN with VID, if not defined.
    return vlans.setdefault(vlan_key, VLAN(vlan_key, dp_id))


def _dp_parse_port(dp_id, port_key, port_conf, vlans):

    def _dp_parse_native_port_vlan():
        if port.native_vlan is not None:
            vlan = _get_vlan_by_key(dp_id, port.native_vlan, vlans)
            port.native_vlan = vlan

    def _dp_parse_tagged_port_vlans():
        if port.tagged_vlans:
            port_tagged_vlans = [
                _get_vlan_by_key(dp_id, vlan_key, vlans) for vlan_key in port.tagged_vlans]
            port.tagged_vlans = port_tagged_vlans

    port = Port(port_key, dp_id, port_conf)
    test_config_condition(str(port_key) not in (str(port.number), port.name), (
        f'Port key {port_key} match port name or port number'))
    _dp_parse_native_port_vlan()
    _dp_parse_tagged_port_vlans()
    return port


def _dp_add_ports(dp, dp_conf, dp_id, vlans):
    ports_conf = dp_conf.get('interfaces', {})
    port_ranges_conf = dp_conf.get('interface_ranges', {})
    # as users can config port VLAN by using VLAN name, we store vid in
    # Port instance instead of VLAN name for data consistency
    test_config_condition(not isinstance(ports_conf, dict), (
        'Invalid syntax in interface config'))
    test_config_condition(not isinstance(port_ranges_conf, dict), (
        'Invalid syntax in interface ranges config'))

    def _map_port_num_to_port(ports_conf):
        port_num_to_port_conf = {}
        for port_key, port_conf in ports_conf.items():
            test_config_condition(not isinstance(port_conf, dict), 'Invalid syntax in port config')
            port_num = port_conf.get('number', port_key)
            try:
                port_num_to_port_conf[port_num] = (port_key, port_conf)
            except TypeError as type_error:
                raise InvalidConfigError('Invalid syntax in port config') from type_error
        return port_num_to_port_conf

    def _parse_port_ranges(port_ranges_conf, port_num_to_port_conf):
        all_port_nums = set()
        for port_range, port_conf in port_ranges_conf.items():
            # port range format: 1-6 OR 1-6,8-9 OR 1-3,5,7-9
            test_config_condition(not isinstance(port_conf, dict), 'Invalid syntax in port config')
            port_nums = set()
            if 'number' in port_conf:
                del port_conf['number']
            for range_ in re.findall(r'(\d+-\d+)', str(port_range)):
                start_num, end_num = [int(num) for num in range_.split('-')]
                test_config_condition(start_num >= end_num, (
                    f'Incorrect port range ({start_num} - {end_num})'))
                port_nums.update(range(start_num, end_num + 1))
                port_range = re.sub(range_, '', port_range)
            other_nums = [int(p) for p in re.findall(r'\d+', str(port_range))]
            port_nums.update(other_nums)
            test_config_condition(
                not port_nums, 'interface-ranges contain invalid config')
            test_config_condition(
                port_nums.intersection(all_port_nums), 'interfaces-ranges cannot overlap')
            all_port_nums.update(port_nums)
            for port_num in port_nums:
                if port_num in port_num_to_port_conf:
                    # port range config has lower priority than individual port config
                    for attr, value in port_conf.items():
                        port_num_to_port_conf[port_num][1].setdefault(attr, value)
                else:
                    port_num_to_port_conf[port_num] = (port_num, port_conf)

    port_num_to_port_conf = _map_port_num_to_port(ports_conf)
    _parse_port_ranges(port_ranges_conf, port_num_to_port_conf)

    for port_num, port_conf in port_num_to_port_conf.values():
        port = _dp_parse_port(dp_id, port_num, port_conf, vlans)
        dp.add_port(port)


def _parse_acls(dp, acls_conf):
    for acl_key, acl_conf in acls_conf.items():
        acl = ACL(acl_key, dp.dp_id, acl_conf)
        dp.add_acl(acl_key, acl)


def _parse_routers(dp, routers_conf):
    for router_key, router_conf in routers_conf.items():
        router = Router(router_key, dp.dp_id, router_conf)
        dp.add_router(router_key, router)


def _parse_meters(dp, meters_conf):
    for meter_key, meter_conf in meters_conf.items():
        meter = Meter(meter_key, dp.dp_id, meter_conf)
        dp.meters[meter_key] = meter


def _parse_dp(dp_key, dp_conf, acls_conf, meters_conf, routers_conf, vlans_conf):
    test_config_condition(not isinstance(dp_conf, dict), 'DP config must be dict')
    dp = DP(dp_key, dp_conf.get('dp_id', None), dp_conf)
    test_config_condition(dp.name != dp_key, (
        f'DP key {dp_key} and DP name must match'))
    vlans = {}
    vids = set()
    for vlan_key, vlan_conf in vlans_conf.items():
        vlan = VLAN(vlan_key, dp.dp_id, vlan_conf)
        test_config_condition(str(vlan_key) not in (str(vlan.vid), vlan.name), (
            f'VLAN {vlan_key} key must match VLAN name or VLAN VID'))
        test_config_condition(not isinstance(vlan_key, (str, int)), (
            f'VLAN {vlan_key} key must not be type {type(vlan_key)}'))
        test_config_condition(vlan.vid in vids, (
            f'VLAN VID {vlan.vid} multiply configured'))
        vlans[vlan_key] = vlan
        vids.add(vlan.vid)
    _parse_acls(dp, acls_conf)
    _parse_routers(dp, routers_conf)
    _parse_meters(dp, meters_conf)
    _dp_add_ports(dp, dp_conf, dp.dp_id, vlans)
    return (dp, vlans)


def _dp_parser_v2(dps_conf, acls_conf, meters_conf,
                  routers_conf, vlans_conf, meta_dp_state):
    # pylint: disable=invalid-name
    dp_vlans = []
    for dp_key, dp_conf in dps_conf.items():
        try:
            dp, vlans = _parse_dp(
                dp_key, dp_conf, acls_conf, meters_conf, routers_conf, vlans_conf)
            dp_vlans.append((dp, vlans))
        except InvalidConfigError as err:
            raise InvalidConfigError(f'DP {dp_key}: {err}') from err

    # Some VLANs are created implicitly just by referencing them in tagged/native,
    # so we must make them available to all DPs.
    implicit_vids = set()
    for dp, vlans in dp_vlans:
        implicit_vids.update(set(vlans.keys()) - set(vlans_conf.keys()))
    dps = []
    for dp, vlans in dp_vlans:
        for vlan_key in implicit_vids:
            if vlan_key not in vlans:
                vlans[vlan_key] = VLAN(vlan_key, dp.dp_id)
        dp.reset_refs(vlans=vlans)
        dps.append(dp)

    for dp in dps:
        dp.finalize_config(dps)
    for dp in dps:
        dp.resolve_stack_topology(dps, meta_dp_state)
    for dp in dps:
        dp.finalize()

    dpid_refs = set()
    for dp in dps:
        test_config_condition(dp.dp_id in dpid_refs, (
            f'DPID {dp.dp_id} is duplicated'))
        dpid_refs.add(dp.dp_id)

    routers_referenced = set()
    for dp in dps:
        routers_referenced.update(dp.routers.keys())
    for router in routers_conf:
        test_config_condition(router not in routers_referenced, (
            f'router {router} configured but not used by any DP'))

    return dps


def dp_preparsed_parser(top_confs, meta_dp_state):
    """Parse a preparsed (after include files have been applied) FAUCET config."""
    local_top_confs = copy.deepcopy(top_confs)
    return _dp_parser_v2(
        local_top_confs.get('dps', {}),
        local_top_confs.get('acls', {}),
        local_top_confs.get('meters', {}),
        local_top_confs.get('routers', {}),
        local_top_confs.get('vlans', {}),
        meta_dp_state)


def _config_parser_v2(config_file, logname, meta_dp_state):
    config_path = config_parser_util.dp_config_path(config_file)
    top_confs = {top_conf: {} for top_conf in V2_TOP_CONFS}
    config_hashes = {}
    config_contents = {}
    dps = None

    if not config_parser_util.dp_include(
            config_hashes, config_contents, config_path, logname, top_confs):
        raise InvalidConfigError(f'Error found while loading config file: {config_path}')

    if not top_confs['dps']:
        raise InvalidConfigError(f'DPs not configured in file: {config_path}')

    dps = dp_preparsed_parser(top_confs, meta_dp_state)
    return (config_hashes, config_contents, dps, top_confs)


def watcher_parser(config_file, logname, prom_client):
    """Return Watcher instances from config."""
    conf, _ = config_parser_util.read_config(config_file, logname)
    conf_hash = config_parser_util.config_file_hash(config_file)
    faucet_config_files, faucet_conf_hashes, result = _watcher_parser_v2(
        conf, logname, prom_client)
    return conf_hash, faucet_config_files, faucet_conf_hashes, result


def _parse_dps_for_watchers(conf, logname, meta_dp_state=None):
    all_dps_list = []
    faucet_conf_hashes = {}

    if not isinstance(conf, dict):
        raise InvalidConfigError('Gauge config not valid')

    faucet_config_files = conf.get('faucet_configs', [])
    for faucet_config_file in faucet_config_files:
        conf_hashes, _, dp_list, _ = dp_parser(faucet_config_file, logname)
        if dp_list:
            faucet_conf_hashes[faucet_config_file] = conf_hashes
            all_dps_list.extend(dp_list)

    faucet_config = conf.get('faucet', None)
    if faucet_config:
        all_dps_list.extend(dp_preparsed_parser(faucet_config, meta_dp_state))

    dps = {dp.name: dp for dp in all_dps_list}
    if not dps:
        raise InvalidConfigError(
            'Gauge configured without any FAUCET configuration')
    return faucet_config_files, faucet_conf_hashes, dps


def _watcher_parser_v2(conf, logname, prom_client):
    logger = config_parser_util.get_logger(logname)

    if conf is None:
        conf = {}
    faucet_config_files, faucet_conf_hashes, dps = _parse_dps_for_watchers(
        conf, logname)
    dbs = conf.pop('dbs')

    result = []
    for watcher_name, watcher_conf in conf['watchers'].items():
        if watcher_conf.get('all_dps', False):
            watcher_dps = dps.keys()
        else:
            watcher_dps = watcher_conf['dps']
        # Watcher config has a list of DPs, but actually a WatcherConf is
        # created for each DP.
        # TODO: refactor watcher_conf as a container.
        for dp_name in watcher_dps:
            if dp_name not in dps:
                logger.error(f'DP {dp_name} in Gauge but not configured in FAUCET')
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

    return faucet_config_files, faucet_conf_hashes, result


def get_config_for_api(valves):
    """Return config as dict for all DPs."""
    config = {i: {} for i in V2_TOP_CONFS}
    for valve in valves.values():
        valve_conf = valve.get_config_dict()
        for i in V2_TOP_CONFS:
            if i in valve_conf:
                config[i].update(valve_conf[i])  # pytype: disable=attribute-error
    return config
