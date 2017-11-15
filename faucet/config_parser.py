"""Implement configuration file parsing."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
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

from faucet import config_parser_util
from faucet.acl import ACL
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
    logger = config_parser_util.get_logger(logname)
    conf = config_parser_util.read_config(config_file, logname)
    config_hashes = None
    dps = None

    if conf is not None:
        version = conf.pop('version', 2)
        if version != 2:
            logger.fatal('Only config version 2 is supported')

        config_hashes, dps = _config_parser_v2(config_file, logname)
    return config_hashes, dps


def _dp_parser_v2(logger, acls_conf, dps_conf, meters_conf,
                  routers_conf, vlans_conf):
    dps = []
    vid_dp = collections.defaultdict(set)

    def _get_vlan_by_identifier(dp_id, vlan_ident, vlans):
        if vlan_ident in vlans:
            return vlans[vlan_ident]
        for vlan in list(vlans.values()):
            if vlan_ident == str(vlan.vid):
                return vlan
        try:
            vid = int(str(vlan_ident), 0)
        except ValueError:
            assert False, 'VLAN VID value (%s) is invalid' % vlan_ident

        return vlans.setdefault(vlan_ident, VLAN(vid, dp_id))

    def _dp_add_vlan(dp, vlan):
        if vlan not in dp.vlans:
            dp.add_vlan(vlan)
            vid_dp[vlan.vid].add(dp.name)

            if len(vid_dp[vlan.vid]) > 1:
                assert not vlan.bgp_routerid, (
                    'DPs %s sharing a BGP speaker VLAN is unsupported' % (
                        str.join(', ', vid_dp[vlan.vid])))

    def _dp_parse_port(dp_id, p_identifier, port_conf, vlans):
        port = Port(p_identifier, port_conf)

        if port.native_vlan is not None:
            v_identifier = port.native_vlan
            vlan = _get_vlan_by_identifier(dp_id, v_identifier, vlans)
            port.native_vlan = vlan
            vlan.add_untagged(port)
        port_tagged_vlans = [
            _get_vlan_by_identifier(dp_id, v_identifier, vlans) for v_identifier in port.tagged_vlans]
        port.tagged_vlans = port_tagged_vlans
        for vlan in port.tagged_vlans:
            vlan.add_tagged(port)

        for vlan in port.vlans():
            _dp_add_vlan(dp, vlan)

        return port

    def _dp_add_ports(dp, dp_conf, dp_id, vlans):
        ports_conf = dp_conf.pop('interfaces', {})
        # as users can config port vlan by using vlan name, we store vid in
        # Port instance instead of vlan name for data consistency
        for port_num, port_conf in list(ports_conf.items()):
            port = _dp_parse_port(dp_id, port_num, port_conf, vlans)
            dp.add_port(port)


    try:
        for identifier, dp_conf in list(dps_conf.items()):
            dp = DP(identifier, dp_conf)
            dp.sanity_check()
            dp_id = dp.dp_id

            vlans = {}
            for vlan_ident, vlan_conf in list(vlans_conf.items()):
                vlans[vlan_ident] = VLAN(vlan_ident, dp_id, vlan_conf)
            acls = []
            for acl_ident, acl_conf in list(acls_conf.items()):
                acls.append((acl_ident, ACL(acl_ident, acl_conf)))
            for router_ident, router_conf in list(routers_conf.items()):
                router = Router(router_ident, router_conf)
                dp.add_router(router_ident, router)
            for meter_ident, meter_conf in list(meters_conf.items()):
                dp.meters[meter_ident] = Meter(meter_ident, meter_conf)
            _dp_add_ports(dp, dp_conf, dp_id, vlans)
            for acl_ident, acl in acls:
                dp.add_acl(acl_ident, acl)
            dps.append(dp)

        for dp in dps:
            dp.finalize_config(dps)
        for dp in dps:
            dp.resolve_stack_topology(dps)

    except AssertionError as err:
        logger.exception('Error in config file: %s', err)
        return None

    return dps


def _config_parser_v2(config_file, logname):
    logger = config_parser_util.get_logger(logname)
    config_path = config_parser_util.dp_config_path(config_file)
    top_confs = {}
    config_hashes = {}
    dps = None
    for top_conf in V2_TOP_CONFS:
        top_confs[top_conf] = {}

    if not config_parser_util.dp_include(
            config_hashes, config_path, logname, top_confs):
        logger.critical('error found while loading config file: %s', config_path)
    elif not top_confs['dps']:
        logger.critical('DPs not configured in file: %s', config_path)
    else:
        dps = _dp_parser_v2(
            logger,
            top_confs['acls'],
            top_confs['dps'],
            top_confs['meters'],
            top_confs['routers'],
            top_confs['vlans'])
    return (config_hashes, dps)


def get_config_for_api(valves):
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
    conf = config_parser_util.read_config(config_file, logname)
    return _watcher_parser_v2(conf, logname, prom_client)


def _watcher_parser_v2(conf, logname, prom_client):
    logger = config_parser_util.get_logger(logname)
    result = []

    dps = {}
    for faucet_file in conf['faucet_configs']:
        _, dp_list = dp_parser(faucet_file, logname)
        if dp_list:
            for dp in dp_list:
                dps[dp.name] = dp

    dbs = conf.pop('dbs')

    for name, dictionary in list(conf['watchers'].items()):
        for dp_name in dictionary['dps']:
            if dp_name not in dps:
                logger.error('dp %s metered but not configured', dp_name)
                continue
            dp = dps[dp_name]
            watcher = WatcherConf(name, dictionary, prom_client)
            watcher.add_db(dbs[watcher.db])
            watcher.add_dp(dp)
            result.append(watcher)

    return result
