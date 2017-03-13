# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
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

from acl import ACL
from dp import DP
from port import Port
from vlan import VLAN
from router import Router
from watcher_conf import WatcherConf

import config_parser_util


def dp_parser(config_file, logname):
    logger = config_parser_util.get_logger(logname)
    conf = config_parser_util.read_config(config_file, logname)
    if conf is None:
        return None
    version = conf.pop('version', 2)
    if version != 2:
        logger.fatal('Only config version 2 is supported')

    config_hashes, dps = _config_parser_v2(config_file, logname)
    if dps is not None:
        for dp in dps:
            try:
                dp.finalize_config(dps)
            except AssertionError as err:
                logger.exception('Error finalizing datapath configs: %s', err)
        for dp in dps:
            dp.resolve_stack_topology(dps)
    return config_hashes, dps


def port_parser(dp_id, p_identifier, port_conf, vlans):
    port = Port(p_identifier, port_conf)

    if port.mirror is not None:
        # ignore other config
        return port
    if port.native_vlan is not None:
        v_identifier = port.native_vlan
        vlan = vlans.setdefault(v_identifier, VLAN(v_identifier, dp_id))
        vlan.untagged.append(port)
    for v_identifier in port.tagged_vlans:
        vlan = vlans.setdefault(v_identifier, VLAN(v_identifier, dp_id))
        vlan.tagged.append(port)

    return port


def _dp_add_vlan(vid_dp, dp, vlan):
    if vlan.vid not in vid_dp:
        vid_dp[vlan.vid] = set()

    if len(vid_dp[vlan.vid]) > 1:
        assert not vlan.bgp_routerid, \
                'DPs %s sharing a BGP speaker VLAN is unsupported' % (
                    str.join(", ", vid_dp[vlan.vid]))

    if vlan not in dp.vlans:
        dp.add_vlan(vlan)

    vid_dp[vlan.vid].add(dp.name)


def _dp_parser_v2(logger, acls_conf, dps_conf, routers_conf, vlans_conf):
    dps = []
    vid_dp = {}
    for identifier, dp_conf in dps_conf.iteritems():
        try:
            dp = DP(identifier, dp_conf)
            dp.sanity_check()
            dp_id = dp.dp_id

            vlans = {}
            for vid, vlan_conf in vlans_conf.iteritems():
                vlans[vid] = VLAN(vid, dp_id, vlan_conf)
            acls = []
            for acl_ident, acl_conf in acls_conf.iteritems():
                acls.append((acl_ident, ACL(acl_ident, acl_conf)))
            routers = []
            for router_ident, router_conf in routers_conf.iteritems():
                routers.append((router_ident, Router(router_ident, router_conf)))
            if routers:
                assert len(routers) == 1, 'only one router supported'
                router_ident, router = routers[0]
                assert set(router.vlans) == set(vlans.keys()), 'only global routing supported'
                dp.add_router(router_ident, router)
            ports_conf = dp_conf.pop('interfaces', {})
            ports = {}
            for port_num, port_conf in ports_conf.iteritems():
                port = port_parser(dp_id, port_num, port_conf, vlans)
                ports[port_num] = port
                if port.native_vlan is not None:
                    _dp_add_vlan(vid_dp, dp, vlans[port.native_vlan])
                if port.tagged_vlans is not None:
                    for vid in port.tagged_vlans:
                        _dp_add_vlan(vid_dp, dp, vlans[vid])
        except AssertionError as err:
            logger.exception('Error in config file: %s', err)
            return None
        for port in ports.itervalues():
            dp.add_port(port)
        for acl_ident, acl in acls:
            dp.add_acl(acl_ident, acl)
        dps.append(dp)
    return dps


def _config_parser_v2(config_file, logname):
    logger = config_parser_util.get_logger(logname)
    config_path = config_parser_util.dp_config_path(config_file)
    config_hashes = {}
    top_confs = {
        'acls': {},
        'dps': {},
        'routers': {},
        'vlans': {},
    }

    if not config_parser_util.dp_include(
            config_hashes, config_path, logname, top_confs):
        logger.critical('error found while loading config file: %s', config_path)
        return None

    if not top_confs['dps']:
        logger.critical('dps not configured in file: %s', config_path)
        return None

    dps = _dp_parser_v2(
        logger,
        top_confs['acls'],
        top_confs['dps'],
        top_confs['routers'],
        top_confs['vlans'])
    return (config_hashes, dps)


def watcher_parser(config_file, logname):
    conf = config_parser_util.read_config(config_file, logname)
    return _watcher_parser_v2(conf, logname)


def _watcher_parser_v2(conf, logname):
    logger = config_parser_util.get_logger(logname)
    result = []

    dps = {}
    for faucet_file in conf['faucet_configs']:
        _, dp_list = dp_parser(faucet_file, logname)
        for dp in dp_list:
            dps[dp.name] = dp

    dbs = conf.pop('dbs')

    for name, dictionary in conf['watchers'].iteritems():
        for dp_name in dictionary['dps']:
            if dp_name not in dps:
                logger.error('dp %s metered but not configured', dp_name)
                continue
            dp = dps[dp_name]
            watcher = WatcherConf(name, dictionary)
            watcher.add_db(dbs[watcher.db])
            watcher.add_dp(dp)
            result.append(watcher)

    return result
