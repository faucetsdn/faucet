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

import copy
import logging
import yaml

from dp import DP
from port import Port
from vlan import VLAN
from watcher_conf import WatcherConf

def get_logger(logname):
    return logging.getLogger(logname + '.config')

def read_config(config_file, logname):
    logger = get_logger(logname)
    try:
        with open(config_file, 'r') as stream:
            conf = yaml.safe_load(stream)
    except yaml.YAMLError as ex:
        mark = ex.problem_mark
        errormsg = "Error in file: {0} at ({1}, {2})".format(
            config_file,
            mark.line + 1,
            mark.column + 1)
        logger.error(errormsg)
        return None
    return conf


def dp_parser(config_file, logname):
    logger = get_logger(logname)
    conf = read_config(config_file, logname)
    if conf is None:
        return None

    version = conf.pop('version', 1)

    if version == 1:
        return _dp_parser_v1(conf, config_file, logname)
    elif version == 2:
        return _dp_parser_v2(conf, config_file, logname)
    else:
        logger.error("unsupported config version number: {0}".format(version))
        return None

def port_parser(p_identifier, port_conf, vlans):
    port = Port(p_identifier, port_conf)

    if port.mirror is not None:
        # ignore other config
        return port
    if port.native_vlan is not None:
        v_identifier = port.native_vlan
        vlan = vlans.setdefault(v_identifier,  VLAN(v_identifier))
        vlan.untagged.append(port)
    for v_identifier in port.tagged_vlans:
        vlan = vlans.setdefault(v_identifier,  VLAN(v_identifier))
        vlan.tagged.append(port)

    return port


def _dp_parser_v1(conf, config_file, logname):
    logger = get_logger(logname)

    # TODO: warn when the configuration contains meaningless elements
    # they are probably typos
    if 'dp_id' not in conf:
        logger.error('dp_id not configured in file {0}'.format(config_file))

    dp_id = conf['dp_id']
    dp = DP(dp_id, conf)

    interfaces_conf = conf.pop('interfaces', {})
    vlans_conf = conf.pop('vlans', {})
    acls_conf = conf.pop('acls', {})

    logger.info(str(dp))
    vlans = {}
    port = {}
    for vid, vlan_conf in vlans_conf.iteritems():
        vlans[vid] = VLAN(vid, vlan_conf)
    for port_num, port_conf in interfaces_conf.iteritems():
        dp.add_port(port_parser(port_num, port_conf, vlans))
    for acl_num, acl_conf in acls_conf.iteritems():
        dp.add_acl(acl_num, acl_conf)
    for vlan in vlans.itervalues():
        dp.add_vlan(vlan)
    try:
        dp.sanity_check()
    except AssertionError as err:
        logger.exception("Error in config file: {0}".format(err))
        return None

    return [dp]

def _dp_parser_v2(conf, config_file, logname):
    logger = get_logger(logname)

    if 'dps' not in conf:
        logger.error("dps not configured in file: {0}".format(config_file))
        return None

    vlans_conf = conf.pop('vlans', {})
    acls_conf = conf.pop('acls', {})

    dps = []
    for identifier, dp_conf in conf['dps'].iteritems():
        ports_conf = dp_conf.pop('interfaces', {})

        dp = DP(identifier, dp_conf)
        dp.sanity_check()

        vlans = {}
        ports = {}

        for vid, vlan_conf in vlans_conf.iteritems():
            vlans[vid] = VLAN(vid, vlan_conf)
        for port_num, port_conf in ports_conf.iteritems():
            ports[port_num] = port_parser(port_num, port_conf, vlans)
        for vlan in vlans.itervalues():
            # add now for vlans configured on ports but not elsewhere
            dp.add_vlan(vlan)
        for port in ports.itervalues():
            # now that all ports are created, handle mirroring rewriting
            if port.mirror is not None:
                port.mirror = ports[port.mirror].number
            dp.add_port(port)
        for a_identifier, acl_conf in acls_conf.iteritems():
            # TODO: turn this into an object
            dp.add_acl(a_identifier, acl_conf)

        dps.append(dp)

    return dps

def watcher_parser(config_file, logname):
    logger = get_logger(logname)
    #TODO: make this backwards compatible

    conf = read_config(config_file, logname)
    if isinstance(conf, dict):
        # in this case it may be an old style config
        return _watcher_parser_v2(conf, logname)
    else:
        return _watcher_parser_v1(config_file, logname)

def _watcher_parser_v1(config_file, logname):
    logger = get_logger(logname)
    result = []

    INFLUX_KEYS = [
        'influx_db',
        'influx_host',
        'influx_port',
        'influx_user',
        'influx_pwd',
        'influx_timeout',
        ]

    dps = []
    with open(config_file, 'r') as conf:
        for line in conf:
            dps.append(dp_parser(line.strip(), logname)[0])

    for dp in dps:
        if dp.influxdb_stats:
            w_type = 'port_state'
            port_state_conf = {
                'type': w_type,
                'db_type': 'influx'
                }
            for key in INFLUX_KEYS:
                port_state_conf[key] = dp.__dict__.get(key, None)
            name = dp.name + '-' + w_type
            watcher = WatcherConf(name, port_state_conf)
            result.append(watcher)

        if dp.monitor_ports:
            w_type = 'port_stats'
            port_stats_conf = {'type': w_type}
            port_stats_conf['interval'] = dp.monitor_ports_interval
            if dp.influxdb_stats:
                port_stats_conf['db_type'] = 'influx'
                for key in INFLUX_KEYS:
                    port_stats_conf[key] = dp.__dict__.get(key, None)
            else:
                port_stats_conf['db_type'] = 'text'
                port_stats_conf['file'] = dp.monitor_ports_file
            name = dp.name + '-' + w_type
            watcher = WatcherConf(name, port_stats_conf)
            result.append(watcher)

        if dp.monitor_flow_table:
            w_type = 'flow_table'
            flow_table_conf = {'type': w_type}
            flow_table_conf['interval'] = dp.monitor_flow_table_interval
            flow_table_conf['file'] = dp.monitor_flow_table_file
            name = dp.name + '-' + w_type
            watcher = WatcherConf(name, flow_table_conf)
            result.append(watcher)

    return result


def _watcher_parser_v2(conf, logname):
    logger = get_logger(logname)
    result = []

    dps = {}
    for faucet_file in conf['faucet_configs']:
        dp_list = dp_parser(faucet_file, logname)
        for dp in dp_list:
            dps[dp.name] = dp

    dbs = conf.pop('dbs')

    for name, dictionary in conf['watchers'].iteritems():
        for dp_name in dictionary['dps']:
            if dp_name not in dps:
                errormsg = "dp: {0} metered but not configured".format(
                    dp_name
                    )
                logger.error(errormsg)
                continue

            dp = dps[dp_name]

            watcher = WatcherConf(name, dictionary)
            watcher.add_db(dbs[watcher.db])
            watcher.add_dp(dp)
            result.append(watcher)

    return result
