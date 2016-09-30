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

import hashlib
import logging
import os
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
        logger.error('Error in file %s (%s)', config_file, str(ex))
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
        logger.error('unsupported config version number %s', version)
        return None

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

def _dp_config_path(config_file, parent_file=None):
    if parent_file and not os.path.isabs(config_file):
        return os.path.realpath(os.path.join(os.path.dirname(parent_file), config_file))
    else:
        return os.path.realpath(config_file)

def _dp_parser_v1(conf, config_file, logname):
    logger = get_logger(logname)

    config_path = _dp_config_path(config_file)

    # TODO: warn when the configuration contains meaningless elements
    # they are probably typos
    if 'dp_id' not in conf:
        logger.error('dp_id not configured in file %s', config_file)

    dp_id = conf['dp_id']
    dp = DP(dp_id, conf)

    interfaces_conf = conf.pop('interfaces', {})
    vlans_conf = conf.pop('vlans', {})
    acls_conf = conf.pop('acls', {})

    logger.info(str(dp))
    vlans = {}
    for vid, vlan_conf in vlans_conf.iteritems():
        vlans[vid] = VLAN(vid, dp_id, vlan_conf)
    for port_num, port_conf in interfaces_conf.iteritems():
        dp.add_port(port_parser(dp_id, port_num, port_conf, vlans))
    for acl_num, acl_conf in acls_conf.iteritems():
        dp.add_acl(acl_num, acl_conf)
    for vlan in vlans.itervalues():
        dp.add_vlan(vlan)
    dp.finalize_config()
    try:
        dp.sanity_check()
    except AssertionError as err:
        logger.exception('Error in config file: %s', err)
        return None

    with open(config_path, 'r') as f:
        return ({config_path: hashlib.sha256(f.read()).hexdigest()}, [dp])

def _dp_include(config_hashes, parent_file, config_file, dps_conf, vlans_conf, acls_conf, logname):
    logger = get_logger(logname)

    # Save the updated configuration state in separate dicts,
    # so if an error is found, the changes can simply be thrown away.
    new_config_hashes = config_hashes.copy()
    new_dps_conf = dps_conf.copy()
    new_vlans_conf = vlans_conf.copy()
    new_acls_conf = acls_conf.copy()

    if not os.path.isfile(config_file):
        logger.warning('not a regular file or does not exist: %s', config_file)
        return False

    conf = read_config(config_file, logname)

    if not conf:
        logger.warning('error loading config from file: %s', config_file)
        return False

    # Add the SHA256 hash for this configuration file, so FAUCET can determine
    # whether or not this configuration file should be reloaded upon receiving
    # a HUP signal.
    with open(config_file, 'r') as f:
        new_config_hashes[config_file] = hashlib.sha256(f.read()).hexdigest()

    new_dps_conf.update(conf.pop('dps', {}))
    new_vlans_conf.update(conf.pop('vlans', {}))
    new_acls_conf.update(conf.pop('acls', {}))

    for include_file in conf.pop('include', []):
        include_path = _dp_config_path(include_file, parent_file=config_file)
        if include_path in config_hashes:
            logger.error(
                'include file %s already loaded, include loop found in file: %s',
                include_path,
                config_file,
            )
            return False
        if not _dp_include(new_config_hashes,
                config_file, include_path,
                new_dps_conf, new_vlans_conf, new_acls_conf,
                logname):
            logger.error('unable to load required include file: %s', include_path)
            return False

    for include_file in conf.pop('include-optional', []):
        include_path = _dp_config_path(include_file, parent_file=config_file)
        if include_path in config_hashes:
            logger.error(
                'include file %s already loaded, include loop found in file: %s',
                include_path,
                config_file,
            )
            return False
        if not _dp_include(new_config_hashes,
                config_file, include_path,
                new_dps_conf, new_vlans_conf, new_acls_conf,
                logname):
            new_config_hashes[include_path] = None
            logger.warning('skipping optional include file: %s', include_path)

    # Actually update the configuration data structures,
    # now that this file has been successfully loaded.
    config_hashes.update(new_config_hashes)
    dps_conf.update(new_dps_conf)
    vlans_conf.update(new_vlans_conf)
    acls_conf.update(new_acls_conf)

    return True

def _dp_add_vlan(vid_dp, dp, vlan, logname):
    if vlan.vid not in vid_dp:
        vid_dp[vlan.vid] = set()

    if len(vid_dp[vlan.vid]) > 1:
        assert not vlan.bgp_routerid, \
                "DPs {0} sharing a BGP speaker VLAN is unsupported".format(
                    str.join(", ", vid_dp[vlan.vid]),
                )

    if vlan not in dp.vlans:
        dp.add_vlan(vlan)

    vid_dp[vlan.vid].add(dp.name)

def _dp_parser_v2(conf, config_file, logname):
    logger = get_logger(logname)

    config_path = _dp_config_path(config_file)

    config_hashes = {}

    dps_conf = {}
    vlans_conf = {}
    acls_conf = {}

    if not _dp_include(config_hashes, None, config_path, dps_conf, vlans_conf, acls_conf, logname):
        logger.critical('error found while loading config file: %s', config_path)
        return None

    if not dps_conf:
        logger.critical('dps not configured in file: %s', config_path)
        return None

    dps = []
    vid_dp = {}

    for identifier, dp_conf in dps_conf.iteritems():
        ports_conf = dp_conf.pop('interfaces', {})

        dp = DP(identifier, dp_conf)
        dp.sanity_check()

        dp_id = dp.dp_id

        vlans = {}
        ports = {}

        for vid, vlan_conf in vlans_conf.iteritems():
            vlans[vid] = VLAN(vid, dp_id, vlan_conf)
        try:
            for port_num, port_conf in ports_conf.iteritems():
                port = port_parser(dp_id, port_num, port_conf, vlans)
                ports[port_num] = port
                if port.native_vlan is not None:
                    _dp_add_vlan(vid_dp, dp, vlans[port.native_vlan], logname)
                if port.tagged_vlans is not None:
                    for vid in port.tagged_vlans:
                        _dp_add_vlan(vid_dp, dp, vlans[vid], logname)
        except AssertionError as err:
            logger.exception('Error in config file: %s', err)
            return None
        for port in ports.itervalues():
            dp.add_port(port)
        for a_identifier, acl_conf in acls_conf.iteritems():
            # TODO: turn this into an object
            dp.add_acl(a_identifier, acl_conf)
        dp.finalize_config()

        dps.append(dp)

    return (config_hashes, dps)

def watcher_parser(config_file, logname):
    #TODO: make this backwards compatible

    conf = read_config(config_file, logname)
    if isinstance(conf, dict):
        # in this case it may be an old style config
        return _watcher_parser_v2(conf, logname)
    else:
        return _watcher_parser_v1(config_file, logname)

def _watcher_parser_v1(config_file, logname):
    result = []

    INFLUX_KEYS = [
        'influx_db',
        'influx_host',
        'influx_port',
        'influx_user',
        'influx_pwd',
        'influx_timeout',
        ]

    GAUGEDB_KEYS = [
        'gdb_type',
        'nosql_db',
        'db_username',
        'db_password',
        'db_ip',
        'db_fqdn',
        'db_port',
        'driver',
        'views',
        'switches_doc',
        'flows_doc',
        ]

    dps = []
    with open(config_file, 'r') as conf:
        for line in conf:
            dps.append(dp_parser(line.strip(), logname)[1][0])

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
            # add dp to watcher. prevents the dp_id attribute error in gauge.
            watcher.add_dp(dp)
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
            # add dp to watcher. prevents the dp_id attribute error in gauge.
            watcher.add_dp(dp)
            result.append(watcher)

        if dp.monitor_flow_table:
            w_type = 'flow_table'
            flow_table_conf = {'type': w_type}
            flow_table_conf['interval'] = dp.monitor_flow_table_interval
            flow_table_conf['file'] = dp.monitor_flow_table_file
            name = dp.name + '-' + w_type
            watcher = WatcherConf(name, flow_table_conf)
            # add dp to watcher. prevents the dp_id attribute error in gauge.
            watcher.add_dp(dp)
            result.append(watcher)

        if dp.gaugedb_updates:
            w_type = 'flow_table'
            flow_table_conf = {'type': w_type}
            flow_table_conf['db_type'] = 'gaugedb'
            flow_table_conf['interval'] = dp.monitor_flow_table_interval
            flow_table_conf['db_update_counter'] = dp.gaugedb_update_counter
            name = dp.name + '-' + w_type
            for key in GAUGEDB_KEYS:
                flow_table_conf[key] = dp.__dict__.get('gaugedb').get(
                    key, None)
            watcher = WatcherConf(name, flow_table_conf)
            watcher.add_dp(dp)
            result.append(watcher)

    return result


def _watcher_parser_v2(conf, logname):
    logger = get_logger(logname)
    result = []

    dps = {}
    for faucet_file in conf['faucet_configs']:
        __, dp_list = dp_parser(faucet_file, logname)
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
