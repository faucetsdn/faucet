"""Gauge watcher configuration."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os
from copy import deepcopy
from faucet.conf import Conf, test_config_condition


class WatcherConf(Conf):
    """Stores the state and configuration to monitor a single stat.

Watcher Config

Watchers are configured in the watchers config block in the config for gauge.

The following elements can be configured for each watcher, at the level of
/watchers/<watcher name>/:

 * type (string): The type of watcher (IE what stat this watcher monitors). \
       The types are 'port_state', 'port_stats' or 'flow_table'.
 * dps (list): A list of dps that should be monitored with this watcher.
 * db (string): The db that will be used to store the data once it is retreived.
 * interval (int): if this watcher requires polling the switch, it will \
       monitor at this interval.

The config for a db should be created in the gauge config file under the dbs
config block.

The following elements can be configured for each db, at the level of
/dbs/<db name>/:

 * type (string): the type of db. The available types are 'text' and 'influx' \
       for port_state, 'text', 'influx'and 'prometheus' for port_stats and \
       'text' and flow_table.

The following config elements then depend on the type.

For text:
 * file (string): the filename of the file to write output to.
 * path (string): path where files should be written when writing to \
       muiltiple files
 * compress (bool): compress (with gzip) flow_table output while writing it

For influx:
 * influx_db (str): The name of the influxdb database. Defaults to 'faucet'.
 * influx_host (str): The host where the influxdb is reachable. Defaults to \
       'localhost'.
 * influx_port (int): The port that the influxdb host will listen on. Defaults \
       to 8086.
 * influx_user (str): The username for accessing influxdb. Defaults to ''.
 * influx_pwd (str): The password for accessing influxdb. Defaults to ''.
 * influx_timeout (int): The timeout in seconds for connecting to influxdb. \
       Defaults to 10.
 * influx_retries (int): The number of times to retry connecting to influxdb \
       after failure. Defaults to 3.

For Prometheus:
 * prometheus_port (int): The port used to export prometheus data. Defaults to \
       9303.
 * prometheus_addr (ip addr str): The address used to export prometheus data. \
       Defaults to '127.0.0.1'.
"""

    db_defaults = {
        'type': None,
        'file': None,
        'path': None,
        'compress': False,
        # compress flow table file
        'influx_db': 'faucet',
        # influx database name
        'influx_host': 'localhost',
        # influx database location
        'influx_port': 8086,
        'influx_user': '',
        # influx username
        'influx_pwd': '',
        # influx password
        'influx_timeout': 10,
        # timeout on influx requests
        'influx_retries': 3,
        # attempts to retry influx request
        # prometheus config
        'prometheus_port': 9303,
        'prometheus_addr': '0.0.0.0',
        'prometheus_test_thread': False,
    }

    db_defaults_types = {
        'type': str,
        'file': str,
        'path': str,
        'compress': bool,
        'influx_db': str,
        'influx_host': str,
        'influx_port': int,
        'influx_user': str,
        'influx_pwd': str,
        'influx_timeout': int,
        'influx_retries': int,
        'prometheus_port': int,
        'prometheus_addr': str,
        'prometheus_test_thread': bool,
    }

    defaults = {
        'name': None,
        'type': None,
        'dps': None,
        'all_dps': False,
        'interval': 30,
        'db': None,
        'dbs': None,
        'db_type': 'text',
    }

    defaults_types = {
        'name': str,
        'type': str,
        'dps': list,
        'all_dps': bool,
        'interval': int,
        'db': str,
        'dbs': list,
        'db_type': str,
    }

    def __init__(self, _id, dp_id, conf, prom_client):
        self.db = None  # pylint: disable=invalid-name
        self.dbs = None
        self.dp = None  # pylint: disable=invalid-name
        self.all_dps = None
        self.type = None
        self.interval = None
        self.db_type = None
        self.dps = None
        self.compress = None
        self.file = None
        self.path = None
        self.influx_db = None
        self.influx_host = None
        self.influx_port = None
        self.influx_user = None
        self.influx_pwd = None
        self.influx_timeout = None
        self.influx_retries = None
        self.name = None
        self.prometheus_port = None
        self.prometheus_addr = None
        self.prometheus_test_thread = None
        self.defaults.update(self.db_defaults)
        self.defaults_types.update(self.db_defaults_types)
        super().__init__(_id, dp_id, conf)
        self.name = str(self._id)
        self.prom_client = prom_client

    def add_db(self, db_conf):
        """Add database config to this watcher."""
        self._check_conf_types(db_conf, self.db_defaults_types)
        db_conf = deepcopy(db_conf)
        db_type = db_conf.pop('type')
        db_conf['db_type'] = db_type
        self.update(db_conf)
        test_config_condition(
            self.file is not None and not
            (os.path.dirname(self.file) and os.access(os.path.dirname(self.file), os.W_OK)),
            f'{self.file} is not writable')
        test_config_condition(
            self.path is not None and not os.access(self.path, os.W_OK),
            f'{self.file} is not writable')

    def add_dp(self, dp):
        """Add a datapath to this watcher."""
        self.dp = dp

    def check_config(self):
        super().check_config()
        test_config_condition(
            self.all_dps and self.dps is not None,
            'all_dps and dps cannot be set together')
        test_config_condition(
            not self.type, 'type must be set')
        valid_types = {'flow_table', 'port_stats', 'port_state', 'meter_stats'}
        test_config_condition(
            self.type not in valid_types,
            f'type {self.type} not one of {valid_types}')
