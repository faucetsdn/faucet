"""Gauge watcher configuration."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from copy import deepcopy
from faucet.conf import Conf


class WatcherConf(Conf):
    """Gauge watcher configuration."""

    db = None # pylint: disable=invalid-name
    dp = None # pylint: disable=invalid-name
    prom_client = None

    defaults = {
        'name': None,
        'type': None,
        'dps': None,
        'interval': 30,
        'db': None,
        'db_type': 'text',
        'file': None,
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
        'prometheus_addr': '127.0.0.1',
        'views': {},
        'db_update_counter': 0,
        'nosql_db': '',
        'db_password': '',
        'flows_doc': '',
        'db_ip': '',
        'db_port': 0,
        'gdb_type': '',
        'driver': '',
        'db_username': '',
        'switches_doc': '',
    }

    def __init__(self, _id, conf, prom_client):
        super(WatcherConf, self).__init__(_id, conf)
        self.prom_client = prom_client
        self.name = str(self._id)

    def add_db(self, db_conf):
        """Add database config to this watcher."""
        db_conf = deepcopy(db_conf)
        db_type = db_conf.pop('type')
        db_conf['db_type'] = db_type
        self.update(db_conf)

    def add_dp(self, dp): # pylint: disable=invalid-name
        """Add a datapath to this watcher."""
        self.dp = dp # pylint: disable=invalid-name
