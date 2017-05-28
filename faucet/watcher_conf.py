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
from conf import Conf


class WatcherConf(Conf):

    db = None
    dp = None

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
    }

    def __init__(self, _id, conf):
        self._id = _id
        self.update(conf)
        self.set_defaults()

    def set_defaults(self):
        for key, value in list(self.defaults.items()):
            self._set_default(key, value)
        self.name = str(self._id)

    def add_db(self, db_conf):
        db_conf = deepcopy(db_conf)
        db_type = db_conf.pop('type')
        db_conf['db_type'] = db_type
        self.update(db_conf)

    def add_dp(self, dp):
        self.dp = dp
