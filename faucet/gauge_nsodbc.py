"""Library for interacting with ODBC databases."""

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

from faucet.gauge_pollers import GaugeFlowTablePoller
from faucet.nsodbc import nsodbc_factory, init_switch_db, init_flow_db


class GaugeNsODBC(object):
    """
    Helper class for NSODBC operations

    Inheritors must have a WatcherConf object as conf.
    """
    conf = None
    db_update_counter = None
    conn_string = None
    switch_database = None
    flow_database = None
    conn = None

    def setup(self):
        if self.conf is None:
            return
        self.conn_string = (
            'driver={0};server={1};port={2};uid={3};pwd={4}'.format(
                self.conf.driver, self.conf.db_ip, self.conf.db_port,
                self.conf.db_username, self.conf.db_password))
        nsodbc = nsodbc_factory()
        self.conn = nsodbc.connect(self.conn_string)
        self.switch_database, exists = self.conn.create(self.conf.switches_doc)
        if not exists:
            init_switch_db(self.switch_database)
        self.flow_database, exists = self.conn.create(self.conf.flows_doc)
        if not exists:
            init_flow_db(self.flow_database)
        self.db_update_counter = int(self.conf.db_update_counter)

    def refresh_switchdb(self):
        if self.conf is None:
            return
        self.conn.delete(self.conf.switches_doc)
        self.switch_database, _ = self.conn.create(self.conf.switches_doc)
        init_switch_db(self.switch_database)

    def refresh_flowdb(self):
        if self.conf is None:
            return
        self.conn.delete(self.conf.flows_doc)
        self.flow_database, _ = self.conn.create(self.conf.flows_doc)
        init_flow_db(self.flow_database)


class GaugeFlowTableDBLogger(GaugeFlowTablePoller, GaugeNsODBC):
    """Periodically dumps the current datapath flow table to ODBC DB."""

    def __init__(self, conf, logname, prom_client):
        super(GaugeFlowTableDBLogger, self).__init__(conf, logname, prom_client)
        self.setup()

    def update(self, rcv_time, dp_id, msg):
        super(GaugeFlowTableDBLogger, self).update(rcv_time, dp_id, msg)
        jsondict = msg.to_jsondict()
        if self.db_update_counter == self.conf.db_update_counter:
            self.refresh_switchdb()
            switch_object = {'_id': str(hex(self.dp.dp_id)),
                             'data': {'flows': []}}
            self.switch_database.insert_update_doc(switch_object,
                                                   'data')
            try:
                rows = self.switch_database.get_docs(
                    self.conf.views['switch_view'],
                    key=str(hex(self.dp.dp_id)))
                switch = rows[0]
            except IndexError:
                switch = None

            if switch:
                self.refresh_flowdb()
                for f_msg in jsondict['OFPFlowStatsReply']['body']:
                    flow_object = {'data': f_msg, 'tags': []}
                    flow_id = self.flow_database.insert_update_doc(
                        flow_object, '')
                    switch.value['data']['flows'].append(flow_id)
                    self.switch_database.insert_update_doc(
                        switch.value, 'data')
        self.db_update_counter -= 1
        if not self.db_update_counter:
            self.db_update_counter = self.conf.db_update_counter
