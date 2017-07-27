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

import numpy

from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError, InfluxDBServerError
from requests.exceptions import ConnectTimeoutError, ReadTimeout


class InfluxShipper(object):
    """Convenience class for shipping values to InfluxDB.

    Inheritors must have a WatcherConf object as conf.
    """
    conf = None

    def ship_points(self, points):
        try:
            client = InfluxDBClient(
                host=self.conf.influx_host,
                port=self.conf.influx_port,
                username=self.conf.influx_user,
                password=self.conf.influx_pwd,
                database=self.conf.influx_db,
                timeout=self.conf.influx_timeout)
            return client.write_points(points=points, time_precision='s')
        except (ConnectionError, ConnectTimeoutError, ReadTimeout, InfluxDBClientError, InfluxDBServerError):
            return False

    def make_point(self, dp_name, port_name, rcv_time, stat_name, stat_val):
        port_tags = {
            'dp_name': dp_name,
            'port_name': port_name,
        }
        # InfluxDB has only one integer type, int64. We are logging OF
        # stats that are uint64. Use float64 to prevent an overflow.
        # q.v. https://docs.influxdata.com/influxdb/v1.2/write_protocols/line_protocol_reference/
        point = {
            'measurement': stat_name,
            'tags': port_tags,
            'time': int(rcv_time),
            # pylint: disable=no-member
            'fields': {'value': numpy.float64(stat_val)}}
        return point
