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

from vlan import VLAN
from port import Port


class DP(object):
    """Object to hold the configuration for a faucet controlled datapath."""

    # Known to run FAUCET
    SUPPORTED_HARDWARE = (
        'Allied-Telesis',
        'NoviFlow',
        'Open vSwitch',
    )

    dp_id = None
    acls = None
    vlans = None
    ports = None
    running = False

    def __init__(self, dp_id, logname):
        self.dp_id = dp_id
        self.acls = {}
        self.vlans = {}
        self.ports = {}
        self.mirror_from_port = {}
        self.acl_in = {}
        self.logger = logging.getLogger(logname)
        self.set_defaults()

    @classmethod
    def parser(cls, config_file, logname=__name__):
        logger = logging.getLogger(logname)
        try:
            with open(config_file, 'r') as stream:
                conf = yaml.load(stream)
        except yaml.YAMLError as ex:
            mark = ex.problem_mark
            errormsg = "Error in file: {0} at ({1}, {2})".format(
                config_file,
                mark.line + 1,
                mark.column + 1)
            logger.error(errormsg)
            return None

        if 'dp_id' not in conf:
            errormsg = "dp_id not configured in file: {0}".format(config_file)
            logger.error(errormsg)
            return None

        dp = DP(conf['dp_id'], logname)

        interfaces = conf.pop('interfaces', {})
        vlans = conf.pop('vlans', {})
        acls = conf.pop('acls', {})
        dp.__dict__.update(conf)
        dp.set_defaults()

        for vid, vlan_conf in vlans.iteritems():
            dp.add_vlan(vid, vlan_conf)
        for port_num, port_conf in interfaces.iteritems():
            dp.add_port(port_num, port_conf)
        for acl_num, acl_conf in acls.iteritems():
            dp.add_acl(acl_num, acl_conf)


        return dp

    def sanity_check(self):
        assert 'dp_id' in self.__dict__
        assert isinstance(self.dp_id, int)
        assert self.hardware in self.SUPPORTED_HARDWARE
        for vid, vlan in self.vlans.iteritems():
            assert isinstance(vid, int)
            assert isinstance(vlan, VLAN)
            assert all(isinstance(p, Port) for p in vlan.get_ports())
        for portnum, port in self.ports.iteritems():
            assert isinstance(portnum, int)
            assert isinstance(port, Port)
        assert isinstance(self.monitor_ports, bool)
        assert isinstance(self.monitor_ports_file, basestring)
        assert isinstance(self.monitor_ports_interval, int)
        assert isinstance(self.monitor_flow_table, bool)
        assert isinstance(self.monitor_flow_table_file, basestring)
        assert isinstance(self.monitor_flow_table_interval, int)

    def set_defaults(self):
        # Offset for tables used by faucet
        self.__dict__.setdefault('table_offset', 0)
        # The table for internally associating vlans
        self.__dict__.setdefault('vlan_table', self.table_offset)
        # Table for applying ACLs.
        self.__dict__.setdefault('acl_table', self.table_offset + 1)
        # The table for checking eth src addresses are known
        self.__dict__.setdefault('eth_src_table', self.table_offset + 2)
        # The table for matching eth dst and applying unicast actions
        self.__dict__.setdefault('eth_dst_table', self.table_offset + 3)
        # The table for applying broadcast actions
        self.__dict__.setdefault('flood_table', self.table_offset + 4)
        # How much to offset default priority by
        self.__dict__.setdefault('priority_offset', 0)
        # Some priority values
        self.__dict__.setdefault('lowest_priority', self.priority_offset)
        self.__dict__.setdefault('low_priority', self.priority_offset + 9000)
        self.__dict__.setdefault('high_priority', self.low_priority + 1)
        self.__dict__.setdefault('highest_priority', self.high_priority + 98)
        # Identification cookie value to allow for multiple controllers to
        # control the same datapath
        self.__dict__.setdefault('cookie', 1524372928)
        # inactive MAC timeout
        self.__dict__.setdefault('timeout', 300)
        # enable port stats monitoring?
        self.__dict__.setdefault('monitor_ports', False)
        # File for port stats logging
        self.__dict__.setdefault('monitor_ports_file', 'logfile.log')
        # Stats reporting interval (in seconds)
        self.__dict__.setdefault('monitor_ports_interval', 30)
        # Enable flow table monitoring?
        self.__dict__.setdefault('monitor_flow_table', False)
        # File for flow table logging
        self.__dict__.setdefault('monitor_flow_table_file', 'logfile.log')
        # Stats reporting interval
        self.__dict__.setdefault('monitor_flow_table_interval', 30)
        # Name for this dp, used for stats reporting
        self.__dict__.setdefault('name', str(self.dp_id))
        # description, strictly informational
        self.__dict__.setdefault('description', self.name)
        # The hardware maker (for chosing an openflow driver)
        self.__dict__.setdefault('hardware', 'Open_vSwitch')

    def add_acl(self, acl_num, acl_conf=None):
        if acl_conf is not None:
            self.acls[acl_num] = [x['rule'] for x in acl_conf]

    def add_port(self, port_num, port_conf=None):
        # add port specific vlans or fall back to defaults
        port_conf = copy.copy(port_conf) if port_conf else {}

        port = self.ports.setdefault(port_num, Port(port_num, port_conf))

        port_conf.setdefault('mirror', None)
        if port_conf['mirror'] is not None:
            from_port_num = port_conf['mirror']
            self.mirror_from_port[from_port_num] = port_num
            # other configuration entries ignored.
            return

        # add native vlan
        port_conf.setdefault('native_vlan', None)
        if port_conf['native_vlan'] is not None:
            vid = port_conf['native_vlan']
            if vid not in self.vlans:
                self.vlans[vid] = VLAN(vid)
            self.vlans[vid].untagged.append(self.ports[port_num])

        # add vlans
        port_conf.setdefault('tagged_vlans', [])
        for vid in port_conf['tagged_vlans']:
            if vid not in self.vlans:
                self.vlans[vid] = VLAN(vid)
            self.vlans[vid].tagged.append(port)

        # add ACL
        port_conf.setdefault('acl_in', None)
        if port_conf['acl_in'] is not None:
            self.acl_in[port_num] = port_conf['acl_in']

    def add_vlan(self, vid, vlan_conf=None):
        vlan_conf = copy.copy(vlan_conf) if vlan_conf else {}

        self.vlans.setdefault(vid, VLAN(vid, vlan_conf))

    def get_native_vlan(self, port_num):
        if port_num not in self.ports:
            return None

        port = self.ports[port_num]

        for vlan in self.vlans.values():
            if port in vlan.untagged:
                return vlan

        return None

    def __str__(self):
        return self.name
