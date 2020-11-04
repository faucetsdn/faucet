#!/usr/bin/env python3

"""Base class for all FAUCET unit tests."""

# pylint: disable=missing-docstring
# pylint: disable=too-many-arguments

from functools import partial
import collections
import copy
import glob
import ipaddress
import json
import os
import random
import re
import shutil
import string
import subprocess
import tempfile
import time
import unittest
import yaml

import netaddr
import requests

from ryu.ofproto import ofproto_v1_3 as ofp

from mininet.link import Intf as HWIntf  # pylint: disable=import-error
from mininet.log import error, output  # pylint: disable=import-error
from mininet.net import Mininet  # pylint: disable=import-error
from mininet.util import dumpNodeConnections, pmonitor  # pylint: disable=import-error

from clib import mininet_test_util
from clib import mininet_test_topo
from clib.mininet_test_topo import FaucetLink
from clib.tcpdump_helper import TcpdumpHelper

MAX_TEST_VID = 512
OFPVID_PRESENT = 0x1000
MIN_FLAP_TIME = 1
PEER_BGP_AS = 2**16 + 1
IPV4_ETH = 0x0800
IPV6_ETH = 0x86dd
FPING_ARGS = '-s -T 1 -A'


class FaucetTestBase(unittest.TestCase):
    """Base class for all FAUCET unit tests."""

    # Number of Faucet controllers to create
    NUM_FAUCET_CONTROLLERS = 2
    # Delay between Faucet controllers starting
    FAUCET_CONTROLLER_START_DELAY = 10
    # Number of Gauge controllers to create
    NUM_GAUGE_CONTROLLERS = 1

    CONTROLLER_CLASS = mininet_test_topo.FAUCET

    DP_NAME = 'faucet-1'

    _PROM_LINE_RE = re.compile(r'^(.+)\s+([0-9\.\-\+e]+)$')

    ONE_GOOD_PING = '1 packets transmitted, 1 received, 0% packet loss'
    FAUCET_VIPV4 = ipaddress.ip_interface('10.0.0.254/24')
    FAUCET_VIPV4_2 = ipaddress.ip_interface('172.16.0.254/24')
    FAUCET_VIPV6 = ipaddress.ip_interface('fc00::1:254/112')
    FAUCET_VIPV6_2 = ipaddress.ip_interface('fc01::1:254/112')
    OFCTL = 'ovs-ofctl -OOpenFlow13'
    VSCTL = 'ovs-vsctl'
    OVS_TYPE = 'kernel'
    BOGUS_MAC = '01:02:03:04:05:06'
    FAUCET_MAC = '0e:00:00:00:00:01'
    LADVD = 'ladvd -e lo -f'
    ONEMBPS = (1024 * 1024)
    DB_TIMEOUT = 5
    STAT_RELOAD = ''
    EVENT_SOCK_HEARTBEAT = ''

    CONFIG = ''
    CONFIG_GLOBAL = ''
    GAUGE_CONFIG_DBS = ''

    LOG_LEVEL = 'INFO'

    N_UNTAGGED = 0
    N_TAGGED = 0
    N_EXTENDED = 0
    EXTENDED_CLS = None
    NUM_DPS = 1
    LINKS_PER_HOST = 1
    SOFTWARE_ONLY = False
    NETNS = False
    EVENT_LOGGER_TIMEOUT = 120

    FPING_ARGS = FPING_ARGS
    FPING_ARGS_SHORT = ' '.join((FPING_ARGS, '-i10 -p100 -t100'))
    FPINGS_ARGS_ONE = ' '.join(('fping', FPING_ARGS, '-t100 -c 1'))

    RUN_GAUGE = True
    REQUIRES_METERS = False
    REQUIRES_METADATA = False

    _PORT_ACL_TABLE = 0
    _VLAN_TABLE = 1
    _COPRO_TABLE = 2
    _VLAN_ACL_TABLE = 3
    _ETH_SRC_TABLE = 4
    _IPV4_FIB_TABLE = 5
    _IPV6_FIB_TABLE = 6
    _VIP_TABLE = 7
    _ETH_DST_HAIRPIN_TABLE = 8
    _ETH_DST_TABLE = 9
    _FLOOD_TABLE = 10

    # Standard Gauge port counters.
    PORT_VARS = {
        'of_port_rx_bytes',
        'of_port_tx_bytes',
        'of_port_rx_packets',
        'of_port_tx_packets',
    }

    faucet_controllers = None
    faucet_of_ports = None
    faucet_prom_ports = None

    faucet_config_path = None

    gauge_controllers = None
    gauge_of_ports = None
    gauge_controller = None
    gauge_of_port = None

    config = None
    dpid = None
    hw_dpid = None
    hardware = 'Open vSwitch'
    hw_switch = False
    prom_port = None
    net = None
    of_port = None
    ctl_privkey = None
    ctl_cert = None
    ca_certs = None
    port_map = {}
    switch_map = {}
    tmpdir = None
    net = None
    topo = None
    cpn_intf = None
    cpn_ipv6 = False
    config_ports = {}
    event_sock = None
    event_log = None

    rand_dpids = set()

    def __init__(self, name, config, root_tmpdir, ports_sock, max_test_load,
                 port_order=None, start_port=None):
        super(FaucetTestBase, self).__init__(name)
        self.env = collections.defaultdict(dict)
        self.faucet_controllers = []
        self.faucet_of_ports = []
        self.faucet_prom_ports = []
        self.gauge_controllers = []
        self.gauge_of_ports = []
        self.config = config
        self.root_tmpdir = root_tmpdir
        self.ports_sock = ports_sock
        self.max_test_load = max_test_load
        self.port_order = port_order
        self.start_port = start_port
        self.start_time = None
        self.dpid_names = None
        self.event_log = None
        self.prev_event_id = None

    def hosts_name_ordered(self):
        """Return hosts in strict name only order."""
        return sorted(self.net.hosts, key=lambda host: host.name)

    def switches_name_ordered(self):
        """Return switches in strict name only order."""
        return sorted(self.net.switches, key=lambda switch: switch.name)

    def first_switch(self):
        """Return first switch by name order."""
        if not self.switches_name_ordered():
            return None
        return self.switches_name_ordered()[0]

    def rand_dpid(self):
        """Return a random unused DPID"""
        reserved_range = 100
        while True:
            dpid = random.randint(1, (2**32 - reserved_range)) + reserved_range
            if dpid not in self.rand_dpids:
                self.rand_dpids.add(dpid)
                return str(dpid)

    def _set_var(self, controller, var, value):
        """Set controller environment variable to value"""
        self.env[controller][var] = value

    def _set_vars(self):
        """Set controller additional variables"""
        for c_index in range(self.NUM_FAUCET_CONTROLLERS):
            self._set_var('faucet-%s' % c_index, 'FAUCET_PROMETHEUS_PORT', str(self.prom_port))
            self._set_var('faucet-%s' % c_index, 'FAUCET_PROMETHEUS_ADDR', mininet_test_util.LOCALHOSTV6)
        for c_index in range(self.NUM_FAUCET_CONTROLLERS):
            self._set_var('faucet-%s' % c_index, 'FAUCET_LOG_LEVEL', str(self.LOG_LEVEL))

    def _set_var_path(self, controller, var, path):
        """Update environment variable that is a file path to the correct tmpdir"""
        self._set_var(controller, var, os.path.join(self.tmpdir, path))

    def _set_static_vars(self):
        """Set static environment variables"""
        if self.event_sock and os.path.exists(self.event_sock):
            shutil.rmtree(os.path.dirname(self.event_sock))
        self.event_sock = os.path.join(tempfile.mkdtemp(), 'event.sock')
        for c_index in range(self.NUM_FAUCET_CONTROLLERS):
            self._set_var('faucet-%s' % c_index, 'FAUCET_EVENT_SOCK', self.event_sock)
            self._set_var('faucet-%s' % c_index, 'FAUCET_CONFIG_STAT_RELOAD', self.STAT_RELOAD)
            self._set_var('faucet-%s' % c_index, 'FAUCET_EVENT_SOCK_HEARTBEAT', self.EVENT_SOCK_HEARTBEAT)
            self._set_var_path('faucet-%s' % c_index, 'FAUCET_CONFIG', 'faucet.yaml')
            self._set_var_path('faucet-%s' % c_index, 'FAUCET_LOG', 'faucet-%s.log' % c_index)
            self._set_var_path('faucet-%s' % c_index, 'FAUCET_EXCEPTION_LOG', 'faucet-%s-exception.log' % c_index)
        for c_index in range(self.NUM_GAUGE_CONTROLLERS):
            self._set_var_path('gauge-%s' % c_index, 'GAUGE_CONFIG', 'gauge.yaml')
            self._set_var_path('gauge-%s' % c_index, 'GAUGE_LOG', 'gauge-%s.log' % c_index)
            self._set_var_path('gauge-%s' % c_index, 'GAUGE_EXCEPTION_LOG', 'gauge-%s-exception.log' % c_index)
        self.faucet_config_path = self.env['faucet-0']['FAUCET_CONFIG']
        self.gauge_config_path = self.env['gauge-0']['GAUGE_CONFIG']
        self.debug_log_path = os.path.join(
            self.tmpdir, 'ofchannel.txt')
        self.monitor_stats_file = os.path.join(
            self.tmpdir, 'gauge-ports.txt')
        self.monitor_state_file = os.path.join(
            self.tmpdir, 'gauge-state.txt')
        self.monitor_flow_table_dir = os.path.join(
            self.tmpdir, 'gauge-flow')
        self.monitor_meter_stats_file = os.path.join(
            self.tmpdir, 'gauge-meter.txt')
        os.mkdir(self.monitor_flow_table_dir)
        if self.config is not None:
            if 'hw_switch' in self.config:
                self.hw_switch = self.config['hw_switch']
            if self.hw_switch:
                self.dpid = self.config['dpid']
                self.cpn_intf = self.config['cpn_intf']
                if 'cpn_ipv6' in self.config:
                    self.cpn_ipv6 = self.config['cpn_ipv6']
                self.hardware = self.config['hardware']
                if 'ctl_privkey' in self.config:
                    self.ctl_privkey = self.config['ctl_privkey']
                if 'ctl_cert' in self.config:
                    self.ctl_cert = self.config['ctl_cert']
                if 'ca_certs' in self.config:
                    self.ca_certs = self.config['ca_certs']
                dp_ports = self.config['dp_ports']
                self.switch_map = dp_ports.copy()

    def _enable_event_log(self, timeout=None):
        """Enable analsis of event log contents by copying events to a local log file"""
        assert not self.event_log, 'event_log already enabled'
        if not timeout:
            timeout = self.EVENT_LOGGER_TIMEOUT
        self.event_log = os.path.join(self.tmpdir, 'event.log')
        self.prev_event_id = 0
        controller = self._get_controller()
        sock = self.env[self.faucet_controllers[0].name]['FAUCET_EVENT_SOCK']
        # Relying on a timeout seems a bit brittle;
        # as an alternative we might possibly use something like
        # `with popen(cmd...) as proc`to clean up on exceptions
        controller.cmd(mininet_test_util.timeout_cmd(
            'nc -U %s > %s &' % (sock, self.event_log), timeout))

    def _wait_until_matching_event(self, match_func, timeout=30):
        """Return the next matching event from the event sock, else fail"""
        assert timeout >= 1
        assert self.event_log and os.path.exists(self.event_log)
        for _ in range(timeout):
            with open(self.event_log) as events:
                for event_str in events:
                    event = json.loads(event_str)
                    event_id = event['event_id']
                    if event_id <= self.prev_event_id:
                        continue
                    self.prev_event_id = event_id
                    try:
                        if match_func(event):
                            return event
                    except KeyError:
                        pass  # Allow for easy dict traversal.
                time.sleep(1)
        self.fail('matching event not found in event stream')

    def _read_yaml(self, yaml_path):
        with open(yaml_path) as yaml_file:
            content = yaml.safe_load(yaml_file.read())
        return content

    def _get_faucet_conf(self):
        """Return the yaml content from the config file"""
        return self._read_yaml(self.faucet_config_path)

    def _annotate_interfaces_conf(self, yaml_conf):
        """Consistently name interface names/descriptions."""
        if 'dps' not in yaml_conf:
            return yaml_conf
        yaml_conf_remap = copy.deepcopy(yaml_conf)
        for dp_key, dp_yaml in yaml_conf['dps'].items():
            interfaces_yaml = dp_yaml.get('interfaces', None)
            if interfaces_yaml is not None:
                remap_interfaces_yaml = {}
                for intf_key, orig_intf_conf in interfaces_yaml.items():
                    intf_conf = copy.deepcopy(orig_intf_conf)
                    port_no = None
                    if isinstance(intf_key, int):
                        port_no = intf_key
                    number = intf_conf.get('number', port_no)
                    if isinstance(number, int):
                        port_no = number
                    assert isinstance(number, int), '%u %s' % (intf_key, orig_intf_conf)
                    intf_name = 'b%u' % port_no
                    intf_conf.update({'name': intf_name, 'description': intf_name})
                    remap_interfaces_yaml[intf_key] = intf_conf
                yaml_conf_remap['dps'][dp_key]['interfaces'] = remap_interfaces_yaml
        return yaml_conf_remap

    def _write_yaml_conf(self, yaml_path, yaml_conf):
        assert isinstance(yaml_conf, dict)
        new_conf_str = yaml.dump(yaml_conf).encode()
        with tempfile.NamedTemporaryFile(
                prefix=os.path.basename(yaml_path),
                dir=os.path.dirname(yaml_path),
                delete=False) as conf_file_tmp:
            conf_file_tmp_name = conf_file_tmp.name
            conf_file_tmp.write(new_conf_str)
        with open(conf_file_tmp_name, 'rb') as conf_file_tmp:
            conf_file_tmp_str = conf_file_tmp.read()
            assert new_conf_str == conf_file_tmp_str
        if os.path.exists(yaml_path):
            shutil.copyfile(yaml_path, '%s.%f' % (yaml_path, time.time()))
        os.rename(conf_file_tmp_name, yaml_path)

    def _init_faucet_config(self):
        faucet_config = '\n'.join((
            self.get_config_header(
                self.CONFIG_GLOBAL,
                self.debug_log_path, self.dpid, self.hardware),
            self.CONFIG))
        config_vars = {}
        for config_var in (self.config_ports, self.port_map):
            config_vars.update(config_var)
        faucet_config = faucet_config % config_vars
        yaml_conf = self._annotate_interfaces_conf(yaml.safe_load(faucet_config))
        self._write_yaml_conf(self.faucet_config_path, yaml_conf)

    def _init_gauge_config(self):
        gauge_config = self.get_gauge_config(
            self.faucet_config_path,
            self.monitor_stats_file,
            self.monitor_state_file,
            self.monitor_flow_table_dir)
        if self.config_ports:
            gauge_config = gauge_config % self.config_ports
        self._write_yaml_conf(self.gauge_config_path, yaml.safe_load(gauge_config))

    def _test_name(self):
        return mininet_test_util.flat_test_name(self.id())

    def _tmpdir_name(self):
        tmpdir = os.path.join(self.root_tmpdir, self._test_name())
        os.mkdir(tmpdir)
        return tmpdir

    def _wait_load(self, load_retries=120):
        for _ in range(load_retries):
            load = os.getloadavg()[0]
            time.sleep(random.randint(1, 7))
            if load < self.max_test_load:
                return
            output('load average too high %f, waiting' % load)
        self.fail('load average %f consistently too high' % load)

    def _allocate_config_ports(self):
        for port_name in self.config_ports:
            self.config_ports[port_name] = None
            for config in (self.CONFIG, self.CONFIG_GLOBAL, self.GAUGE_CONFIG_DBS):
                if re.search(port_name, config):
                    port = mininet_test_util.find_free_port(
                        self.ports_sock, self._test_name())
                    self.config_ports[port_name] = port
                    output('allocating port %u for %s' % (port, port_name))

    def _allocate_faucet_ports(self):
        for c_index in range(self.NUM_FAUCET_CONTROLLERS):
            if self.hw_switch and c_index == 0:
                of_port = self.config['of_port']
            else:
                of_port = mininet_test_util.find_free_port(
                    self.ports_sock, self._test_name())
            prom_port = mininet_test_util.find_free_port(
                self.ports_sock, self._test_name())
            self.faucet_of_ports.append(of_port)
            self.faucet_prom_ports.append(prom_port)
        self.of_port = self.faucet_of_ports[0]
        self.prom_port = self.faucet_prom_ports[0]

    def _allocate_gauge_ports(self):
        for c_index in range(self.NUM_GAUGE_CONTROLLERS):
            if self.hw_switch and c_index == 0:
                of_port = self.config['gauge_of_port']
            else:
                of_port = mininet_test_util.find_free_port(
                    self.ports_sock, self._test_name())
            self.gauge_of_ports.append(of_port)
        self.gauge_of_port = self.gauge_of_ports[0]

    def _stop_net(self):
        if self.net is not None:
            for switch in self.net.switches:
                switch.cmd(
                    self.VSCTL, 'del-controller', switch.name, '|| true')
            self.net.stop()

    def setUp(self):
        if self.config and 'hw_switch' in self.config:
            # Simulating/running hardware switches so only 1 controller configured
            # TODO: Handle multiple controllers with hardware tests
            self.NUM_FAUCET_CONTROLLERS = 1
        self.start_time = time.time()
        self.tmpdir = self._tmpdir_name()
        self._set_static_vars()
        self.topo_class = partial(
            mininet_test_topo.FaucetSwitchTopo, port_order=self.port_order,
            switch_map=self.switch_map, start_port=self.start_port)
        if self.hw_switch:
            self.hw_dpid = mininet_test_util.str_int_dpid(self.dpid)
            self.dpid = self.hw_dpid
        else:
            self.dpid = self.rand_dpid()

    def hostns(self, host):
        return '%s' % host.name

    def dump_switch_flows(self, switch):
        """Dump switch information to tmpdir"""
        for dump_cmd in (
                'dump-flows', 'dump-groups', 'dump-meters',
                'dump-group-stats', 'dump-ports', 'dump-ports-desc',
                'meter-stats'):
            switch_dump_name = os.path.join(self.tmpdir, '%s-%s.log' % (switch.name, dump_cmd))
            # TODO: occasionally fails with socket error.
            switch.cmd('%s %s %s > %s' % (self.OFCTL, dump_cmd, switch.name, switch_dump_name),
                       success=None)
        for other_cmd in ('show', 'list controller', 'list manager'):
            other_dump_name = os.path.join(self.tmpdir, '%s.log' % other_cmd.replace(' ', ''))
            switch.cmd('%s %s > %s' % (self.VSCTL, other_cmd, other_dump_name))

    def tearDown(self, ignore_oferrors=False):
        """Clean up after a test.
           ignore_oferrors: return OF errors rather than failing"""
        if self.NETNS:
            for host in self.hosts_name_ordered()[:1]:
                if self.get_host_netns(host):
                    self.quiet_commands(host, ['ip netns del %s' % self.hostns(host)])
        first_switch = self.first_switch()
        if first_switch:
            self.first_switch().cmd('ip link > %s' % os.path.join(self.tmpdir, 'ip-links.log'))
        switch_names = []
        for switch in self.net.switches:
            switch_names.append(switch.name)
            self.dump_switch_flows(switch)
            switch.cmd('%s del-br %s' % (self.VSCTL, switch.name))
        self._stop_net()
        self.net = None
        if os.path.exists(self.event_sock):
            shutil.rmtree(os.path.dirname(self.event_sock))
        mininet_test_util.return_free_ports(
            self.ports_sock, self._test_name())
        if 'OVS_LOGDIR' in os.environ:
            ovs_log_dir = os.environ['OVS_LOGDIR']
            if ovs_log_dir and os.path.exists(ovs_log_dir):
                for ovs_log in glob.glob(os.path.join(ovs_log_dir, '*.log')):
                    lines = []
                    for name in switch_names:
                        lines.extend(self.matching_lines_from_file(name, ovs_log))
                    if lines:
                        switch_ovs_log_name = os.path.join(self.tmpdir, os.path.basename(ovs_log))
                        with open(switch_ovs_log_name, 'w') as switch_ovs_log:
                            switch_ovs_log.write('\n'.join(lines))
        with open(os.path.join(self.tmpdir, 'test_duration_secs'), 'w') as duration_file:
            duration_file.write(str(int(time.time() - self.start_time)))
        # Must not be any controller exception.
        for controller_env in self.env.values():
            if 'FAUCET_EXCEPTION_LOG' in controller_env:
                self.verify_no_exception(controller_env['FAUCET_EXCEPTION_LOG'])
            if 'GAUGE_EXCEPTION_LOG' in controller_env:
                self.verify_no_exception(controller_env['GAUGE_EXCEPTION_LOG'])
        oferrors = ''
        for controller_env in self.env.values():
            if 'FAUCET_LOG' in controller_env:
                logfile = controller_env['FAUCET_LOG']
            elif 'GAUGE_LOG' in controller_env:
                logfile = controller_env['GAUGE_LOG']
            oldlogfile = '.'.join((logfile, 'old'))
            if os.path.exists(oldlogfile):
                logfile = oldlogfile
            # Verify version is logged.
            self.assertTrue(
                self.matching_lines_from_file(r'^.+version\s+(\S+)$', logfile),
                msg='no version logged in %s' % logfile)
            # Verify no OFErrors.
            oferrors += '\n\n'.join(self.matching_lines_from_file(r'^.+(OFError.+)$', logfile))
            if not ignore_oferrors:
                self.assertFalse(oferrors, msg=oferrors)
        return oferrors

    def _block_non_faucet_packets(self):

        def _cmd(cmd):
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            self.assertFalse(stdout, msg='%s: %s' % (stdout, cmd))
            self.assertFalse(stderr, msg='%s: %s' % (stderr, cmd))

        _cmd('ebtables --f OUTPUT')
        for phys_port in self.switch_map.values():
            phys_mac = self.get_mac_of_intf(phys_port)
            for cmd in (
                    'ip link set dev %s up' % phys_port,
                    'ip -4 addr flush dev %s' % phys_port,
                    'ip -6 addr flush dev %s' % phys_port,
                    'ebtables -A OUTPUT -s %s -o %s -j DROP' % (phys_mac, phys_port)):
                _cmd(cmd)

    def _attach_physical_switch(self):
        """Bridge a physical switch into test topology.

           We do this for now to enable us to reconnect
           virtual ethernet interfaces which may already
           exist on emulated hosts and other OVS instances.

           (One alternative would be to create a Link() class
           that uses the hardware interfaces directly.)

           We repurpose the first OvS switch in the topology
           as a patch panel that transparently connects the
           hardware interfaces to the host/switch veth links."""
        switch = self.first_switch()
        if not switch:
            return
        # hw_names are the names of the server hardware interfaces
        # that are cabled to the device under test, sorted by OF port number
        hw_names = [self.switch_map[port] for port in sorted(self.switch_map)]
        hw_macs = set()
        # ovs_ports are the (sorted) OF port numbers of the OvS interfaces
        # that are already attached to the emulated network.
        # The actual tests reorder them according to port_map
        ovs_ports = sorted(self.topo.switch_ports[switch.name])
        # Patch hardware interfaces through to to OvS interfaces
        for hw_name, ovs_port in zip(hw_names, ovs_ports):
            # Note we've already removed any Linux IP addresses from hw_name
            # and blocked traffic to/from its meaningless MAC
            hw_mac = self.get_mac_of_intf(hw_name)
            self.assertFalse(hw_mac in hw_macs,
                             'duplicate hardware MAC %s' % hw_mac)
            hw_macs.add(hw_mac)
            # Create mininet Intf and attach it to the switch
            hw_intf = HWIntf(hw_name, node=switch)
            switch.attach(hw_intf)
            hw_port = switch.ports[hw_intf]
            # Connect hw_port <-> ovs_port
            src, dst = hw_port, ovs_port
            for flow in (
                    # Drop anything to or from the meaningless hw_mac
                    'eth_src=%s,priority=2,actions=drop' % hw_mac,
                    'eth_dst=%s,priority=2,actions=drop' % hw_mac,
                    # Forward traffic bidirectionally src <-> dst
                    'in_port=%u,priority=1,actions=output:%u' % (src, dst),
                    'in_port=%u,priority=1,actions=output:%u' % (dst, src)):
                switch.cmd(self.OFCTL, 'add-flow', switch, flow)

    def create_port_map(self, dpid):
        """Return a port map {'port_1': port...} for a dpid in self.topo"""
        ports = self.topo.dpid_ports(dpid)
        port_map = {'port_%d' % i: port for i, port in enumerate(ports, start=1)}
        return port_map

    def start_net(self):
        """Start Mininet network."""
        controller_intf = 'lo'
        controller_ipv6 = False
        if self.hw_switch:
            controller_intf = self.cpn_intf
            controller_ipv6 = self.cpn_ipv6
        if not self.port_map:
            # Sometimes created in build_net for config purposes, sometimes not
            self.port_map = self.create_port_map(self.dpid)
        self._block_non_faucet_packets()
        self._start_faucet(controller_intf, controller_ipv6)
        self.pre_start_net()
        if self.hw_switch:
            self._attach_physical_switch()
        self._wait_debug_log()
        for port_no in self._dp_ports():
            self.set_port_up(port_no, wait=False)
        dumpNodeConnections(self.hosts_name_ordered())
        self.reset_all_ipv4_prefix(prefix=24)

    def _get_controller(self):
        """Return first controller."""
        return self.net.controllers[0]

    @staticmethod
    def _start_gauge_check():
        return None

    def _start_check(self):
        if not self._wait_controllers_healthy():
            return 'not all controllers healthy'
        if not self._wait_controllers_connected():
            return 'not all controllers connected to switch'
        if not self._wait_ofctl_up():
            return 'ofctl not up'
        if not self.wait_dp_status(1):
            return 'prometheus port not up'
        if not self._wait_controllers_healthy():
            return 'not all controllers healthy after initial switch connection'
        if self.config_ports:
            for port_name, port in self.config_ports.items():
                if port is not None and not port_name.startswith('gauge'):
                    if not self._get_controller().listen_port(port):
                        return 'faucet not listening on %u (%s)' % (
                            port, port_name)
        return self._start_gauge_check()

    def _create_faucet_controller(self, index, intf, ipv6):
        port = self.faucet_of_ports[index]
        name = 'faucet-%s' % index
        faucet_controller = self.CONTROLLER_CLASS(
            name=name, tmpdir=self.tmpdir,
            controller_intf=intf,
            controller_ipv6=ipv6,
            env=self.env[name],
            ctl_privkey=self.ctl_privkey,
            ctl_cert=self.ctl_cert,
            ca_certs=self.ca_certs,
            ports_sock=self.ports_sock,
            prom_port=self.get_prom_port(name),
            port=port,
            test_name=self._test_name())
        self.env[faucet_controller.name] = self.env.pop(name)
        self.faucet_controllers.append(faucet_controller)
        return faucet_controller

    def _create_gauge_controller(self, index, intf, ipv6):
        port = self.gauge_of_ports[index]
        name = 'gauge-%s' % index
        gauge_controller = mininet_test_topo.Gauge(
            name=name, tmpdir=self.tmpdir,
            env=self.env[name],
            controller_intf=intf,
            controller_ipv6=ipv6,
            ctl_privkey=self.ctl_privkey,
            ctl_cert=self.ctl_cert,
            ca_certs=self.ca_certs,
            port=port)
        self.env[gauge_controller.name] = self.env.pop(name)
        self.gauge_controllers.append(gauge_controller)
        return gauge_controller

    def _start_faucet(self, controller_intf, controller_ipv6):
        last_error_txt = ''
        # Cannot multiply call _start_faucet()
        self.assertIsNone(self.net, 'Cannot multiply call _start_faucet()')
        for _ in range(3):
            self.faucet_controllers = []
            self.gauge_controllers = []
            mininet_test_util.return_free_ports(
                self.ports_sock, self._test_name())
            self._allocate_config_ports()
            self._allocate_faucet_ports()
            self._set_vars()
            for log in glob.glob(os.path.join(self.tmpdir, '*.log')):
                os.remove(log)
            # Create all the controller instances here, but only add the first one to the net
            for c_index in range(self.NUM_FAUCET_CONTROLLERS):
                controller = self._create_faucet_controller(c_index, controller_intf, controller_ipv6)
            self.net = Mininet(
                self.topo,
                link=FaucetLink,
                controller=self.faucet_controllers[0])
            # Add all gauge controllers to the net
            if self.RUN_GAUGE:
                self._allocate_gauge_ports()
                self._init_gauge_config()
                for c_index in range(self.NUM_GAUGE_CONTROLLERS):
                    controller = self._create_gauge_controller(c_index, controller_intf, controller_ipv6)
                    self.net.addController(controller)
                self.gauge_controller = self.gauge_controllers[0]
            self._init_faucet_config()
            self.net.start()
            self._wait_load()
            last_error_txt = self._start_check()
            if last_error_txt is None:
                self._config_tableids()
                self._wait_load()
                for controller in self.faucet_controllers:
                    if controller != self.faucet_controllers[0]:
                        self.net.addController(controller)
                        for switch in self.net.switches:
                            switch.addController(controller)
                # Add remaining faucet controllers & ensure remaining controllers are connected
                for controller in self.faucet_controllers:
                    if controller != self.faucet_controllers[0]:
                        time.sleep(self.FAUCET_CONTROLLER_START_DELAY)
                        controller.start()
                time.sleep(self.FAUCET_CONTROLLER_START_DELAY)
                if self.NUM_FAUCET_CONTROLLERS > 1:
                    # If we add controllers, want to make sure that they are now connected
                    self._wait_load()
                    last_error_txt = self._start_check()
                    time.sleep(self.FAUCET_CONTROLLER_START_DELAY)
                if last_error_txt is None:
                    self._config_tableids()
                    self._wait_load()
                    if self.NETNS:
                        # TODO: seemingly can't have more than one namespace.
                        for host in self.hosts_name_ordered()[:1]:
                            hostns = self.hostns(host)
                            if self.get_host_netns(host):
                                self.quiet_commands(host, ['ip netns del %s' % hostns])
                            self.quiet_commands(host, ['ip netns add %s' % hostns])
                    return
            self._stop_net()
            last_error_txt += '\n\n' + self._dump_controller_logs()
            error('%s: %s' % (self._test_name(), last_error_txt))
            time.sleep(mininet_test_util.MIN_PORT_AGE)
        self.fail(last_error_txt)

    def _ofctl_rest_url(self, req):
        """Return control URL for Ryu ofctl module."""
        return 'http://[%s]:%u/%s' % (
            mininet_test_util.LOCALHOSTV6, self._get_controller().ofctl_port, req)

    @staticmethod
    def _ofctl(req, params=None):
        if params is None:
            params = {}
        try:
            ofctl_result = requests.get(req, params=params).json()
        except requests.exceptions.ConnectionError:
            return None
        return ofctl_result

    def _ofctl_up(self):
        switches = self._ofctl(self._ofctl_rest_url('stats/switches'))
        return isinstance(switches, list) and switches

    def _wait_ofctl_up(self, timeout=10):
        for _ in range(timeout):
            if self._ofctl_up():
                return True
            time.sleep(1)
        return False

    def _ofctl_post(self, int_dpid, req, timeout, params=None):
        for _ in range(timeout):
            try:
                ofctl_result = requests.post(
                    self._ofctl_rest_url(req),
                    json=params).json()
                return ofctl_result[int_dpid]
            except (ValueError, TypeError, requests.exceptions.ConnectionError):
                # Didn't get valid JSON, try again
                time.sleep(1)
                continue
        return []

    def _ofctl_get(self, int_dpid, req, timeout, params=None):
        for _ in range(timeout):
            ofctl_result = self._ofctl(self._ofctl_rest_url(req), params=params)
            try:
                return ofctl_result[int_dpid]
            except (ValueError, TypeError):
                # Didn't get valid JSON, try again
                time.sleep(1)
                continue
        return []

    def _portmod(self, int_dpid, port_no, config, mask):
        result = requests.post(
            self._ofctl_rest_url('stats/portdesc/modify'),
            json={'dpid': str(int_dpid), 'port_no': str(port_no),
                  'config': str(config), 'mask': str(mask)})
        # ofctl doesn't use barriers, so cause port_mod to be sent.
        self.get_port_stats_from_dpid(int_dpid, port_no)
        return result

    @staticmethod
    def _signal_proc_on_port(host, port, signal):
        tcp_pattern = '%s/tcp' % port
        fuser_out = host.cmd('fuser %s -k -%u' % (tcp_pattern, signal))
        return re.search(r'%s:\s+\d+' % tcp_pattern, fuser_out)

    def _get_ofchannel_logs(self):
        ofchannel_logs = []
        config = self._get_faucet_conf()
        for dp_name, dp_config in config['dps'].items():
            if 'ofchannel_log' in dp_config:
                debug_log = dp_config['ofchannel_log']
                ofchannel_logs.append((dp_name, debug_log))
        return ofchannel_logs

    def _dump_controller_logs(self):
        dump_txt = ''
        test_logs = glob.glob(os.path.join(self.tmpdir, '*.log'))
        for controller in self.net.controllers:
            for test_log_name in test_logs:
                basename = os.path.basename(test_log_name)
                if basename.startswith(controller.name):
                    with open(test_log_name) as test_log:
                        dump_txt += '\n'.join((
                            '',
                            basename,
                            '=' * len(basename),
                            '',
                            test_log.read()))
                    break
        return dump_txt

    def _controllers_healthy(self):
        for controller in self.net.controllers:
            if not controller.healthy():
                return False
        if self.event_sock and not os.path.exists(self.event_sock):
            error('event socket %s not created\n' % self.event_sock)
            return False
        return True

    def _controllers_connected(self):
        for controller in self.net.controllers:
            if not controller.connected():
                return False
        return True

    def _wait_controllers_healthy(self, timeout=30):
        for _ in range(timeout):
            if self._controllers_healthy():
                return True
            time.sleep(1)
        return False

    def _wait_controllers_connected(self, timeout=30):
        for _ in range(timeout):
            if self._controllers_connected():
                return True
            time.sleep(1)
        return False

    def _wait_debug_log(self):
        """Require all switches to have exchanged flows with controller."""
        ofchannel_logs = self._get_ofchannel_logs()
        for _, debug_log in ofchannel_logs:
            for _ in range(60):
                if (os.path.exists(debug_log) and
                        os.path.getsize(debug_log) > 0):
                    return True
                time.sleep(1)
        return False

    def verify_no_exception(self, exception_log_name):
        if not os.path.exists(exception_log_name):
            return
        with open(exception_log_name) as exception_log:
            exception_contents = exception_log.read()
            self.assertEqual(
                '',
                exception_contents,
                msg='%s log contains %s' % (
                    exception_log_name, exception_contents))

    @staticmethod
    def tcpdump_helper(*args, **kwargs):
        return TcpdumpHelper(*args, **kwargs).execute()

    @staticmethod
    def scapy_template(packet, iface, count=1):
        return ('python3 -c \"from scapy.all import * ; sendp(%s, iface=\'%s\', count=%u)"' % (
            packet, iface, count))

    def scapy_base_udp(self, mac, iface, src_ip, dst_ip, dport, sport, count=1, dst=None):
        if dst is None:
            dst = 'ff:ff:ff:ff:ff:ff'
        return self.scapy_template(
            ('Ether(dst=\'%s\', src=\'%s\', type=%u) / '
             'IP(src=\'%s\', dst=\'%s\') / UDP(dport=%s,sport=%s) ' % (
                dst, mac, IPV4_ETH, src_ip, dst_ip, dport, sport)),
            iface, count)

    def scapy_dhcp(self, mac, iface, count=1, dst=None):
        if dst is None:
            dst = 'ff:ff:ff:ff:ff:ff'
        return self.scapy_template(
            ('Ether(dst=\'%s\', src=\'%s\', type=%u) / '
             'IP(src=\'0.0.0.0\', dst=\'255.255.255.255\') / UDP(dport=67,sport=68) / '
             'BOOTP(op=1) / DHCP(options=[(\'message-type\', \'discover\'), (\'end\')])') % (
                 dst, mac, IPV4_ETH),
            iface, count)

    def scapy_icmp(self, mac, iface, src_ip, dst_ip, count=1, dst=None):
        if dst is None:
            dst = 'ff:ff:ff:ff:ff:ff'
        return self.scapy_template(
            ('Ether(dst=\'%s\', src=\'%s\', type=%u) / '
             'IP(src=\'%s\', dst=\'%s\') / ICMP()') % (
                dst, mac, IPV4_ETH, src_ip, dst_ip),
            iface, count)

    def scapy_dscp(self, src_mac, dst_mac, dscp_value, iface, count=1):
        # creates a packet with L2-L4 headers using scapy
        return self.scapy_template(
            ('Ether(dst=\'%s\', src=\'%s\', type=%u) / '
             'IP(src=\'0.0.0.0\', dst=\'255.255.255.255\', tos=%s) / UDP(dport=67,sport=68) / '
             'BOOTP(op=1)') % (
                 dst_mac, src_mac, IPV4_ETH, dscp_value),
            iface, count)

    def scapy_bcast(self, host, count=1):
        return self.scapy_dhcp(host.MAC(), host.defaultIntf(), count)

    @staticmethod
    def pre_start_net():
        """Hook called after Mininet initializtion, before Mininet started."""
        return

    def get_config_header(self, config_global, debug_log, dpid, hardware):
        """Build v2 FAUCET config header."""
        return """
%s
dps:
    %s:
        ofchannel_log: %s
        dp_id: 0x%x
        hardware: "%s"
        cookie: %u
""" % (config_global, self.DP_NAME, debug_log,
       int(dpid), hardware, random.randint(1, 2**64-1))

    def get_gauge_watcher_config(self):
        return """
    port_stats:
        dps: ['%s']
        type: 'port_stats'
        interval: 5
        db: 'stats_file'
    port_state:
        dps: ['%s']
        type: 'port_state'
        interval: 5
        db: 'state_file'
    flow_table:
        dps: ['%s']
        type: 'flow_table'
        interval: 5
        db: 'flow_dir'
""" % (self.DP_NAME, self.DP_NAME, self.DP_NAME)

    def get_gauge_config(self, faucet_config_file,
                         monitor_stats_file,
                         monitor_state_file,
                         monitor_flow_table_dir):
        """Build Gauge config."""
        return """
faucet_configs:
    - %s
watchers:
    %s
dbs:
    stats_file:
        type: 'text'
        file: %s
    state_file:
        type: 'text'
        file: %s
    flow_dir:
        type: 'text'
        path: %s
%s
""" % (faucet_config_file,
            self.get_gauge_watcher_config(),
            monitor_stats_file,
            monitor_state_file,
            monitor_flow_table_dir,
            self.GAUGE_CONFIG_DBS)

    @staticmethod
    def get_exabgp_conf(peer, peer_config=''):
        return """
  neighbor %s {
    router-id 2.2.2.2;
    local-address %s;
    connect %s;
    peer-as 1;
    local-as %s;
    %s
  }
""" % (peer, peer, '%(bgp_port)d', PEER_BGP_AS, peer_config)

    def get_all_groups_desc_from_dpid(self, dpid, timeout=2):
        int_dpid = mininet_test_util.str_int_dpid(dpid)
        return self._ofctl_get(
            int_dpid, 'stats/groupdesc/%s' % int_dpid, timeout)

    def get_all_flows_from_dpid(self, dpid, table_id, timeout=10, match=None):
        """Return all flows from DPID."""
        int_dpid = mininet_test_util.str_int_dpid(dpid)
        params = {}
        params['table_id'] = table_id
        if match is not None:
            params['match'] = match
        return self._ofctl_post(
            int_dpid, 'stats/flow/%s' % int_dpid, timeout, params=params)

    @staticmethod
    def _port_stat(port_stats, port):
        if port_stats:
            for port_stat in port_stats:
                if port_stat['port_no'] == port:
                    return port_stat
        return None

    def get_port_stats_from_dpid(self, dpid, port, timeout=2):
        """Return port stats for a port."""
        int_dpid = mininet_test_util.str_int_dpid(dpid)
        port_stats = self._ofctl_get(
            int_dpid, 'stats/port/%s/%s' % (int_dpid, port), timeout)
        return self._port_stat(port_stats, port)

    def get_port_desc_from_dpid(self, dpid, port, timeout=2):
        """Return port desc for a port."""
        int_dpid = mininet_test_util.str_int_dpid(dpid)
        port_stats = self._ofctl_get(
            int_dpid, 'stats/portdesc/%s/%s' % (int_dpid, port), timeout)
        return self._port_stat(port_stats, port)

    def get_all_meters_from_dpid(self, dpid):
        """Return all meters from DPID"""
        int_dpid = mininet_test_util.str_int_dpid(dpid)
        return self._ofctl_get(
            int_dpid, 'stats/meterconfig/%s' % int_dpid, timeout=10)

    def wait_matching_in_group_table(self, action, group_id, timeout=10):
        groupdump = os.path.join(self.tmpdir, 'groupdump-%s.txt' % self.dpid)
        for _ in range(timeout):
            group_dump = self.get_all_groups_desc_from_dpid(self.dpid, 1)
            with open(groupdump, 'w') as groupdump_file:
                for group_dict in group_dump:
                    groupdump_file.write(str(group_dict) + '\n')
                    if group_dict['group_id'] == group_id:
                        actions = set(group_dict['buckets'][0]['actions'])
                        if set([action]).issubset(actions):
                            return True
            time.sleep(1)
        return False

    # TODO: Should this have meter_confs as well or can we just match meter_ids
    def get_matching_meters_on_dpid(self, dpid):
        meterdump = os.path.join(self.tmpdir, 'meterdump-%s.log' % dpid)
        meter_dump = self.get_all_meters_from_dpid(dpid)
        with open(meterdump, 'w') as meterdump_file:
            meterdump_file.write(str(meter_dump))
        return meterdump

    def get_matching_flows_on_dpid(self, dpid, match, table_id, timeout=10,
                                   actions=None, hard_timeout=0, cookie=None,
                                   ofa_match=True):

        # TODO: Ryu ofctl serializes to old matches.
        def to_old_match(match):
            old_matches = {
                'tcp_dst': 'tp_dst',
                'ip_proto': 'nw_proto',
                'eth_dst': 'dl_dst',
                'eth_type': 'dl_type',
            }
            if match is not None:
                for new_match, old_match in old_matches.items():
                    if new_match in match:
                        match[old_match] = match[new_match]
                        del match[new_match]
            return match

        flowdump = os.path.join(self.tmpdir, 'flowdump-%s.log' % dpid)
        match = to_old_match(match)
        match_set = None
        exact_mask_match_set = None
        if match:
            # Different OFAs handle matches with an exact mask, different.
            # Most (including OVS) drop the redundant exact mask. But others
            # include an exact mask. So we must handle both.
            mac_exact = str(netaddr.EUI(2**48-1)).replace('-', ':').lower()
            match_set = frozenset(match.items())
            exact_mask_match = {}
            for field, value in match.items():
                if isinstance(value, str) and not '/' in value:
                    value_mac = None
                    value_ip = None
                    try:
                        value_mac = netaddr.EUI(value)
                        value_ip = ipaddress.ip_address(value)
                    except (ValueError, netaddr.core.AddrFormatError):
                        pass
                    if value_mac:
                        value = '/'.join((value, mac_exact))
                    elif value_ip:
                        ip_exact = str(ipaddress.ip_address(2**value_ip.max_prefixlen-1))
                        value = '/'.join((value, ip_exact))
                exact_mask_match[field] = value
            exact_mask_match_set = frozenset(exact_mask_match.items())
        actions_set = None
        if actions:
            actions_set = frozenset(actions)

        for _ in range(timeout):
            flow_dicts = []
            if ofa_match:
                flow_dump = self.get_all_flows_from_dpid(dpid, table_id, match=match)
            else:
                flow_dump = self.get_all_flows_from_dpid(dpid, table_id)
            with open(flowdump, 'w') as flowdump_file:
                flowdump_file.write(str(flow_dump))
            for flow_dict in flow_dump:
                if (cookie is not None and
                        cookie != flow_dict['cookie']):
                    continue
                if hard_timeout:
                    if not 'hard_timeout' in flow_dict:
                        continue
                    if flow_dict['hard_timeout'] < hard_timeout:
                        continue
                if actions is not None:
                    flow_actions_set = frozenset(flow_dict['actions'])
                    if actions:
                        if not actions_set.issubset( # pytype: disable=attribute-error
                                flow_actions_set):
                            continue
                    else:
                        if flow_dict['actions']:
                            continue
                if not ofa_match and match is not None:
                    flow_match_set = frozenset(flow_dict['match'].items())
                    if not (match_set.issubset(flow_match_set) or exact_mask_match_set.issubset(flow_match_set)): # pytype: disable=attribute-error
                        continue
                flow_dicts.append(flow_dict)
            if flow_dicts:
                return flow_dicts
            time.sleep(1)
        return flow_dicts

    def get_matching_flow_on_dpid(self, dpid, match, table_id, timeout=10,
                                  actions=None, hard_timeout=0, cookie=None,
                                  ofa_match=True):
        flow_dicts = self.get_matching_flows_on_dpid(
            dpid, match, table_id, timeout=timeout,
            actions=actions, hard_timeout=hard_timeout, cookie=cookie,
            ofa_match=ofa_match)
        if flow_dicts:
            return flow_dicts[0]
        return []

    def get_matching_flow(self, match, table_id, timeout=10,
                          actions=None, hard_timeout=0,
                          cookie=None, ofa_match=True):
        return self.get_matching_flow_on_dpid(
            self.dpid, match, table_id, timeout=timeout,
            actions=actions, hard_timeout=hard_timeout,
            cookie=cookie, ofa_match=ofa_match)

    def get_group_id_for_matching_flow(self, match, table_id, timeout=10):
        for _ in range(timeout):
            flow_dict = self.get_matching_flow(match, table_id, timeout=timeout)
            if flow_dict:
                for action in flow_dict['actions']:
                    if action.startswith('GROUP'):
                        _, group_id = action.split(':')
                        return int(group_id)
            time.sleep(1)
        return None

    def matching_flow_present_on_dpid(self, dpid, match, table_id, timeout=10,
                                      actions=None, hard_timeout=0, cookie=None,
                                      ofa_match=True):
        """Return True if matching flow is present on a DPID."""
        return self.get_matching_flow_on_dpid(
            dpid, match, table_id, timeout=timeout,
            actions=actions, hard_timeout=hard_timeout, cookie=cookie,
            ofa_match=ofa_match)

    def matching_flow_present(self, match, table_id, timeout=10,
                              actions=None, hard_timeout=0, cookie=None,
                              ofa_match=True):
        """Return True if matching flow is present on default DPID."""
        return self.matching_flow_present_on_dpid(
            self.dpid, match, table_id, timeout=timeout,
            actions=actions, hard_timeout=hard_timeout, cookie=cookie,
            ofa_match=ofa_match)

    def wait_until_matching_flow(self, match, table_id, timeout=10,
                                 actions=None, hard_timeout=0, cookie=None,
                                 ofa_match=True, dpid=None):
        """Wait (require) for flow to be present on default DPID."""
        if dpid is None:
            dpid = self.dpid
        self.assertTrue(
            self.matching_flow_present_on_dpid(
                dpid, match, table_id, timeout=timeout,
                actions=actions, hard_timeout=hard_timeout, cookie=cookie,
                ofa_match=ofa_match),
            msg=('match: %s table_id: %u actions: %s' % (match, table_id, actions)))

    def wait_until_no_matching_flow(self, match, table_id, timeout=10,
                                    actions=None, hard_timeout=0, cookie=None,
                                    ofa_match=True, dpid=None):
        """Wait for a flow not to be present."""
        if dpid is None:
            dpid = self.dpid
        for _ in range(timeout):
            matching_flow = self.matching_flow_present_on_dpid(
                dpid, match, table_id, timeout=1,
                actions=actions, hard_timeout=hard_timeout, cookie=cookie,
                ofa_match=ofa_match)
            if not matching_flow:
                return
        self.fail('%s present' % matching_flow)

    def wait_until_controller_flow(self):
        self.wait_until_matching_flow(
            None, table_id=self._ETH_SRC_TABLE, actions=['OUTPUT:CONTROLLER'])

    def mac_learned(self, mac, timeout=10, in_port=None, hard_timeout=1):
        """Return True if a MAC has been learned on default DPID."""
        for eth_field, table_id in (
                ('dl_src', self._ETH_SRC_TABLE),
                ('dl_dst', self._ETH_DST_TABLE)):
            match = {eth_field: '%s' % mac}
            match_hard_timeout = 0
            if table_id == self._ETH_SRC_TABLE:
                if in_port is not None:
                    match['in_port'] = in_port
                match_hard_timeout = hard_timeout
            if not self.matching_flow_present(
                    match, table_id, timeout=timeout, hard_timeout=match_hard_timeout):
                return False
        return True

    def scrape_port_counters(self, ports, port_vars):
        """Scrape Gauge for list of ports and list of variables."""
        port_counters = {port: {} for port in ports}
        for port in ports:
            port_labels = self.port_labels(self.port_map[port])
            for port_var in port_vars:
                val = self.scrape_prometheus_var(
                    port_var, labels=port_labels, controller=self.gauge_controller.name, dpid=True, retries=3)
                self.assertIsNotNone(val, '%s missing for port %s' % (port_var, port))
                port_counters[port][port_var] = val
            # Require port to be up and reporting non-zero speed.
            speed = self.scrape_prometheus_var(
                'of_port_curr_speed', labels=port_labels, controller=self.gauge_controller.name, retries=3)
            self.assertTrue(speed and speed > 0, msg='%s %s: %s' % (
                'of_port_curr_speed', port_labels, speed))
            state = self.scrape_prometheus_var(
                'of_port_state', labels=port_labels, controller=self.gauge_controller.name, retries=3)
            self.assertFalse(state & ofp.OFPPS_LINK_DOWN, msg='%s %s: %s' % (
                'of_port_state', port_labels, state))
        return port_counters

    def wait_ports_updating(self, ports, port_vars, stimulate_counters_func=None):
        """Return True if list of ports have list of variables all updated."""
        if stimulate_counters_func is None:
            stimulate_counters_func = self.ping_all_when_learned
        ports_not_updated = set(ports)
        first_counters = self.scrape_port_counters(ports_not_updated, port_vars)
        start_time = time.time()

        for _ in range(self.DB_TIMEOUT * 3):
            stimulate_counters_func()
            now_counters = self.scrape_port_counters(ports_not_updated, port_vars)
            updated_ports = set()
            for port in ports_not_updated:
                first = first_counters[port]
                now = now_counters[port]
                not_updated = [var for var, val in now.items() if val <= first[var]]
                if not_updated:
                    break
                else:
                    updated_ports.add(port)
            ports_not_updated -= updated_ports
            if ports_not_updated:
                time.sleep(1)
            else:
                break

        end_time = time.time()

        error('counter latency up to %u sec\n' % (end_time - start_time))
        return not ports_not_updated

    @staticmethod
    def mac_as_int(mac):
        return int(mac.replace(':', ''), 16)

    @staticmethod
    def mac_from_int(mac_int):
        mac_int_str = '%012x' % int(mac_int)
        return ':'.join(mac_int_str[i:i+2] for i in range(0, len(mac_int_str), 2))

    def prom_macs_learned(self, port=None, vlan=None):
        labels = {
            'n': r'\d+',
            'port': r'b\d+',
            'vlan': r'\d+',
        }
        if port:
            labels.update(self.port_labels(port))
        if vlan:
            labels['vlan'] = str(vlan)
        port_learned_macs_prom = self.scrape_prometheus_var(
            'learned_macs', labels=labels, default=[], multiple=True, dpid=True)
        macs = [self.mac_from_int(mac_int) for _, mac_int in port_learned_macs_prom if mac_int]
        return macs

    def prom_mac_learned(self, mac, port=None, vlan=None):
        return mac in self.prom_macs_learned(port=port, vlan=vlan)

    def host_learned(self, host, timeout=10, in_port=None, hard_timeout=1):
        """Return True if a host has been learned on default DPID."""
        return self.mac_learned(host.MAC(), timeout, in_port, hard_timeout=hard_timeout)

    @staticmethod
    def get_host_intf_mac(host, intf):
        return host.cmd('cat /sys/class/net/%s/address' % intf).strip()

    def get_host_netns(self, host):
        hostns = self.hostns(host)
        nses = [netns.split()[0] for netns in host.cmd('ip netns list').splitlines()]
        return hostns in nses

    @staticmethod
    def host_ip(host, family, family_re):
        host_ip_cmd = (
            r'ip -o -f %s addr show %s|'
            'grep -m 1 -Eo "%s %s"|cut -f2 -d " "' % (
                family,
                host.defaultIntf(),
                family,
                family_re))
        return host.cmd(host_ip_cmd).strip()

    def host_ipv4(self, host):
        """Return first IPv4/netmask for host's default interface."""
        return self.host_ip(host, 'inet', r'[0-9\\.]+\/[0-9]+')

    def host_ipv6(self, host):
        """Return first IPv6/netmask for host's default interface."""
        return self.host_ip(host, 'inet6', r'[0-9a-f\:]+\/[0-9]+')

    @staticmethod
    def reset_ipv4_prefix(host, prefix=24):
        host.setIP(host.IP(), prefixLen=prefix)

    def reset_all_ipv4_prefix(self, prefix=24):
        for host in self.hosts_name_ordered():
            self.reset_ipv4_prefix(host, prefix)

    def stimulate_host_learn(self, host):
        unicast_learn_cli = self.scapy_dhcp(host.MAC(), host.defaultIntf(), dst=self.FAUCET_MAC)
        bcast_learn_cli = self.scapy_dhcp(host.MAC(), host.defaultIntf())
        results = []
        for learn_cli in (unicast_learn_cli, bcast_learn_cli):
            results.append(host.cmd(learn_cli))
        return ' '.join(results)

    def require_host_learned(self, host, retries=8, in_port=None, hard_timeout=1):
        """Require a host be learned on default DPID."""
        for _ in range(retries):
            if self.host_learned(host, timeout=1, in_port=in_port, hard_timeout=hard_timeout):
                return
            learn_result = self.stimulate_host_learn(host)
        self.fail('Could not learn host %s (%s): %s' % (host, host.MAC(), learn_result))

    def get_prom_port(self, controller=None):
        if controller is None:
            controller = self.faucet_controllers[0].name
        return int(self.env[controller]['FAUCET_PROMETHEUS_PORT'])

    def get_prom_addr(self, controller=None):
        if controller is None:
            controller = self.faucet_controllers[0].name
        return self.env[controller]['FAUCET_PROMETHEUS_ADDR']

    def _prometheus_url(self, controller):
        if 'faucet' in controller:
            return 'http://[%s]:%u' % (
                self.get_prom_addr(), self.get_prom_port())
        if 'gauge' in controller:
            return 'http://[%s]:%u' % (
                self.get_prom_addr(), self.config_ports['gauge_prom_port'])
        raise NotImplementedError

    def scrape_prometheus(self, controller=None, timeout=15, var=None, verify_consistent=False):
        """
        Obtain prometheus statistics

        Args:
            controller (str): name of the controller for the prometheus variable to scrape for
            timeout (int): Timeout for scrape request
            var (str): Variable to match on & return
            verify_consistent (bool): Verifies that all values for each controller is consistent
        """
        all_prom_lines = []
        if controller is None:
            controller = self.faucet_controllers[0].name
        controller_iter = []
        if self.net.get(controller) in self.faucet_controllers:
            controller_iter = self.faucet_controllers
        else:
            controller_iter = self.gauge_controllers
        for cont in controller_iter:
            controller_name = cont.name
            url = self._prometheus_url(controller_name)
            try:
                prom_raw = requests.get(url, {}, timeout=timeout).text
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
                return []
            with open(os.path.join(self.tmpdir, '%s-prometheus.log' % controller_name), 'w') as prom_log:
                prom_log.write(prom_raw)
            prom_lines = [
                prom_line for prom_line in prom_raw.splitlines() if not prom_line.startswith('#')]
            if var:
                prom_lines = [
                    prom_line for prom_line in prom_lines if prom_line.startswith(var)]
            all_prom_lines.append(prom_lines)
        if verify_consistent:
            self.verify_prom_var(all_prom_lines)
        cont = self.net.get(controller)
        index = controller_iter.index(cont)
        return all_prom_lines[index]

    def verify_prom_var(self, all_prom_lines):
        """
        Verifies that all lines scraped from prometheus for each controller is consistent
        NOTE: Doesn't work too well as different controllers will have some different
            statistics, i.e. cold start time.
            So make sure to only set `verify_consistent` in `scrape_prometheus` with
            specific variables that you know should be consistent
        """
        for lines_a in all_prom_lines:
            for lines_b in all_prom_lines:
                self.assertEqual(len(lines_a), len(lines_b))
                for i in range(len(lines_a)):
                    prom_line_a = lines_a[i]
                    prom_line_b = lines_b[i]
                    match_a = self._PROM_LINE_RE.match(prom_line_a)
                    match_b = self._PROM_LINE_RE.match(prom_line_b)
                    self.assertIsNotNone(match_a)
                    self.assertIsNotNone(match_b)
                    var_a = match_a.group(1)
                    var_b = match_b.group(1)
                    self.assertEqual(var_a, var_b)
                    val_a = int(float(match_a.group(2)))
                    val_b = int(float(match_b.group(2)))
                    self.assertEqual(val_a, val_b, msg='%s %s inconsistent' % (prom_line_a, prom_line_b))

    def parse_prom_var(self, prom_line):
        """Parse prometheus variable, return tuple of variable name, variable value"""
        prom_line_match = self._PROM_LINE_RE.match(prom_line)
        self.assertIsNotNone(
            prom_line_match,
            msg='Invalid prometheus line %s' % prom_line)
        prom_var = prom_line_match.group(1)
        prom_val = int(float(prom_line_match.group(2)))
        return (prom_var, prom_val)

    def wait_for_prometheus_var(self, var, result_wanted, labels=None, any_labels=False, default=None,
                                dpid=True, multiple=False, controller=None, retries=3,
                                timeout=5, orgreater=False):
        if controller is None:
            controller = self.faucet_controllers[0].name
        for _ in range(timeout):
            result = self.scrape_prometheus_var(
                var, labels=labels, any_labels=any_labels, default=default,
                dpid=dpid, multiple=multiple, controller=controller, retries=retries)
            if result == result_wanted:
                return True
            if orgreater and result > result_wanted:
                return True
            time.sleep(1)
        return False

    def scrape_prometheus_var(self, var, labels=None, any_labels=False, default=None,
                              dpid=True, multiple=False, controller=None, retries=3,
                              verify_consistent=False):
        """
        Return parsed, prometheus variable

        Args:
            var (str): Prometheus variable to scrape for
            labels (dict): Labels to apply for the variable search
            any_labels (bool): Wildcard label match
            default: Default value to return if nothing found
            dpid (bool/int): Specific DPID or use default DPID in labels
            multiple (bool): Return multiple instances of found matching variables
            controller (str): Name of the controller owned variable to search for
            retries (int): Number of attempts to scrape a variable
            verify_consistent (bool): Verifies that all controllers have consistent variables
        """
        if controller is None:
            controller = self.faucet_controllers[0].name
        if dpid:
            if dpid is True:
                dpid = int(self.dpid)
            else:
                dpid = int(dpid)
        if dpid and self.dpid_names:
            dp_name = self.dpid_names[str(dpid)]
        else:
            dp_name = self.DP_NAME
        label_values_re = r''
        if any_labels:
            label_values_re = r'\{[^\}]+\}'
        else:
            if labels is None:
                labels = {}
            if dpid:
                labels.update({'dp_id': '0x%x' % dpid, 'dp_name': dp_name})
            if labels:
                label_values = []
                for label, value in sorted(labels.items()):
                    label_values.append('%s="%s"' % (label, value))
                label_values_re = r'\{%s\}' % r'\S+'.join(label_values)
        var_re = re.compile(r'^%s%s$' % (var, label_values_re))
        for i in range(retries):
            results = []
            prom_lines = self.scrape_prometheus(controller=controller, var=var)
            for prom_line in prom_lines:
                prom_var, prom_val = self.parse_prom_var(prom_line)
                if var_re.match(prom_var):
                    results.append((var, prom_val))
                    if not multiple:
                        break
            if results:
                if multiple:
                    return results
                return results[0][1]
            if i < (retries - 1):
                time.sleep(1)
        return default

    def gauge_smoke_test(self):
        watcher_files = set([
            self.monitor_stats_file,
            self.monitor_state_file,
            ])
        found_watcher_files = set()
        for _ in range(60):
            for watcher_file in watcher_files:
                if (os.path.exists(watcher_file)
                        and os.path.getsize(watcher_file)):
                    found_watcher_files.add(watcher_file)
            if watcher_files == found_watcher_files \
                    and bool(os.listdir(self.monitor_flow_table_dir)):
                break
            self.verify_no_exception(self.env[self.gauge_controller.name]['GAUGE_EXCEPTION_LOG'])
            time.sleep(1)
            found_watcher_files = set()
        missing_watcher_files = watcher_files - found_watcher_files
        self.assertEqual(
            missing_watcher_files, set(), msg='Gauge missing logs: %s' % missing_watcher_files)
        self.hup_controller(self.gauge_controller.name)
        self.verify_no_exception(self.env[self.faucet_controllers[0].name]['FAUCET_EXCEPTION_LOG'])

    def prometheus_smoke_test(self):
        prom_out = '\n'.join(self.scrape_prometheus())
        for nonzero_var in (
                r'of_packet_ins', r'of_flowmsgs_sent', r'of_dp_connections',
                r'faucet_config\S+name=\"flood\"', r'faucet_pbr_version\S+version='):
            self.assertTrue(
                re.search(r'%s\S+\s+[1-9]+' % nonzero_var, prom_out),
                msg='expected %s to be nonzero (%s)' % (nonzero_var, prom_out))
        for zero_var in (
                'of_errors', 'of_dp_disconnections'):
            self.assertTrue(
                re.search(r'%s\S+\s+0' % zero_var, prom_out),
                msg='expected %s to be present and zero (%s)' % (zero_var, prom_out))

    def get_configure_count(self, retries=5, controller=None):
        """Return the number of times FAUCET has processed a reload request."""
        if controller is None:
            controller = self.faucet_controllers[0].name
        for _ in range(retries):
            count = self.scrape_prometheus_var(
                'faucet_config_reload_requests_total',
                dpid=False, controller=controller)
            if count:
                break
            time.sleep(1)
        self.assertTrue(count, msg='configure count stayed zero')
        return count

    def hup_controller(self, controller=None):
        """Send a HUP signal to the controller."""
        if controller is None:
            controller = self.faucet_controllers[0].name
        cont_obj = self.net.get(controller)
        self.assertTrue(
            self._signal_proc_on_port(cont_obj, int(cont_obj.port), 1))

    def reload_conf(self, yaml_conf, conf_path, restart, cold_start,
                    change_expected=True, host_cache=None, hup=True, dpid=True):

        def _update_conf(conf_path, yaml_conf):
            if yaml_conf:
                yaml_conf = self._annotate_interfaces_conf(yaml_conf)
                self._write_yaml_conf(conf_path, yaml_conf)

        update_conf_func = partial(_update_conf, conf_path, yaml_conf)
        verify_faucet_reconf_func = partial(
            self.verify_faucet_reconf,
            cold_start=cold_start,
            change_expected=change_expected,
            reconf_funcs=[update_conf_func], hup=hup, dpid=dpid)

        if restart:
            if host_cache:
                vlan_labels = dict(vlan=host_cache)
                old_mac_table = sorted(self.scrape_prometheus_var(
                    'learned_macs', labels=vlan_labels, multiple=True, default=[], dpid=dpid))
                verify_faucet_reconf_func()
                new_mac_table = sorted(self.scrape_prometheus_var(
                    'learned_macs', labels=vlan_labels, multiple=True, default=[], dpid=dpid))
                self.assertFalse(
                    cold_start, msg='host cache is not maintained with cold start')
                self.assertTrue(
                    new_mac_table, msg='no host cache for VLAN %u' % host_cache)
                self.assertEqual(
                    old_mac_table, new_mac_table,
                    msg='host cache for VLAN %u not same over reload (old %s, new %s)' % (
                        host_cache, old_mac_table, new_mac_table))
            else:
                verify_faucet_reconf_func()
            return

        update_conf_func()

    def coldstart_conf(self, hup=True):
        orig_conf = self._get_faucet_conf()
        cold_start_conf = copy.deepcopy(orig_conf)
        if 'routers' in cold_start_conf:
            del cold_start_conf['routers']
        used_vids = set()
        for vlan_name, vlan_conf in cold_start_conf['vlans'].items():
            used_vids.add(vlan_conf.get('vid', vlan_name))
        unused_vids = list(set(range(2, max(used_vids))) - used_vids)
        assert len(unused_vids) >= len(self.port_map)
        # Ensure cold start by moving all ports to new, unused VLANs,
        # then back again.
        for dp_conf in cold_start_conf['dps'].values():
            dp_conf['interfaces'] = {
                self.port_map[port]: {'native_vlan': unused_vids[i]}
                for i, port in enumerate(self.port_map.keys(), start=0)}
        for conf in (cold_start_conf, orig_conf):
            self.reload_conf(
                conf, self.faucet_config_path,
                restart=True, cold_start=True, hup=hup)

    def add_port_config(self, port, port_config, conf=None,
                        restart=True, cold_start=False,
                        hup=True):
        if conf is None:
            conf = self._get_faucet_conf()
        conf['dps'][self.DP_NAME]['interfaces'][port] = port_config
        self.reload_conf(
            conf, self.faucet_config_path,
            restart, cold_start, hup=hup)

    def change_port_config(self, port, config_name, config_value,
                           conf=None, restart=True, cold_start=False,
                           hup=True, change_expected=True):
        if conf is None:
            conf = self._get_faucet_conf()
        if config_name is None:
            del conf['dps'][self.DP_NAME]['interfaces'][port]
        else:
            if config_value is None:
                del conf['dps'][self.DP_NAME]['interfaces'][port][config_name]
            else:
                conf['dps'][self.DP_NAME]['interfaces'][port][config_name] = config_value
        self.reload_conf(
            conf, self.faucet_config_path,
            restart, cold_start, hup=hup, change_expected=change_expected)

    def change_vlan_config(self, vlan, config_name, config_value,
                           conf=None, restart=True, cold_start=False,
                           hup=True):
        if conf is None:
            conf = self._get_faucet_conf()
        conf['vlans'][vlan][config_name] = config_value
        self.reload_conf(
            conf, self.faucet_config_path,
            restart, cold_start, hup=hup)

    def ipv4_vip_bcast(self):
        return self.FAUCET_VIPV4.network.broadcast_address

    def verify_traveling_dhcp_mac(self, retries=10):
        mac = '0e:00:00:00:00:ff'
        locations = set()
        for host in self.hosts_name_ordered():
            for _ in range(retries):
                host.cmd(self.scapy_dhcp(mac, host.defaultIntf()))
                new_locations = set()
                for line in self.scrape_prometheus(var='learned_macs'):
                    location, mac_float = self.parse_prom_var(line)
                    if self.mac_from_int(int(float(mac_float))) == mac:
                        new_locations.add(location)
                if locations != new_locations:
                    break
                time.sleep(1)
            # TODO: verify port/host association, not just that host moved.
            self.assertNotEqual(locations, new_locations)
            locations = new_locations

    def _verify_xcast(self, received_expected, packets, tcpdump_filter, scapy_cmd, host_a, host_b):
        received_packets = False
        for _ in range(packets):
            tcpdump_txt = self.tcpdump_helper(
                host_b, tcpdump_filter,
                [partial(host_a.cmd, scapy_cmd)],
                packets=1, timeout=2)
            msg = '%s (%s) -> %s (%s): %s' % (
                host_a, host_a.MAC(), host_b, host_b.MAC(), tcpdump_txt)
            received_no_packets = self.tcpdump_rx_packets(tcpdump_txt, packets=0)
            received_packets = received_packets or not received_no_packets
            if received_packets:
                if received_expected is not False:
                    return True
                self.assertTrue(received_expected, msg=msg)
            time.sleep(1)

        if received_expected is None:
            return received_packets
        else:
            self.assertEqual(received_expected, received_packets, msg=msg)
        return None

    def verify_broadcast(self, hosts=None, broadcast_expected=True, packets=3):
        host_a = self.hosts_name_ordered()[0]
        host_b = self.hosts_name_ordered()[-1]
        if hosts is not None:
            host_a, host_b = hosts
        tcpdump_filter = ' and '.join((
            'ether dst host ff:ff:ff:ff:ff:ff',
            'ether src host %s' % host_a.MAC(),
            'udp'))
        scapy_cmd = self.scapy_bcast(host_a, count=packets)
        return self._verify_xcast(broadcast_expected, packets, tcpdump_filter, scapy_cmd, host_a, host_b)

    def verify_unicast(self, hosts, unicast_expected=True, packets=3):
        host_a = self.hosts_name_ordered()[0]
        host_b = self.hosts_name_ordered()[-1]
        if hosts is not None:
            host_a, host_b = hosts
        tcpdump_filter = ' and '.join((
            'ether dst %s' % host_b.MAC(),
            'ether src %s' % host_a.MAC(),
            'udp'))
        scapy_cmd = self.scapy_template(
            ('Ether(src=\'%s\', dst=\'%s\', type=%u) / '
             'IP(src=\'%s\', dst=\'%s\') / UDP(dport=67,sport=68)') % (
                 host_a.MAC(), host_b.MAC(), IPV4_ETH,
                 host_a.IP(), host_b.IP()), host_a.defaultIntf(), count=packets)
        return self._verify_xcast(unicast_expected, packets, tcpdump_filter, scapy_cmd, host_a, host_b)

    def verify_empty_caps(self, cap_files):
        cap_file_cmds = [
            'tcpdump -n -v -A -r %s 2> /dev/null' % cap_file for cap_file in cap_files]
        self.quiet_commands(self.net.controllers[0], cap_file_cmds)

    def verify_no_bcast_to_self(self, timeout=3):
        bcast_cap_files = []
        tcpdump_timeout = timeout * len(self.hosts_name_ordered()) * 2
        for host in self.hosts_name_ordered():
            tcpdump_filter = '-Q in ether src %s' % host.MAC()
            bcast_cap_file = os.path.join(self.tmpdir, '%s-bcast.cap' % host)
            bcast_cap_files.append(bcast_cap_file)
            host.cmd(mininet_test_util.timeout_cmd(
                'tcpdump -U -n -c 1 -i %s -w %s %s &' % (
                    host.defaultIntf(), bcast_cap_file, tcpdump_filter), tcpdump_timeout))
        for host in self.hosts_name_ordered():
            for bcast_cmd in (
                    ('ndisc6 -w1 fe80::1 %s' % host.defaultIntf()),
                    ('ping -b -i0.1 -c3 %s' % self.ipv4_vip_bcast())):
                host.cmd(mininet_test_util.timeout_cmd(bcast_cmd, timeout))
        self.verify_empty_caps(bcast_cap_files)

    def verify_unicast_not_looped(self, packets=3):
        unicast_mac1 = '0e:00:00:00:00:02'
        unicast_mac2 = '0e:00:00:00:00:03'
        hello_template = (
            'Ether(src=\'%s\', dst=\'%s\')/'
            'IP(src=\'10.0.0.100\', dst=\'10.0.0.255\')/'
            'UDP(dport=9)/'
            'b\'hello\'')
        tcpdump_filter = '-Q in ether src %s' % unicast_mac1
        for host in self.hosts_name_ordered():
            host.cmd(
                self.scapy_template(
                    hello_template % (unicast_mac1, 'ff:ff:ff:ff:ff:ff'),
                    host.defaultIntf()))
            host.cmd(
                self.scapy_template(
                    hello_template % (unicast_mac2, 'ff:ff:ff:ff:ff:ff'),
                    host.defaultIntf()))
            tcpdump_txt = self.tcpdump_helper(
                host, tcpdump_filter, [
                    partial(host.cmd, (
                        self.scapy_template(
                            hello_template % (unicast_mac1, unicast_mac2),
                            host.defaultIntf(),
                            count=packets)))],
                timeout=(packets - 1), vflags='-vv', packets=1)
            self.verify_no_packets(tcpdump_txt)

    def verify_controller_fping(self, host, faucet_vip,
                                total_packets=100, packet_interval_ms=100, size=64):
        fping_bin = 'fping'
        if faucet_vip.version == 6:
            fping_bin = 'fping6'
        fping_cli = '%s %s -b %u -c %u -i %u %s' % (
            fping_bin, self.FPING_ARGS_SHORT, size, total_packets, packet_interval_ms, faucet_vip.ip)
        timeout = int(((1000.0 / packet_interval_ms) * total_packets) * 1.5)
        fping_out = host.cmd(mininet_test_util.timeout_cmd(
            fping_cli, timeout))
        error('%s: %s' % (self._test_name(), fping_out))
        self.assertTrue(
            re.search(r'\s+[1-9][0-9]* ICMP Echo Replies received', fping_out),
            msg=fping_out)

    def verify_learn_counters(self, vlan, ports, verify_neighbors=False):
        # Need to synchronize with stats update thread.
        for _ in range(7):
            vlan_hosts_learned = self.scrape_prometheus_var(
                'vlan_hosts_learned',
                {'vlan': str(vlan)})
            port_vlan_hosts_learned = 0
            prom_macs_learned = 0
            for port in ports:
                port_no = self.port_map['port_%u' % port]
                labels = {'vlan': str(vlan)}
                labels.update(self.port_labels(port_no))
                port_vlan_hosts_learned += self.scrape_prometheus_var(
                    'port_vlan_hosts_learned', labels, default=0)
                prom_macs_learned += len(self.prom_macs_learned(
                    vlan=vlan, port=port_no))
            if (vlan_hosts_learned == port_vlan_hosts_learned and
                    vlan_hosts_learned == prom_macs_learned):
                break
            time.sleep(1)
        self.assertEqual(vlan_hosts_learned, port_vlan_hosts_learned)
        self.assertEqual(vlan_hosts_learned, prom_macs_learned)
        if verify_neighbors:
            vlan_neighbors = self.scrape_prometheus_var(
                'vlan_neighbors',
                {'vlan': str(vlan)})
            self.assertEqual(vlan_hosts_learned, vlan_neighbors)
        return vlan_hosts_learned

    def verify_learning(self, test_net, learn_ip, min_hosts, max_hosts, learn_pps=20):

        # TODO: test environment is pretty hard on test host, with this many macvlans
        def simplify_intf_conf(host, intf):
            for conf_cmd in (
                    'echo 1 > /proc/sys/net/ipv6/conf/%s/disable_ipv6',
                    'echo 300 > /proc/sys/net/ipv4/neigh/%s/gc_stale_time',
                    'ip link set dev %s arp off',):
                self.assertEqual('', host.cmd(conf_cmd % intf))

        def generate_test_ipas():
            test_ipas = []
            for ipa in sorted(test_net.hosts()):
                if str(ipa).endswith('.0'):
                    continue
                if str(ipa).endswith('.255'):
                    continue
                test_ipas.append(ipa)
                if len(test_ipas) == max_hosts+len(self.hosts_name_ordered()):
                    break
            base_ipas = test_ipas[-len(self.hosts_name_ordered()):]
            return (base_ipas, test_ipas)

        def generate_mac_intfs(test_ipas, other_hosts):
            mac_intf_ipv4s = []
            for i in range(0, max_hosts):
                host = other_hosts[i % len(other_hosts)]
                mac_intf = 'mac%u' % i
                mac_ipv4 = str(test_ipas[i])
                mac_intf_ipv4s.append((host, mac_intf, mac_ipv4))
            return mac_intf_ipv4s

        first_host = self.hosts_name_ordered()[0]
        other_hosts = self.hosts_name_ordered()[1:]

        base_ipas, test_ipas = generate_test_ipas()
        mac_intf_ipv4s = generate_mac_intfs(test_ipas, other_hosts)

        for i, host in enumerate(self.hosts_name_ordered()):
            host.setIP(str(base_ipas[i]), prefixLen=test_net.prefixlen)
        self.ping_all_when_learned()

        learn_hosts = min_hosts
        successful_learn_hosts = 0

        fping_prefix = 'fping %s -q -c 1' % self.FPING_ARGS_SHORT
        pps_ms = 1e3 / learn_pps
        while learn_hosts <= max_hosts and successful_learn_hosts < max_hosts:
            error('will learn %u hosts\n' % learn_hosts)
            start_time = time.time()
            learn_host_list = mac_intf_ipv4s[successful_learn_hosts:learn_hosts]
            random.shuffle(learn_host_list)
            # configure macvlan interfaces and stimulate learning
            for host, mac_intf, mac_ipv4 in learn_host_list:
                fping_conf_start = time.time()
                self.add_macvlan(host, mac_intf, mac_ipv4, ipm=test_net.prefixlen)
                simplify_intf_conf(host, mac_intf)
                host.cmd('%s -I%s %s' % (fping_prefix, mac_intf, str(learn_ip)))
                fping_ms = (time.time() - fping_conf_start) * 1e3
                if fping_ms < pps_ms:
                    time.sleep((pps_ms - fping_ms) / 1e3)

            def verify_connectivity(learn_hosts):
                error('verifying connectivity')
                all_unverified_ips = [str(ipa) for ipa in test_ipas[:learn_hosts]]
                random.shuffle(all_unverified_ips)
                loss_re = re.compile(
                    r'^(\S+) : xmt\/rcv\/\%loss = \d+\/\d+\/(\d+)\%.+')
                while all_unverified_ips:
                    unverified_ips = set()
                    for _ in range(min(learn_pps, len(all_unverified_ips))):
                        unverified_ips.add(all_unverified_ips.pop())
                    for _ in range(10):
                        error('.')
                        random_unverified_ips = list(unverified_ips)
                        random.shuffle(random_unverified_ips)
                        fping_cmd = '%s %s' % (fping_prefix, ' '.join(random_unverified_ips))
                        fping_lines = first_host.cmd(fping_cmd).splitlines()
                        for fping_line in fping_lines:
                            loss_match = loss_re.match(fping_line)
                            if loss_match:
                                ipa = loss_match.group(1)
                                loss = int(loss_match.group(2))
                                if loss == 0:
                                    unverified_ips.remove(ipa)
                        if unverified_ips:
                            time.sleep(0.1 * len(unverified_ips))
                        else:
                            break
                    if unverified_ips:
                        error('could not verify connectivity for all hosts: %s\n' % unverified_ips)
                        return False

                return self.wait_for_prometheus_var(
                    'vlan_hosts_learned', learn_hosts, labels={'vlan': '100'},
                    timeout=15, orgreater=True)

            if verify_connectivity(learn_hosts):
                learn_time = time.time() - start_time
                # dump_packet_counters()
                error('verified %u hosts learned in %u sec\n' % (
                    learn_hosts, learn_time))
                successful_learn_hosts = learn_hosts
                learn_hosts = min(learn_hosts * 2, max_hosts)
            else:
                break
        self.assertGreaterEqual(successful_learn_hosts, min_hosts)

    def verify_vlan_flood_limited(self, vlan_first_host, vlan_second_host,
                                  other_vlan_host):
        """Verify that flooding doesn't cross VLANs."""
        for first_host, second_host in (
                (vlan_first_host, vlan_second_host),
                (vlan_second_host, vlan_first_host)):
            tcpdump_filter = 'ether host %s or ether host %s' % (
                first_host.MAC(), second_host.MAC())
            tcpdump_txt = self.tcpdump_helper(
                other_vlan_host, tcpdump_filter, [
                    partial(first_host.cmd, 'arp -d %s' % second_host.IP()),
                    partial(first_host.cmd, ' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))],
                packets=1)
            self.verify_no_packets(tcpdump_txt)

    def verify_ping_mirrored(self, first_host, second_host, mirror_host, both_mirrored=False):
        """Verify that unicast traffic to and from a mirrored port is mirrored."""
        self.ping((first_host, second_host))
        for host in (first_host, second_host):
            self.require_host_learned(host)
        self.retry_net_ping(hosts=(first_host, second_host))
        tcpdump_filter = (
            '(ether src %s or ether src %s) and '
            '(icmp[icmptype] == 8 or icmp[icmptype] == 0)') % (
                first_host.MAC(), second_host.MAC())
        first_ping_second = ' '.join((self.FPINGS_ARGS_ONE, second_host.IP()))
        expected_pings = 2
        max_expected_pings = 2
        if both_mirrored:
            max_expected_pings *= 2
        tcpdump_txt = self.tcpdump_helper(
            mirror_host, tcpdump_filter, [
                partial(first_host.cmd, first_ping_second)], packets=(max_expected_pings+1))
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt),
                        msg=tcpdump_txt)
        self.assertTrue(re.search(
            '%s: ICMP echo reply' % first_host.IP(), tcpdump_txt),
                        msg=tcpdump_txt)
        received_pings = self.match_tcpdump_rx_packets(tcpdump_txt)
        self.assertGreaterEqual(received_pings, expected_pings)
        self.assertLessEqual(received_pings, max_expected_pings)

    def verify_bcast_ping_mirrored(self, first_host, second_host, mirror_host, tagged=False, require_learned=True):
        """Verify that broadcast to a mirrored port, is mirrored."""
        if require_learned:
            self.ping((first_host, second_host))
            for host in (first_host, second_host):
                self.require_host_learned(host)
            self.retry_net_ping(hosts=(first_host, second_host))
        tcpdump_filter = (
            'ether src %s and ether dst ff:ff:ff:ff:ff:ff and '
            'icmp[icmptype] == 8') % second_host.MAC()
        if tagged:
            tcpdump_filter = 'vlan and %s' % tcpdump_filter
        else:
            tcpdump_filter = '%s and not vlan' % tcpdump_filter
        second_ping_bcast = 'ping -c3 -b %s' % self.ipv4_vip_bcast()
        tcpdump_txt = self.tcpdump_helper(
            mirror_host, tcpdump_filter, [
                partial(second_host.cmd, second_ping_bcast)],
            packets=1)
        self.assertTrue(re.search(
            '%s: ICMP echo request' % self.ipv4_vip_bcast(), tcpdump_txt),
                        msg=tcpdump_txt)

    def verify_ping_mirrored_multi(self, ping_pairs, mirror_host, both_mirrored=False):
        """ Verify that mirroring of multiple switchs works. Method
        will both perform a one at a time ping mirror check and a
        all at once test where all ping pairs are executed at the
        same time.

        Args:
            ping_pairs (list of tuple): Hosts to ping for tests
                in the format '[(host_a, host_b)]` where host_a
                will ping host_bs IP.
            mirror_host (FaucetHost): host to check mirroring
        """
        # Verify individual ping works
        for hosts in ping_pairs:
            self.verify_ping_mirrored(hosts[0], hosts[1], mirror_host, both_mirrored=both_mirrored)

        # Prepare our ping pairs
        for hosts in ping_pairs:
            self.ping(hosts)
        for hosts in ping_pairs:
            for host in hosts:
                self.require_host_learned(host)
        for hosts in ping_pairs:
            self.retry_net_ping(hosts=hosts)

        mirror_mac = mirror_host.MAC()
        tcpdump_filter = (
            'not ether src %s and '
            '(icmp[icmptype] == 8 or icmp[icmptype] == 0)') % mirror_mac

        # Calculate the execpted number of pings we need
        # to capture to validate port mirroring
        expected_pings = len(ping_pairs) * 2
        max_expected_pings = expected_pings
        if both_mirrored:
            max_expected_pings *= 2

        # Generate and run the mirror test pings
        ping_commands = []
        for hosts in ping_pairs:
            ping_commands.append(
                lambda hosts=hosts: hosts[0].cmd(' '.join((self.FPINGS_ARGS_ONE, hosts[1].IP()))))
        tcpdump_txt = self.tcpdump_helper(
            mirror_host, tcpdump_filter, ping_commands, packets=(max_expected_pings+1))

        for hosts in ping_pairs:
            self.assertTrue(re.search(
                '%s > %s: ICMP echo request' % (hosts[0].IP(), hosts[1].IP()), tcpdump_txt),
                            msg=tcpdump_txt)
            self.assertTrue(re.search(
                '%s > %s: ICMP echo reply' % (hosts[1].IP(), hosts[0].IP()), tcpdump_txt),
                            msg=tcpdump_txt)

        received_pings = self.match_tcpdump_rx_packets(tcpdump_txt)
        self.assertGreaterEqual(received_pings, expected_pings)
        self.assertLessEqual(received_pings, max_expected_pings)

    def match_tcpdump_rx_packets(self, tcpdump_txt):
        match_re = re.compile(r'.*(\d+) packets* captured.*')
        match = match_re.match(tcpdump_txt)
        self.assertTrue(match, msg=tcpdump_txt)
        packets = int(match.group(1))
        return packets

    def tcpdump_rx_packets(self, tcpdump_txt, packets=0):
        return self.match_tcpdump_rx_packets(tcpdump_txt) == packets

    def verify_no_packets(self, tcpdump_txt):
        self.assertTrue(self.tcpdump_rx_packets(tcpdump_txt, packets=0), msg=tcpdump_txt)

    def verify_eapol_mirrored(self, first_host, second_host, mirror_host):
        self.ping((first_host, second_host))
        for host in (first_host, second_host):
            self.require_host_learned(host)
        self.retry_net_ping(hosts=(first_host, second_host))
        mirror_mac = mirror_host.MAC()
        tmp_eap_conf = os.path.join(self.tmpdir, 'eap.conf')
        tcpdump_filter = (
            'not ether src %s and ether proto 0x888e' % mirror_mac)
        eap_conf_cmd = (
            'echo "eapol_version=2\nap_scan=0\nnetwork={\n'
            'key_mgmt=IEEE8021X\neap=MD5\nidentity=\\"login\\"\n'
            'password=\\"password\\"\n}\n" > %s' % tmp_eap_conf)
        wpa_supplicant_cmd = mininet_test_util.timeout_cmd(
            'wpa_supplicant -c%s -Dwired -i%s -d' % (
                tmp_eap_conf,
                first_host.defaultIntf().name),
            3)
        tcpdump_txt = self.tcpdump_helper(
            mirror_host, tcpdump_filter, [
                partial(first_host.cmd, eap_conf_cmd),
                partial(first_host.cmd, wpa_supplicant_cmd),
                partial(first_host.cmd, wpa_supplicant_cmd),
                partial(first_host.cmd, wpa_supplicant_cmd)],
            timeout=20, packets=1)
        self.assertTrue(
            re.search('01:80:c2:00:00:03, ethertype EAPOL', tcpdump_txt),
            msg=tcpdump_txt)

    def bogus_mac_flooded_to_port1(self):
        first_host, second_host, third_host = self.hosts_name_ordered()[0:3]
        unicast_flood_filter = 'ether host %s' % self.BOGUS_MAC
        static_bogus_arp = 'arp -s %s %s' % (first_host.IP(), self.BOGUS_MAC)
        curl_first_host = 'curl -m 5 http://%s' % first_host.IP()
        tcpdump_txt = self.tcpdump_helper(
            first_host, unicast_flood_filter,
            [lambda: second_host.cmd(static_bogus_arp),
             lambda: second_host.cmd(curl_first_host),
             lambda: self.ping(hosts=(second_host, third_host))])
        return not self.tcpdump_rx_packets(tcpdump_txt, 0)

    def ladvd_cmd(self, ladvd_args, repeats=1, timeout=3):
        ladvd_mkdir = 'mkdir -p /var/run/ladvd'
        ladvd_all_args = ['%s %s' % (
            mininet_test_util.timeout_cmd(self.LADVD, timeout), ladvd_args)] * repeats
        ladvd_cmd = ';'.join([ladvd_mkdir] + ladvd_all_args)
        return ladvd_cmd

    def ladvd_noisemaker(self, send_cmd, tcpdump_filter, hosts=None, timeout=3, repeats=3):
        if hosts is None:
            hosts = self.hosts_name_ordered()[:2]
        first_host = hosts[0]
        other_hosts = hosts[1:]
        other_host_cmds = []
        for other_host in other_hosts:
            other_host_cmds.append(partial(other_host.cmd, self.ladvd_cmd(
                send_cmd % other_host.defaultIntf(), repeats=3, timeout=timeout)))
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, other_host_cmds,
            timeout=(timeout*repeats*len(hosts)), packets=1)
        self.verify_no_packets(tcpdump_txt)

    def verify_lldp_blocked(self, hosts=None, timeout=3):
        self.ladvd_noisemaker(
            '-L -o %s', 'ether proto 0x88cc',
            hosts, timeout=timeout)

    def verify_cdp_blocked(self, hosts=None, timeout=3):
        self.ladvd_noisemaker(
            '-C -o %s', 'ether dst host 01:00:0c:cc:cc:cc and ether[20:2]==0x2000',
            hosts, timeout=timeout)
        self.wait_nonzero_packet_count_flow(
            {'dl_dst': '01:00:0c:cc:cc:cc'}, self._FLOOD_TABLE, actions=[], ofa_match=False)

    def verify_faucet_reconf(self, timeout=20,
                             cold_start=True, change_expected=True,
                             hup=True, reconf_funcs=None, dpid=True):
        """HUP and verify the HUP was processed."""
        if reconf_funcs is None:
            reconf_funcs = []
        if hup:
            for controller in self.faucet_controllers:
                reconf_funcs.append(partial(self.hup_controller, controller=controller.name))
        var = 'faucet_config_reload_warm_total'
        if cold_start:
            var = 'faucet_config_reload_cold_total'
        old_counts = []
        start_configure_counts = []
        for controller in self.faucet_controllers:
            old_count = int(
                self.scrape_prometheus_var(var, controller=controller.name, dpid=dpid, default=0))
            old_counts.append(old_count)
            start_configure_count = self.get_configure_count(controller=controller.name)
            start_configure_counts.append(start_configure_count)
        for reconf_func in reconf_funcs:
            reconf_func()
        for i, controller in enumerate(self.faucet_controllers):
            cont_name = controller.name
            start_configure_count = start_configure_counts[i]
            old_count = old_counts[i]
            for _ in range(timeout):
                configure_count = self.get_configure_count(controller=cont_name)
                if configure_count > start_configure_count:
                    break
                time.sleep(1)
            self.assertNotEqual(
                start_configure_count, configure_count, 'FAUCET %s did not reconfigure' % cont_name)
            if change_expected:
                for _ in range(timeout):
                    new_count = int(
                        self.scrape_prometheus_var(var, controller=cont_name, dpid=dpid, default=0))
                    if new_count > old_count:
                        break
                    time.sleep(1)
                self.assertTrue(
                    new_count > old_count,
                    msg='FAUCET %s %s did not increment: %u' % (cont_name, var, new_count))
            else:
                new_count = int(
                    self.scrape_prometheus_var(var, controller=cont_name, dpid=dpid, default=0))
                self.assertEqual(
                    old_count, new_count,
                    msg='FAUCET %s %s incremented: %u' % (cont_name, var, new_count))
            self.wait_for_prometheus_var('faucet_config_applied', 1, controller=cont_name, dpid=None, timeout=30)
            self.wait_dp_status(1, controller=cont_name)

    def force_faucet_reload(self, new_config):
        """Force FAUCET to reload."""
        with open(self.faucet_config_path, 'w') as config_file:
            config_file.write(new_config)
        self.verify_faucet_reconf(change_expected=False)

    def get_host_port_stats(self, hosts_switch_ports):
        port_stats = {}
        for host, switch_port in hosts_switch_ports:
            if host not in port_stats:
                port_stats[host] = {}
            port_stats[host].update(self.get_port_stats_from_dpid(
                self.dpid, switch_port))
        return port_stats

    def wait_host_stats_updated(self, hosts_switch_ports, timeout, sync_counters_func=None):
        first = self.get_host_port_stats(hosts_switch_ports)
        for _ in range(timeout):
            if sync_counters_func:
                sync_counters_func()
            if self.get_host_port_stats(hosts_switch_ports) != first:
                return
            time.sleep(1)
        self.fail('port stats for %s never updated' % hosts_switch_ports)

    def of_bytes_mbps(self, start_port_stats, end_port_stats, var, seconds):
        return (end_port_stats[var] - start_port_stats[var]) * 8 / seconds / self.ONEMBPS

    def verify_iperf_min(self, hosts_switch_ports, min_mbps, client_ip, server_ip,
                         seconds=5, prop=0.2, sync_counters_func=None):
        """Verify minimum performance and OF counters match iperf approximately."""
        # Attempt loose counter sync before starting.
        self.wait_host_stats_updated(
            hosts_switch_ports, timeout=seconds*2, sync_counters_func=sync_counters_func)
        start_port_stats = self.get_host_port_stats(hosts_switch_ports)
        hosts = [host for host, _ in hosts_switch_ports]
        client_host, server_host = hosts
        iperf_mbps = self.iperf(
            client_host, client_ip, server_host, server_ip, seconds)
        self.assertGreater(iperf_mbps, min_mbps)
        # TODO: account for drops.
        for _ in range(3):
            end_port_stats = self.get_host_port_stats(hosts_switch_ports)
            approx_match = True
            for host in hosts:
                of_rx_mbps = self.of_bytes_mbps(
                    start_port_stats[host], end_port_stats[host], 'rx_bytes', seconds)
                of_tx_mbps = self.of_bytes_mbps(
                    start_port_stats[host], end_port_stats[host], 'tx_bytes', seconds)
                output(of_rx_mbps, of_tx_mbps)
                max_of_mbps = float(max(of_rx_mbps, of_tx_mbps))
                iperf_to_max = 0
                if max_of_mbps:
                    iperf_to_max = iperf_mbps / max_of_mbps
                msg = 'iperf: %fmbps, of: %fmbps (%f)' % (
                    iperf_mbps, max_of_mbps, iperf_to_max)
                error(msg)
                if ((iperf_to_max < (1.0 - prop)) or
                        (iperf_to_max > (1.0 + prop))):
                    approx_match = False
            if approx_match:
                return
            time.sleep(1)
        self.fail(msg=msg)

    def port_labels(self, port_no):
        port_name = 'b%u' % port_no
        return {'port': port_name, 'port_description': port_name}

    def set_dpid_names(self, dpid_names):
        self.dpid_names = copy.deepcopy(dpid_names)

    def wait_port_status(self, dpid, port_no, status, expected_status, timeout=10):
        for _ in range(timeout):
            port_status = self.scrape_prometheus_var(
                'port_status', self.port_labels(port_no), default=None, dpid=dpid)
            if port_status is not None and port_status == expected_status:
                return
            self._portmod(dpid, port_no, status, ofp.OFPPC_PORT_DOWN)
            time.sleep(1)
        self.fail('dpid %x port %s status %s != expected %u' % (
            dpid, port_no, port_status, expected_status))

    def set_port_status(self, dpid, port_no, status, wait):
        if dpid is None:
            dpid = self.dpid
        expected_status = 1
        if status == ofp.OFPPC_PORT_DOWN:
            expected_status = 0
        self._portmod(dpid, port_no, status, ofp.OFPPC_PORT_DOWN)
        if wait:
            self.wait_port_status(int(dpid), port_no, status, expected_status)

    def set_port_down(self, port_no, dpid=None, wait=True):
        self.set_port_status(dpid, port_no, ofp.OFPPC_PORT_DOWN, wait)

    def set_port_up(self, port_no, dpid=None, wait=True):
        self.set_port_status(dpid, port_no, 0, wait)

    def wait_dp_status(self, expected_status, controller=None, timeout=30):
        if controller is None:
            controller = self.faucet_controllers[0].name
        return self.wait_for_prometheus_var(
            'dp_status', expected_status, any_labels=True, controller=controller, default=None, timeout=timeout)

    def _get_tableid(self, name, retries, default):
        return self.scrape_prometheus_var(
            'faucet_config_table_names', {'table_name': name},
            retries=retries, default=default)

    def quiet_commands(self, host, commands):
        for command in commands:
            result = host.cmd(command)
            self.assertEqual('', result, msg='%s: %s' % (command, result))

    def _config_tableids(self):
        # Wait for VLAN table to appear, rapidly scrape the rest.
        self._VLAN_TABLE = self._get_tableid(
            'vlan', 1, self._VLAN_TABLE)
        self._COPRO_TABLE = self._get_tableid(
            'vlan', 1, self._COPRO_TABLE)
        self._PORT_ACL_TABLE = self._get_tableid(
            'port_acl', 1, self._PORT_ACL_TABLE)
        self._VLAN_ACL_TABLE = self._get_tableid(
            'vlan_acl', 1, self._VLAN_ACL_TABLE)
        self._ETH_SRC_TABLE = self._get_tableid(
            'eth_src', 1, self._ETH_SRC_TABLE)
        self._IPV4_FIB_TABLE = self._get_tableid(
            'ipv4_fib', 1, self._IPV4_FIB_TABLE)
        self._IPV6_FIB_TABLE = self._get_tableid(
            'ipv6_fib', 1, self._IPV6_FIB_TABLE)
        self._VIP_TABLE = self._get_tableid(
            'vip', 1, self._VIP_TABLE)
        self._ETH_DST_HAIRPIN_TABLE = self._get_tableid(
            'eth_dst_hairpin', 1, self._ETH_DST_HAIRPIN_TABLE)
        self._ETH_DST_TABLE = self._get_tableid(
            'eth_dst', 1, self._ETH_DST_TABLE)
        self._FLOOD_TABLE = self._get_tableid(
            'flood', 1, self._FLOOD_TABLE)

    def _dp_ports(self):
        return list(sorted(self.port_map.values()))

    def flap_port(self, port_no, flap_time=MIN_FLAP_TIME):
        self.set_port_down(port_no)
        time.sleep(flap_time)
        self.set_port_up(port_no)

    def flap_all_switch_ports(self, flap_time=MIN_FLAP_TIME):
        """Flap all ports on switch."""
        for port_no in self._dp_ports():
            self.flap_port(port_no, flap_time=flap_time)

    @staticmethod
    def get_mac_of_intf(intf, host=None):
        """Get MAC address of a port."""
        address_file_name = '/sys/class/net/%s/address' % intf
        if host is None:
            with open(address_file_name) as address_file:
                address = address_file.read()
        else:
            address = host.cmd('cat %s' % address_file_name)
        return address.strip().lower()

    def add_macvlan(self, host, macvlan_intf, ipa=None, ipm=24, mac=None, mode='vepa'):
        if mac is None:
            mac = ''
        else:
            mac = 'address %s' % mac
        add_cmds = [
            'ip link add %s link %s %s type macvlan mode %s' % (
                macvlan_intf, host.defaultIntf(), mac, mode),
            'ip link set dev %s up' % macvlan_intf]
        if ipa:
            add_cmds.append(
                'ip address add %s/%s brd + dev %s' % (ipa, ipm, macvlan_intf))
        self.quiet_commands(host, add_cmds)

    def del_macvlan(self, host, macvlan_intf):
        self.quiet_commands(host, [
            host.cmd('ip link del link %s %s' % (
                host.defaultIntf(), macvlan_intf))])

    def add_host_ipv6_address(self, host, ip_v6, intf=None):
        """Add an IPv6 address to a Mininet host."""
        if intf is None:
            intf = host.intf()
        self.quiet_commands(host, [
            host.cmd('ip -6 addr add %s dev %s' % (ip_v6, intf))])

    def add_host_route(self, host, ip_dst, ip_gw):
        """Add an IP route to a Mininet host."""
        host.cmd('ip -%u route del %s' % (
            ip_dst.version, ip_dst.network.with_prefixlen))
        add_cmd = 'ip -%u route add %s via %s' % (
            ip_dst.version, ip_dst.network.with_prefixlen, ip_gw)
        self.quiet_commands(host, (add_cmd,))

    def _ip_ping(self, host, dst, retries, timeout=500,
                 fping_bin='fping', intf=None, expected_result=True, count=1,
                 require_host_learned=require_host_learned):
        """Ping a destination from a host"""
        if intf is None:
            intf = host.defaultIntf()
        good_ping = r'xmt/rcv/%%loss = %u/%u/0%%' % (count, count)
        ping_cmd = '%s %s -c%u -I%s -t%u %s' % (
            fping_bin, self.FPING_ARGS, count, intf, timeout, dst)
        if require_host_learned:
            self.require_host_learned(host)
        pause = timeout / 1e3
        for _ in range(retries):
            ping_out = host.cmd(ping_cmd)
            ping_result = bool(re.search(good_ping, ping_out))
            if ping_result:
                break
            time.sleep(pause)
            pause *= 2
        self.assertEqual(ping_result, expected_result, msg='%s %s: %s' % (
            ping_cmd, ping_result, ping_out))

    def one_ipv4_ping(self, host, dst, retries=3, timeout=1000, intf=None,
                      require_host_learned=True, expected_result=True):
        """Ping an IPv4 destination from a host."""
        return self._ip_ping(
            host, dst, retries,
            timeout=timeout, fping_bin='fping', intf=intf,
            require_host_learned=require_host_learned,
            expected_result=expected_result)

    def flush_arp_cache(self, host):
        """Flush the ARP cache for a host."""
        host.cmd("ip -s neigh flush all")

    def one_ipv4_controller_ping(self, host):
        """Ping the controller from a host with IPv4."""
        self.flush_arp_cache(host)
        self.one_ipv4_ping(host, self.FAUCET_VIPV4.ip)
        self.verify_ipv4_host_learned_mac(
            host, self.FAUCET_VIPV4.ip, self.FAUCET_MAC)

    def one_ipv6_ping(self, host, dst, retries=5, timeout=1000, intf=None,
                      require_host_learned=True, expected_result=True):
        """Ping an IPv6 destination from a host."""
        return self._ip_ping(
            host, dst, retries,
            timeout=timeout, fping_bin='fping6', intf=intf,
            require_host_learned=require_host_learned,
            expected_result=expected_result)

    def one_ipv6_controller_ping(self, host):
        """Ping the controller from a host with IPv6."""
        self.one_ipv6_ping(host, self.FAUCET_VIPV6.ip)
        # TODO: VIP might not be in neighbor table if still tentative/ND used non VIP source address.
        # Make test host source addresses consistent.
        # self.verify_ipv6_host_learned_mac(
        #    host, self.FAUCET_VIPV6.ip, self.FAUCET_MAC)

    def pingAll(self, timeout=3):
        """Provide reasonable timeout default to Mininet's pingAll()."""
        return self.net.pingAll(timeout=timeout)

    def ping(self, hosts, timeout=3):
        """Provide reasonable timeout default to Mininet's ping()."""
        return self.net.ping(hosts, timeout=timeout)

    def retry_net_ping(self, hosts=None, required_loss=0, retries=3, timeout=2):
        loss = None
        for _ in range(retries):
            if hosts is None:
                loss = self.pingAll(timeout=timeout)
            else:
                loss = self.net.ping(hosts, timeout=timeout)
            if loss <= required_loss:
                return
            time.sleep(1)
        self.fail('ping %f loss > required loss %f' % (loss, required_loss))

    @staticmethod
    def tcp_port_free(host, port, ipv=4):
        listen_out = host.cmd(
            mininet_test_util.tcp_listening_cmd(port, ipv))
        if listen_out:
            return listen_out
        return None

    def wait_for_tcp_free(self, host, port, timeout=10, ipv=4):
        """Wait for a host to start listening on a port."""
        for _ in range(timeout):
            listen_out = self.tcp_port_free(host, port, ipv)
            if listen_out is None:
                return
            time.sleep(1)
        self.fail('%s busy on port %u (%s)' % (host, port, listen_out))

    def wait_for_tcp_listen(self, host, port, timeout=10, ipv=4):
        """Wait for a host to start listening on a port."""
        for _ in range(timeout):
            listen_out = self.tcp_port_free(host, port, ipv)
            if listen_out is not None:
                return
            time.sleep(1)
        self.fail('%s never listened on port %u' % (host, port))

    def serve_str_on_tcp_port(self, host, port, serve_str='hello', timeout=20):
        """Serve str on a TCP port on a host."""
        host.cmd(mininet_test_util.timeout_cmd(
            'echo %s | nc -l %s %u &' % (serve_str, host.IP(), port), timeout))
        self.wait_for_tcp_listen(host, port)

    def wait_nonzero_packet_count_flow(self, match, table_id, timeout=15,
                                       actions=None, dpid=None, ofa_match=True):
        """Wait for a flow to be present and have a non-zero packet_count."""
        if dpid is None:
            dpid = self.dpid
        for _ in range(timeout):
            flow = self.get_matching_flow_on_dpid(
                dpid, match, table_id, timeout=1,
                actions=actions, ofa_match=ofa_match)
            if flow and flow['packet_count'] > 0:
                return
            time.sleep(1)
        if flow:
            self.fail('flow %s matching %s table ID %s had zero packet count' % (flow, match, table_id))
        else:
            self.fail('no flow matching %s table ID %s' % (match, table_id))

    def verify_tp_dst_blocked(self, port, first_host, second_host, table_id=0, mask=None):
        """Verify that a TCP port on a host is blocked from another host."""
        client_cmd = mininet_test_util.timeout_cmd('nc %s %u' % (second_host.IP(), port), 5)
        self.serve_str_on_tcp_port(second_host, port)
        self.quiet_commands(first_host, (client_cmd,))
        if table_id is None:
            return
        match = {
            'dl_type': IPV4_ETH, 'ip_proto': 6
        }
        match_port = int(port)
        if mask is not None:
            match_port = '/'.join((str(port), str(mask)))
        match['tp_dst'] = match_port
        self.wait_nonzero_packet_count_flow(match, table_id, ofa_match=False)
        # cleanup listening nc (if any)
        second_host.cmd(client_cmd)

    def verify_tp_dst_notblocked(self, port, first_host, second_host, table_id=0):
        """Verify that a TCP port on a host is NOT blocked from another host."""
        serve_str = ''.join(random.choice(string.ascii_letters) for i in range(8))
        self.serve_str_on_tcp_port(second_host, port, serve_str=serve_str)
        client_str = first_host.cmd('nc -w 10 %s %u' % (second_host.IP(), port)).strip()
        self.assertEqual(serve_str, client_str)
        if table_id is None:
            return
        self.wait_nonzero_packet_count_flow(
            {'tp_dst': int(port), 'dl_type': IPV4_ETH, 'ip_proto': 6}, table_id)

    def bcast_dst_blocked_helper(self, port, first_host, second_host, success_re, retries):
        tcpdump_filter = 'udp and ether src %s and ether dst %s' % (
            first_host.MAC(), "ff:ff:ff:ff:ff:ff")
        target_addr = str(self.FAUCET_VIPV4.network.broadcast_address)
        for _ in range(retries):
            tcpdump_txt = self.tcpdump_helper(
                second_host, tcpdump_filter, [
                    partial(first_host.cmd, (
                        'date | socat - udp-datagram:%s:%d,broadcast' % (
                            target_addr, port)))],
                packets=1)
            if re.search(success_re, tcpdump_txt):
                return True
            time.sleep(1)
        return False

    def verify_bcast_dst_blocked(self, port, first_host, second_host):
        """Verify that a UDP port on a host is blocked from broadcast."""
        self.assertTrue(self.bcast_dst_blocked_helper(
            port, first_host, second_host, r'0 packets received by filter', 1))

    def verify_bcast_dst_notblocked(self, port, first_host, second_host):
        """Verify that a UDP port on a host is NOT blocked from broadcast."""
        self.assertTrue(self.bcast_dst_blocked_helper(
            port, first_host, second_host, r'1 packet received by filter', 3))

    @staticmethod
    def swap_host_macs(first_host, second_host):
        """Swap the MAC addresses of two Mininet hosts."""
        first_host_mac = first_host.MAC()
        second_host_mac = second_host.MAC()
        first_host.setMAC(second_host_mac)
        second_host.setMAC(first_host_mac)

    def start_exabgp(self, exabgp_conf, timeout=30, log_prefix=''):
        """Start exabgp process on controller host."""
        exabgp_conf_file_name = os.path.join(self.tmpdir, '%sexabgp.conf' % log_prefix)
        exabgp_log = os.path.join(self.tmpdir, '%sexabgp.log' % log_prefix)
        exabgp_out = os.path.join(self.tmpdir, '%sexabgp.out' % log_prefix)
        exabgp_env = ' '.join((
            'exabgp.daemon.user=root',
            'exabgp.log.all=true',
            'exabgp.log.level=DEBUG',
            'exabgp.log.destination=%s' % exabgp_log,
        ))
        bgp_port = self.config_ports['bgp_port']
        exabgp_conf = exabgp_conf % {'bgp_port': bgp_port}
        with open(exabgp_conf_file_name, 'w') as exabgp_conf_file:
            exabgp_conf_file.write(exabgp_conf)
        controller = self._get_controller()
        # Ensure exabgp only attempts one connection.
        exabgp_cmd = mininet_test_util.timeout_cmd(
            'exabgp %s --once -d 2>&1 > %s &' % (
                exabgp_conf_file_name, exabgp_out), 300)
        exabgp_cli = 'env %s %s' % (exabgp_env, exabgp_cmd)
        controller.cmd(exabgp_cli)
        for _ in range(timeout):
            if os.path.exists(exabgp_log):
                break
            time.sleep(1)
        self.assertTrue(
            os.path.exists(exabgp_log), msg='exabgp (%s) did not start' % exabgp_cli)
        return (exabgp_log, exabgp_out)

    def wait_bgp_up(self, neighbor, vlan, exabgp_log, exabgp_err):
        """Wait for BGP to come up."""
        label_values = {
            'neighbor': neighbor,
            'vlan': vlan,
        }
        for _ in range(60):
            uptime = self.scrape_prometheus_var(
                'bgp_neighbor_uptime', label_values, default=0)
            if uptime > 0:
                return
            time.sleep(1)
        exabgp_log_content = []
        for log_name in (exabgp_log, exabgp_err):
            if os.path.exists(log_name):
                with open(log_name) as log:
                    exabgp_log_content.append(log.read())
        self.fail('exabgp did not peer with FAUCET: %s' % '\n'.join(exabgp_log_content))

    @staticmethod
    def matching_lines_from_file(exp, log_name):
        exp_re = re.compile(exp)
        with open(log_name) as log_file:
            return [log_line for log_line in log_file if exp_re.match(log_line)]

    def wait_until_matching_lines_from_file(self, exp, log_name, timeout=30, count=1):
        """Require (count) matching lines to be present in file."""
        assert timeout >= 1
        lines = []
        for _ in range(timeout):
            if os.path.exists(log_name):
                lines = self.matching_lines_from_file(exp, log_name)
                if len(lines) >= count:
                    return lines
            time.sleep(1)
        self.fail('%s not found in %s (%d/%d)' % (exp, log_name, len(lines), count))

    def wait_until_no_matching_lines_from_file(self, exp, log_name, timeout=30, count=1):
        """Require (count) matching lines to be non-existent in file."""
        assert timeout >= 1
        lines = []
        for _ in range(timeout):
            if os.path.exists(log_name):
                lines = self.matching_lines_from_file(exp, log_name)
                if len(lines) >= count:
                    return self.fail('%s found in %s (%d/%d)' % (exp, log_name, len(lines), count))
            time.sleep(1)
        return lines

    def wait_until_matching_lines_from_faucet_log_files(self, exp, timeout=30, count=1):
        """Require (count) matching lines to be present in file"""
        for controller_env in self.env.values():
            if 'FAUCET_LOG' in controller_env:
                log_name = controller_env['FAUCET_LOG']
                self.wait_until_matching_lines_from_file(exp, log_name, timeout, count)

    def wait_until_matching_lines_from_gauge_log_files(self, exp, timeout=30, count=1):
        """Require (count) matching lines to be present in file"""
        for controller_env in self.env.values():
            if 'GAUGE_LOG' in controller_env:
                log_name = controller_env['GAUGE_LOG']
                self.wait_until_matching_lines_from_file(exp, log_name, timeout, count)

    def exabgp_updates(self, exabgp_log, timeout=60):
        """Verify that exabgp process has received BGP updates."""
        controller = self._get_controller()
        updates = []
        # exabgp should have received our BGP updates
        for _ in range(timeout):
            updates = controller.cmd(
                r'grep UPDATE %s |grep -Eo "\S+ next-hop \S+"' % exabgp_log)
            if updates:
                break
            time.sleep(1)
        self.assertTrue(updates, 'exabgp did not receive BGP updates')
        return updates

    def wait_exabgp_sent_updates(self, exabgp_log_name):
        """Verify that exabgp process has sent BGP updates."""
        self.wait_until_matching_lines_from_file(
            r'.+>> [1-9]+[0-9]* UPDATE.+', exabgp_log_name, timeout=60)

    def start_wpasupplicant(self, host, wpasupplicant_conf, timeout=10, log_prefix='',
                            wpa_ctrl_socket_path=''):
        """Start wpasupplicant process on Mininet host."""
        wpasupplicant_conf_file_name = os.path.join(
            self.tmpdir, '%swpasupplicant.conf' % log_prefix)
        wpasupplicant_log = os.path.join(
            self.tmpdir, '%swpasupplicant.log' % log_prefix)
        with open(wpasupplicant_conf_file_name, 'w') as wpasupplicant_conf_file:
            wpasupplicant_conf_file.write(wpasupplicant_conf)
        wpa_ctrl_socket = ''
        if wpa_ctrl_socket_path:
            wpa_ctrl_socket = '-C %s' % wpa_ctrl_socket_path
        wpasupplicant_cmd = mininet_test_util.timeout_cmd(
            'wpa_supplicant -dd -t -c %s -i %s -D wired -f %s %s &' % (
                wpasupplicant_conf_file_name, host.defaultIntf(), wpasupplicant_log,
                wpa_ctrl_socket), 300)
        host.cmd(wpasupplicant_cmd)
        for _ in range(timeout):
            if os.path.exists(wpasupplicant_log):
                break
            time.sleep(1)
        self.assertTrue(
            os.path.exists(wpasupplicant_log),
            msg='wpasupplicant (%s) did not start' % wpasupplicant_cmd)
        return wpasupplicant_log

    def ping_all_when_learned(self, retries=3, hard_timeout=1):
        """Verify all hosts can ping each other once FAUCET has learned them all."""
        # Cause hosts to send traffic that FAUCET can use to learn them.
        for _ in range(retries):
            loss = self.pingAll()
            # we should have learned all hosts now, so should have no loss.
            for host in self.hosts_name_ordered():
                self.require_host_learned(host, hard_timeout=hard_timeout)
            if loss == 0:
                return
        self.assertEqual(0, loss)

    def match_table(self, prefix):
        exp_prefix = '%s/%s' % (
            prefix.network_address, prefix.netmask)
        if prefix.version == 6:
            nw_dst_match = {'ipv6_dst': exp_prefix, 'dl_type': IPV6_ETH}
            table_id = self._IPV6_FIB_TABLE
        else:
            nw_dst_match = {'nw_dst': exp_prefix, 'dl_type': IPV4_ETH}
            table_id = self._IPV4_FIB_TABLE
        return (nw_dst_match, table_id)

    def wait_for_route_as_flow(self, nexthop, prefix,
                               vlan_vid=None, timeout=30,
                               nonzero_packets=False):
        """Verify a route has been added as a flow."""
        nw_dst_match, table_id = self.match_table(prefix)
        nexthop_action = 'SET_FIELD: {eth_dst:%s}' % nexthop
        if vlan_vid is not None:
            nw_dst_match['dl_vlan'] = str(vlan_vid)
        if nonzero_packets:
            self.wait_nonzero_packet_count_flow(
                nw_dst_match, table_id, timeout=timeout,
                actions=[nexthop_action], ofa_match=False)
        else:
            self.wait_until_matching_flow(
                nw_dst_match, table_id, timeout=timeout,
                actions=[nexthop_action], ofa_match=False)

    def host_ipv4_alias(self, host, alias_ip, intf=None):
        """Add an IPv4 alias address to a host."""
        if intf is None:
            intf = host.intf()
        del_cmd = 'ip addr del %s dev %s' % (
            alias_ip.with_prefixlen, intf)
        add_cmd = 'ip addr add %s dev %s label %s:1' % (
            alias_ip.with_prefixlen, intf, intf)
        host.cmd(del_cmd)
        self.quiet_commands(host, (add_cmd,))

    @staticmethod
    def _ip_neigh(host, ipa, ip_ver):
        neighbors = host.cmd('ip -%u neighbor show %s' % (ip_ver, ipa))
        neighbors_fields = neighbors.split()
        if len(neighbors_fields) >= 5:
            return neighbors.split()[4]
        return None

    def _verify_host_learned_mac(self, host, ipa, ip_ver, mac, retries):
        for _ in range(retries):
            if self._ip_neigh(host, ipa, ip_ver) == mac:
                return
            time.sleep(1)
        self.fail(
            'could not verify %s resolved to %s' % (ipa, mac))

    def verify_ipv4_host_learned_mac(self, host, ipa, mac, retries=3):
        self._verify_host_learned_mac(host, ipa, 4, mac, retries)

    def verify_ipv4_host_learned_host(self, host, learned_host):
        learned_ip = ipaddress.ip_interface(self.host_ipv4(learned_host))
        self.verify_ipv4_host_learned_mac(host, learned_ip.ip, learned_host.MAC())

    def verify_ipv6_host_learned_mac(self, host, ip6, mac, retries=3):
        self._verify_host_learned_mac(host, ip6, 6, mac, retries)

    def verify_ipv6_host_learned_host(self, host, learned_host):
        learned_ip6 = ipaddress.ip_interface(self.host_ipv6(learned_host))
        self.verify_ipv6_host_learned_mac(host, learned_ip6.ip, learned_host.MAC())

    def iperf_client(self, client_host, iperf_client_cmd):
        iperf_results = client_host.cmd(iperf_client_cmd)
        iperf_csv = iperf_results.strip().split(',')
        if len(iperf_csv) == 9:
            return int(iperf_csv[-1]) / self.ONEMBPS
        return -1

    def iperf(self, client_host, client_ip, server_host, server_ip, seconds):

        def run_iperf(iperf_server_cmd, server_host, server_start_exp, port):
            server_out = server_host.popen(
                iperf_server_cmd,
                stdin=mininet_test_util.DEVNULL,
                stderr=subprocess.STDOUT,
                close_fds=True)
            popens = {server_host: server_out}
            for host, line in pmonitor(popens):
                if host != server_host:
                    continue
                if not re.search(server_start_exp, line):
                    continue
                self.wait_for_tcp_listen(
                    server_host, port, ipv=server_ip.version)
                iperf_mbps = self.iperf_client(
                    client_host, iperf_client_cmd)
                self._signal_proc_on_port(server_host, port, 9)
                return iperf_mbps
            return None

        timeout = (seconds * 3) + 5
        for _ in range(3):
            port = mininet_test_util.find_free_port(
                self.ports_sock, self._test_name())
            iperf_base_cmd = 'iperf -f M -p %u' % port
            if server_ip.version == 6:
                iperf_base_cmd += ' -V'
            iperf_server_cmd = '%s -s -B %s' % (iperf_base_cmd, server_ip)
            iperf_server_cmd = mininet_test_util.timeout_cmd(
                iperf_server_cmd, timeout)
            server_start_exp = r'Server listening on TCP port %u' % port
            iperf_client_cmd = mininet_test_util.timeout_cmd(
                '%s -y c -c %s -B %s -t %u' % (iperf_base_cmd, server_ip, client_ip, seconds),
                timeout)
            iperf_mbps = run_iperf(iperf_server_cmd, server_host, server_start_exp, port)
            if iperf_mbps is not None and iperf_mbps > 0:
                return iperf_mbps
            time.sleep(1)
        if iperf_mbps == -1:
            self.fail('iperf client %s did not connect to server %s' % (
                iperf_client_cmd, iperf_server_cmd))
        self.fail('iperf server %s never started' % iperf_server_cmd)

    def verify_ipv4_routing(self, first_host, first_host_routed_ip,
                            second_host, second_host_routed_ip):
        """Verify one host can IPV4 route to another via FAUCET."""
        self.host_ipv4_alias(first_host, first_host_routed_ip)
        self.host_ipv4_alias(second_host, second_host_routed_ip)
        self.add_host_route(
            first_host, second_host_routed_ip, self.FAUCET_VIPV4.ip)
        self.add_host_route(
            second_host, first_host_routed_ip, self.FAUCET_VIPV4.ip)
        self.net.ping(hosts=(first_host, second_host))
        self.wait_for_route_as_flow(
            first_host.MAC(), first_host_routed_ip.network)
        self.wait_for_route_as_flow(
            second_host.MAC(), second_host_routed_ip.network)
        self.one_ipv4_ping(first_host, second_host_routed_ip.ip)
        self.one_ipv4_ping(second_host, first_host_routed_ip.ip)
        self.verify_ipv4_host_learned_host(first_host, second_host)
        self.verify_ipv4_host_learned_host(second_host, first_host)
        # verify at least 1M iperf
        for client_host, client_ip, server_host, server_ip in (
                (first_host, first_host_routed_ip.ip,
                 second_host, second_host_routed_ip.ip),
                (second_host, second_host_routed_ip.ip,
                 first_host, first_host_routed_ip.ip)):
            iperf_mbps = self.iperf(
                client_host, client_ip, server_host, server_ip, 5)
            error('%s: %u mbps to %s\n' % (self._test_name(), iperf_mbps, server_ip))
            self.assertGreater(iperf_mbps, 1)
        # verify packets matched routing flows
        self.wait_for_route_as_flow(
            first_host.MAC(), first_host_routed_ip.network,
            nonzero_packets=True)
        self.wait_for_route_as_flow(
            second_host.MAC(), second_host_routed_ip.network,
            nonzero_packets=True)

    def verify_ipv4_routing_mesh(self):
        """Verify hosts can route to each other via FAUCET."""
        host_pair = self.hosts_name_ordered()[:2]
        first_host, second_host = host_pair
        first_host_routed_ip = ipaddress.ip_interface('10.0.1.1/24')
        second_host_routed_ip = ipaddress.ip_interface('10.0.2.1/24')
        second_host_routed_ip2 = ipaddress.ip_interface('10.0.3.1/24')
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip2)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip2)

    @staticmethod
    def host_drop_all_ips(host):
        for ipv in (4, 6):
            host.cmd('ip -%u addr flush dev %s' % (ipv, host.defaultIntf()))

    def setup_ipv6_hosts_addresses(self, first_host, first_host_ip,
                                   first_host_routed_ip, second_host,
                                   second_host_ip, second_host_routed_ip):
        """Configure host IPv6 addresses for testing."""
        for host in first_host, second_host:
            for intf in ('lo', host.intf()):
                host.cmd('ip -6 addr flush dev %s' % intf)
        self.add_host_ipv6_address(first_host, first_host_ip)
        self.add_host_ipv6_address(second_host, second_host_ip)
        self.add_host_ipv6_address(first_host, first_host_routed_ip, intf='lo')
        self.add_host_ipv6_address(second_host, second_host_routed_ip, intf='lo')
        for host in first_host, second_host:
            self.require_host_learned(host)

    def verify_ipv6_routing(self, first_host, first_host_ip,
                            first_host_routed_ip, second_host,
                            second_host_ip, second_host_routed_ip):
        """Verify one host can IPV6 route to another via FAUCET."""
        self.one_ipv6_ping(first_host, second_host_ip.ip)
        self.one_ipv6_ping(second_host, first_host_ip.ip)
        self.add_host_route(
            first_host, second_host_routed_ip, self.FAUCET_VIPV6.ip)
        self.add_host_route(
            second_host, first_host_routed_ip, self.FAUCET_VIPV6.ip)
        self.wait_for_route_as_flow(
            first_host.MAC(), first_host_routed_ip.network)
        self.wait_for_route_as_flow(
            second_host.MAC(), second_host_routed_ip.network)
        self.one_ipv6_controller_ping(first_host)
        self.one_ipv6_controller_ping(second_host)
        self.one_ipv6_ping(first_host, second_host_routed_ip.ip)
        # verify at least 1M iperf
        for client_host, client_ip, server_host, server_ip in (
                (first_host, first_host_routed_ip.ip,
                 second_host, second_host_routed_ip.ip),
                (second_host, second_host_routed_ip.ip,
                 first_host, first_host_routed_ip.ip)):
            iperf_mbps = self.iperf(
                client_host, client_ip, server_host, server_ip, 5)
            error('%s: %u mbps to %s\n' % (self._test_name(), iperf_mbps, server_ip))
            self.assertGreater(iperf_mbps, 1)
        self.one_ipv6_ping(first_host, second_host_ip.ip)
        self.verify_ipv6_host_learned_mac(
            first_host, second_host_ip.ip, second_host.MAC())
        self.one_ipv6_ping(second_host, first_host_ip.ip)
        self.verify_ipv6_host_learned_mac(
            second_host, first_host_ip.ip, first_host.MAC())

    def verify_ipv6_routing_pair(self, first_host, first_host_ip,
                                 first_host_routed_ip, second_host,
                                 second_host_ip, second_host_routed_ip):
        """Verify hosts can route IPv6 to each other via FAUCET."""
        self.setup_ipv6_hosts_addresses(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)

    def verify_ipv6_routing_mesh(self):
        """Verify IPv6 routing between hosts and multiple subnets."""
        host_pair = self.hosts_name_ordered()[:2]
        first_host, second_host = host_pair
        first_host_ip = ipaddress.ip_interface('fc00::1:1/112')
        second_host_ip = ipaddress.ip_interface('fc00::1:2/112')
        first_host_routed_ip = ipaddress.ip_interface('fc00::10:1/112')
        second_host_routed_ip = ipaddress.ip_interface('fc00::20:1/112')
        second_host_routed_ip2 = ipaddress.ip_interface('fc00::30:1/112')
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2)

    def verify_invalid_bgp_route(self, pattern):
        """Check if we see the pattern in Faucet's log."""
        for cont_env in self.env.values():
            if 'FAUCET_LOG' in cont_env:
                lines = self.matching_lines_from_file(
                    pattern, cont_env['FAUCET_LOG'])
                self.assertGreater(len(lines), 0, msg='%s not found in %s' % (pattern, cont_env['FAUCET_LOG']))
