"""Unit tests for gauge"""

import json
import random
import re
import shutil
import tempfile
import threading
import time
import os
import unittest
from unittest import mock
import urllib

from http.server import HTTPServer, BaseHTTPRequestHandler

import yaml

import requests

from faucet import gauge, gauge_prom, gauge_influx, gauge_pollers, watcher
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.lib import type_desc
from ryu.lib import hub

from prometheus_client import CollectorRegistry


class QuietHandler(BaseHTTPRequestHandler):

    def log_message(self, _format, *_args):
        return


def create_mock_datapath(num_ports):
    """Mock a datapath by creating mocked datapath ports."""
    ports = {}
    for i in range(1, num_ports + 1):
        port = mock.Mock()
        port_name = mock.PropertyMock(return_value='port' + str(i))
        type(port).name = port_name
        ports[i] = port
    tables_by_id = {}
    for i in range(0, 10):
        table = mock.Mock()
        table_name = mock.PropertyMock(return_value='table' + str(i))
        type(table).name = table_name
        tables_by_id[i] = table
    datapath = mock.Mock(ports=ports, dp_id=random.randint(1, 5000), tables_by_id=tables_by_id)
    dp_name = mock.PropertyMock(return_value='datapath')
    type(datapath).name = dp_name
    return datapath

def start_server(handler):
    """ Starts a HTTPServer and runs it as a daemon thread """

    server = HTTPServer(('', 0), handler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server

def port_state_msg(datapath, port_num, reason, status=0):
    """ Create an OFPPortStatus message with random values. """

    port = parser.OFPPort(port_num,
                          '00:00:00:d0:00:0'+ str(port_num),
                          datapath.ports[port_num].name,
                          0,
                          status,
                          random.randint(1, 10000),
                          random.randint(1, 10000),
                          random.randint(1, 10000),
                          random.randint(1, 10000),
                          random.randint(1, 10000),
                          random.randint(1, 10000)
                         )

    return parser.OFPPortStatus(datapath, reason, port)

def port_stats_msg(datapath):
    """ Create an OFPPortStatsReply with random values. """

    stats = []
    sec = random.randint(1, 10000)
    nsec = random.randint(0, 10000)
    for port_num in datapath.ports:
        port_stats = parser.OFPPortStats(port_num,
                                         random.randint(1, 10000),
                                         random.randint(1, 10000),
                                         random.randint(1, 10000),
                                         random.randint(1, 10000),
                                         random.randint(0, 10000),
                                         random.randint(0, 10000),
                                         random.randint(0, 10000),
                                         random.randint(0, 10000),
                                         random.randint(0, 10000),
                                         random.randint(0, 10000),
                                         random.randint(0, 10000),
                                         random.randint(0, 10000),
                                         sec,
                                         nsec
                                        )
        stats.append(port_stats)
    return parser.OFPPortStatsReply(datapath, body=stats)

def flow_stats_msg(datapath, instructions):
    """ Create an OFPFlowStatsReply with random values. """

    matches = generate_all_matches()
    flow_stats = parser.OFPFlowStats(random.randint(0, 9),
                                     random.randint(1, 10000),
                                     random.randint(0, 10000),
                                     random.randint(1, 10000),
                                     random.randint(1, 10000),
                                     random.randint(1, 10000),
                                     0,
                                     random.randint(1, 10000),
                                     random.randint(1, 10000),
                                     random.randint(1, 10000),
                                     matches,
                                     instructions
                                    )

    return parser.OFPFlowStatsReply(datapath, body=[flow_stats])

def generate_all_matches():
    """
    Generate all OpenFlow Extensible Matches (oxm) and return
    a single OFPMatch with all of these oxms. The value for each
    oxm is the largest value possible for the data type. For
    example, the largest number for a 4 bit int is 15.
    """
    matches = dict()
    for oxm_type in ofproto.oxm_types:
        if oxm_type.type == type_desc.MacAddr:
            value = 'ff:ff:ff:ff:ff:ff'
        elif oxm_type.type == type_desc.IPv4Addr:
            value = '255.255.255.255'
        elif oxm_type.type == type_desc.IPv6Addr:
            value = 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
        elif isinstance(oxm_type.type, type_desc.IntDescr):
            value = 2**oxm_type.type.size - 1
        else:
            continue

        matches[oxm_type.name] = value

    return parser.OFPMatch(**matches)

def logger_to_ofp(port_stats):
    """ Translates between the logger stat name and the OpenFlow stat name"""

    return {'packets_out': port_stats.tx_packets,
            'packets_in': port_stats.rx_packets,
            'bytes_out' : port_stats.tx_bytes,
            'bytes_in' : port_stats.rx_bytes,
            'dropped_out' : port_stats.tx_dropped,
            'dropped_in' : port_stats.rx_dropped,
            'errors_in' : port_stats.rx_errors
           }

def get_matches(match_dict):
    """Create a set of match name and value tuples"""
    return {(entry['OXMTlv']['field'], entry['OXMTlv']['value']) for entry in match_dict}

def check_instructions(original_inst, logger_inst, test):
    """
    Check that the original instructions matches the
    instructions from the logger
    """
    for inst_type, inst in logger_inst[0].items():
        test.assertEqual(original_inst[0].__class__.__name__, inst_type)
        for attr_name, attr_val in inst.items():
            original_val = getattr(original_inst[0], attr_name)
            test.assertEqual(original_val, attr_val)

def compare_flow_msg(flow_msg, flow_dict, test):
    """
    Compare the body section of an OFPFlowStatsReply
    message to a dict representation of it
    """
    for stat_name, stat_val in flow_dict.items():
        if stat_name == 'match':
            match_set = get_matches(stat_val['OFPMatch']['oxm_fields'])
            test.assertEqual(match_set, set(flow_msg.body[0].match.items()))
        elif stat_name == 'instructions':
            check_instructions(flow_msg.body[0].instructions, stat_val, test)
        else:
            test.assertEqual(getattr(flow_msg.body[0], stat_name), stat_val)


class PretendInflux(QuietHandler):
    """An HTTP Handler that receives InfluxDB messages."""

    def do_POST(self):
        """ Write request contents to the HTTP server,
        if there is an output file to write to. """

        if hasattr(self.server, 'output_file'):
            content_length = int(self.headers['content-length'])
            data = self.rfile.read(content_length)
            data = data.decode('utf-8')
            with open(self.server.output_file, 'w') as log:
                log.write(data)

        self.send_response(204)
        self.end_headers()


class GaugePrometheusTests(unittest.TestCase):
    """Tests the GaugePortStatsPrometheusPoller update method"""

    prom_client = gauge_prom.GaugePrometheusClient(reg=CollectorRegistry())

    def parse_prom_output(self, output):
        """Parses the port stats from prometheus into a dictionary"""

        parsed_output = {}
        for line in output.split('\n'):
            # discard comments and stats not related to port stats
            if line.startswith('#') or not line.startswith(gauge_prom.PROM_PORT_PREFIX):
                continue

            index = line.find('{')
            #get the stat name e.g. of_port_rx_bytes and strip 'of_port_'
            prefix = gauge_prom.PROM_PORT_PREFIX + gauge_prom.PROM_PREFIX_DELIM
            stat_name = line[0:index].replace(prefix, '')
            #get the labels within {}
            labels = line[index + 1:line.find('}')].split(',')

            for label in labels:
                lab_name, lab_val = label.split('=')
                lab_val = lab_val.replace('"', '')
                if lab_name == 'dp_id':
                    dp_id = int(lab_val, 16)
                elif lab_name == 'port_name':
                    port_name = lab_val

            key = (dp_id, port_name)
            stat_val = line.split(' ')[1]
            if key not in parsed_output:
                parsed_output[key] = []

            parsed_output[key].append((stat_name, float(stat_val)))

        return parsed_output

    def get_prometheus_stats(self, addr, port):
        """Attempts to contact the prometheus server
        at the address to grab port stats."""

        url = 'http://{}:{}'.format(addr, port)
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=10)
        session.mount('http://', adapter)
        return session.get(url).text

    def test_poller(self):
        """Test the update method to see if it pushes port stats"""

        datapath = create_mock_datapath(2)

        conf = mock.Mock(dp=datapath,
                         type='',
                         interval=1,
                         prometheus_port=9303,
                         prometheus_addr='localhost',
                         use_test_thread=True
                        )

        prom_poller = gauge_prom.GaugePortStatsPrometheusPoller(conf, '__name__', self.prom_client)
        msg = port_stats_msg(datapath)
        prom_poller.update(time.time(), datapath.dp_id, msg)

        prom_lines = self.get_prometheus_stats(conf.prometheus_addr, conf.prometheus_port)
        prom_lines = self.parse_prom_output(prom_lines)

        for port_num, port in datapath.ports.items():
            port_stats = msg.body[int(port_num) - 1]
            stats = prom_lines[(datapath.dp_id, port.name)]
            stats_found = set()

            for stat_name, stat_val in stats:
                self.assertAlmostEqual(stat_val, getattr(port_stats, stat_name))
                stats_found.add(stat_name)

            self.assertEqual(stats_found, set(gauge_prom.PROM_PORT_VARS))

    def test_port_state(self):
        """Test the update method to see if it pushes port state"""

        datapath = create_mock_datapath(2)

        conf = mock.Mock(dp=datapath,
                         type='',
                         interval=1,
                         prometheus_port=9303,
                         prometheus_addr='localhost',
                         use_test_thread=True
                        )

        prom_poller = gauge_prom.GaugePortStatePrometheusPoller(conf, '__name__', self.prom_client)
        reasons = [ofproto.OFPPR_ADD, ofproto.OFPPR_DELETE, ofproto.OFPPR_MODIFY]
        for i in range(1, len(conf.dp.ports) + 1):

            msg = port_state_msg(conf.dp, i, reasons[i-1])
            port_name = conf.dp.ports[i].name
            rcv_time = int(time.time())
            prom_poller.update(rcv_time, conf.dp.dp_id, msg)

            prom_lines = self.get_prometheus_stats(conf.prometheus_addr, conf.prometheus_port)
            prom_lines = self.parse_prom_output(prom_lines)

            stats = prom_lines[(datapath.dp_id, port_name)]
            stats_found = set()

            for stat_name, stat_val in stats:
                msg_data = msg if stat_name == 'reason' else msg.desc
                self.assertAlmostEqual(stat_val, getattr(msg_data, stat_name))
                stats_found.add(stat_name)

            self.assertEqual(stats_found, set(gauge_prom.PROM_PORT_STATE_VARS))

    def test_flow_stats(self):
        """Check the update method of the GaugeFlowTablePrometheusPoller class"""

        datapath = create_mock_datapath(2)

        conf = mock.Mock(dp=datapath,
                         type='',
                         interval=1,
                         prometheus_port=9303,
                         prometheus_addr='localhost',
                         use_test_thread=True
                        )

        prom_poller = gauge_prom.GaugeFlowTablePrometheusPoller(conf, '__name__', self.prom_client)
        rcv_time = int(time.time())
        instructions = [parser.OFPInstructionGotoTable(1)]
        msg = flow_stats_msg(conf.dp, instructions)
        prom_poller.update(rcv_time, conf.dp.dp_id, msg)



class GaugeInfluxShipperTest(unittest.TestCase):
    """Tests the InfluxShipper"""

    def create_config_obj(self, port=12345):
        """Create a mock config object that contains the necessary InfluxDB config"""

        conf = mock.Mock(influx_host='localhost',
                         influx_port=port,
                         influx_user='gauge',
                         influx_pwd='',
                         influx_db='gauge',
                         influx_timeout=10
                        )
        return conf

    def get_values(self, dict_to_unpack):
        """Get all the values from a nested dictionary"""

        values = []
        for value in dict_to_unpack.values():
            if isinstance(value, dict):
                values.extend(self.get_values(value))
            else:
                values.append(value)
        return values

    def test_ship_success(self):
        """Checks that the shipper successsfully connects
        to a HTTP server when the points are shipped"""

        try:
            server = start_server(PretendInflux)
            shipper = gauge_influx.InfluxShipper()
            shipper.conf = self.create_config_obj(server.server_port)
            points = [{'measurement': 'test_stat_name', 'fields' : {'value':1}},]
            shipper.ship_points(points)

        except Exception as err:
            self.fail("Code threw an exception: {}".format(err))
        finally:
            server.socket.close()
            server.shutdown()

    def test_ship_connection_err(self):
        """Checks that even when there is a connection error,
        there is no exception thrown"""

        try:
            shipper = gauge_influx.InfluxShipper()
            shipper.conf = self.create_config_obj()
            shipper.logger = mock.Mock()
            points = [{'measurement': 'test_stat_name', 'fields' : {'value':1}},]
            shipper.ship_points(points)

        except Exception as err:
            self.fail("Code threw an exception: {}".format(err))

    def test_ship_no_config(self):
        """Check that no exceptions are thrown when
        there is no config"""

        try:
            shipper = gauge_influx.InfluxShipper()
            points = [{'measurement': 'test_stat_name', 'fields' : {'value':1}},]
            shipper.ship_points(points)

        except Exception as err:
            self.fail("Code threw an exception: {}".format(err))

    def test_point(self):
        """Checks that the points produced still have the variables given to it"""

        shipper = gauge_influx.InfluxShipper()
        dp_name = 'faucet-1'
        port_name = 'port1.0.1'
        rcv_time = int(time.time())
        stat_name = 'test_stat_name'
        #max uint64 number
        stat_val = 2**64 - 1

        port_point = shipper.make_port_point(dp_name, port_name, rcv_time, stat_name, stat_val)
        values = {dp_name, port_name, rcv_time, stat_name}
        port_vals = set(self.get_values(port_point))
        port_vals_stat = port_vals.difference(values)
        self.assertEqual(len(port_vals_stat), 1)
        self.assertAlmostEqual(port_vals_stat.pop(), stat_val)

        tags = {'dp_name': dp_name, 'port_name': port_name}
        point = shipper.make_point(tags, rcv_time, stat_name, stat_val)
        point_vals = set(self.get_values(point))
        point_vals_stat = point_vals.difference(values)
        self.assertEqual(len(point_vals_stat), 1)
        self.assertAlmostEqual(point_vals_stat.pop(), stat_val)


class GaugeInfluxUpdateTest(unittest.TestCase):
    """Test the Influx loggers update methods"""

    def setUp(self):
        """ Starts up an HTTP server to mock InfluxDB.
        Also opens a new temp file for the server to write to """

        self.server = start_server(PretendInflux)
        self.temp_fd, self.server.output_file = tempfile.mkstemp()

    def tearDown(self):
        """ Close the temp file (which should delete it)
        and stop the HTTP server """
        os.close(self.temp_fd)
        os.remove(self.server.output_file)
        self.server.socket.close()
        self.server.shutdown()

    def create_config_obj(self, datapath):
        """Create a mock config object that contains the necessary InfluxDB config"""

        conf = mock.Mock(influx_host='localhost',
                         influx_port=self.server.server_port,
                         influx_user='gauge',
                         influx_pwd='',
                         influx_db='gauge',
                         influx_timeout=10,
                         interval=5,
                         dp=datapath
                        )
        return conf

    @staticmethod
    def parse_key_value(dictionary, kv_list):
        """
        When given a list consisting of strings such as: 'key1=val1',
        add to the dictionary as dictionary['key1'] = 'val1'.
        Ignore entries in the list which do not contain '='
        """
        for key_val in kv_list:
            if '=' in key_val:
                key, val = key_val.split('=')

                try:
                    val = float(val)
                    val = int(val)
                except ValueError:
                    pass

                dictionary[key] = val


    def parse_influx_output(self, output_to_parse):
        """
        Parse the output from the mock InfluxDB server
        The usual layout of the output is:
        measurement,tag1=val1,tag2=val2 field1=val3 timestamp
        The tags are separated with a comma and the fields
        are separated with a space. The measurement always
        appears first, and the timestamp is always last

        """
        influx_data = dict()

        tags = output_to_parse.split(',')
        fields = tags[-1].split(' ')
        tags[-1] = fields[0]
        influx_data['timestamp'] = int(fields[-1])
        fields = fields[1:-1]

        self.parse_key_value(influx_data, tags)
        self.parse_key_value(influx_data, fields)

        return (tags[0], influx_data)


    def test_port_state(self):
        """ Check the update method of the GaugePortStateInfluxDBLogger class"""

        conf = self.create_config_obj(create_mock_datapath(3))
        db_logger = gauge_influx.GaugePortStateInfluxDBLogger(conf, '__name__', mock.Mock())

        reasons = [ofproto.OFPPR_ADD, ofproto.OFPPR_DELETE, ofproto.OFPPR_MODIFY]
        for i in range(1, len(conf.dp.ports) + 1):

            msg = port_state_msg(conf.dp, i, reasons[i-1])
            rcv_time = int(time.time())
            db_logger.update(rcv_time, conf.dp.dp_id, msg)

            with open(self.server.output_file, 'r') as log:
                output = log.read()

            influx_data = self.parse_influx_output(output)[1]
            data = {conf.dp.name, conf.dp.ports[i].name, rcv_time, reasons[i-1]}
            self.assertEqual(data, set(influx_data.values()))

    def test_port_stats(self):
        """Check the update method of the GaugePortStatsInfluxDBLogger class"""
        conf = self.create_config_obj(create_mock_datapath(2))
        db_logger = gauge_influx.GaugePortStatsInfluxDBLogger(conf, '__name__', mock.Mock())

        msg = port_stats_msg(conf.dp)
        rcv_time = int(time.time())

        db_logger.update(rcv_time, conf.dp.dp_id, msg)
        with open(self.server.output_file, 'r') as log:
            output = log.readlines()

        for line in output:
            measurement, influx_data = self.parse_influx_output(line)

            #get the number at the end of the port_name
            port_num = int(influx_data['port_name'][-1])
            #get the original port stat value
            port_stat_val = logger_to_ofp(msg.body[port_num - 1])[measurement]

            self.assertEqual(port_stat_val, influx_data['value'])
            self.assertEqual(conf.dp.name, influx_data['dp_name'])
            self.assertEqual(rcv_time, influx_data['timestamp'])

    def test_flow_stats(self):
        """Check the update method of the GaugeFlowTableInfluxDBLogger class"""

        conf = self.create_config_obj(create_mock_datapath(0))
        db_logger = gauge_influx.GaugeFlowTableInfluxDBLogger(conf, '__name__', mock.Mock())

        rcv_time = int(time.time())
        instructions = [parser.OFPInstructionGotoTable(1)]
        msg = flow_stats_msg(conf.dp, instructions)
        db_logger.update(rcv_time, conf.dp.dp_id, msg)

        other_fields = {'dp_name': conf.dp.name,
                        'dp_id': hex(conf.dp.dp_id),
                        'timestamp': rcv_time,
                        'priority': msg.body[0].priority,
                        'table_id': msg.body[0].table_id,
                        'inst_count': len(msg.body[0].instructions),
                        'vlan': msg.body[0].match.get('vlan_vid') ^ ofproto.OFPVID_PRESENT,
                        'cookie': msg.body[0].cookie,
                       }

        with open(self.server.output_file, 'r') as log:
            output = log.readlines()

        for line in output:
            measurement, influx_data = self.parse_influx_output(line)

            for stat_name, stat_val in influx_data.items():
                if stat_name == 'value':
                    if measurement == 'flow_packet_count':
                        self.assertEqual(msg.body[0].packet_count, stat_val)
                    elif measurement == 'flow_byte_count':
                        self.assertEqual(msg.body[0].byte_count, stat_val)
                    else:
                        self.fail("Unknown measurement")

                elif stat_name in other_fields:
                    self.assertEqual(other_fields[stat_name], stat_val)

                elif stat_name in  msg.body[0].match:
                    self.assertEqual(msg.body[0].match.get(stat_name), stat_val)

                else:
                    self.fail("Unknown key: {} and value: {}".format(stat_name, stat_val))

class GaugeThreadPollerTest(unittest.TestCase):
    """Tests the methods in the GaugeThreadPoller class"""

    def setUp(self):
        """Creates a gauge poller and initialises class variables"""
        self.interval = 1
        conf = mock.Mock(interval=self.interval)
        self.poller = gauge_pollers.GaugeThreadPoller(conf, '__name__', mock.Mock())
        self.send_called = False

    def fake_send_req(self):
        """This should be called instead of the send_req method in the
        GaugeThreadPoller class, which just throws an error"""
        self.send_called = True

    def fake_no_response(self):
        """This should be called instead of the no_response method in the
        GaugeThreadPoller class, which just throws an error"""
        pass

    def test_start(self):
        """ Checks if the poller is started """
        self.poller.send_req = self.fake_send_req
        self.poller.no_response = self.fake_no_response

        self.poller.start(mock.Mock(), active=True)
        poller_thread = self.poller.thread
        hub.sleep(self.interval + 1)
        self.assertTrue(self.send_called)
        self.assertFalse(poller_thread.dead)

    def test_stop(self):
        """ Check if a poller can be stopped """
        self.poller.send_req = self.fake_send_req
        self.poller.no_response = self.fake_no_response

        self.poller.start(mock.Mock(), active=True)
        poller_thread = self.poller.thread
        self.poller.stop()
        hub.sleep(self.interval + 1)

        self.assertFalse(self.send_called)
        self.assertTrue(poller_thread.dead)

    def test_active(self):
        """Check if active reflects the state of the poller """
        self.assertFalse(self.poller.is_active())
        self.assertFalse(self.poller.running())
        self.poller.start(mock.Mock(), active=True)
        self.assertTrue(self.poller.is_active())
        self.assertTrue(self.poller.running())
        self.poller.stop()
        self.assertFalse(self.poller.is_active())
        self.assertFalse(self.poller.running())
        self.poller.start(mock.Mock(), active=False)
        self.assertFalse(self.poller.is_active())
        self.assertTrue(self.poller.running())
        self.poller.stop()
        self.assertFalse(self.poller.is_active())
        self.assertFalse(self.poller.running())

class GaugePollerTest(unittest.TestCase):
    """Checks the send_req and no_response methods in a Gauge Poller"""

    def check_send_req(self, poller, msg_class):
        """Check that the message being sent matches the expected one"""
        datapath = mock.Mock(ofproto=ofproto, ofproto_parser=parser)
        poller.start(datapath, active=True)
        poller.stop()
        poller.send_req()
        for method_call in datapath.mock_calls:
            arg = method_call[1][0]
            self.assertTrue(isinstance(arg, msg_class))

    def check_no_response(self, poller):
        """Check that no exception occurs when the no_response method is called"""
        try:
            poller.no_response()
        except Exception as err:
            self.fail("Code threw an exception: {}".format(err))

class GaugePortStatsPollerTest(GaugePollerTest):
    """Checks the GaugePortStatsPoller class"""

    def test_send_req(self):
        """Check that the poller sends a port stats request"""
        conf = mock.Mock(interval=1)
        poller = gauge_pollers.GaugePortStatsPoller(conf, '__name__', mock.Mock())
        self.check_send_req(poller, parser.OFPPortStatsRequest)

    def test_no_response(self):
        """Check that the poller doesnt throw an exception"""
        poller = gauge_pollers.GaugePortStatsPoller(mock.Mock(), '__name__', mock.Mock())
        self.check_no_response(poller)

class GaugeFlowTablePollerTest(GaugePollerTest):
    """Checks the GaugeFlowTablePoller class"""

    def test_send_req(self):
        """Check that the poller sends a flow stats request"""
        conf = mock.Mock(interval=1)
        poller = gauge_pollers.GaugeFlowTablePoller(conf, '__name__', mock.Mock())
        self.check_send_req(poller, parser.OFPFlowStatsRequest)


    def test_no_response(self):
        """Check that the poller doesnt throw an exception"""
        poller = gauge_pollers.GaugeFlowTablePoller(mock.Mock(), '__name__', mock.Mock())
        self.check_no_response(poller)

class GaugeWatcherTest(unittest.TestCase):
    """ Checks the loggers in watcher.py"""

    def setUp(self):
        """Creates a temporary file and a mocked conf object"""
        self.temp_fd, self.temp_path = tempfile.mkstemp()
        self.conf = mock.Mock(file=self.temp_path, compress=False)

    def tearDown(self):
        """Closes and deletes the temporary file"""
        os.close(self.temp_fd)
        os.remove(self.temp_path)

    def get_file_contents(self):
        """Return the contents of the temporary file and clear it"""
        with open(self.temp_path, 'r+') as file_:
            contents = file_.read()
            file_.seek(0, 0)
            file_.truncate()

        return contents

    def test_port_state(self):
        """Check the update method in the GaugePortStateLogger class"""

        logger = watcher.GaugePortStateLogger(self.conf, '__name__', mock.Mock())
        reasons = {'unknown' : 5,
                   'add' : ofproto.OFPPR_ADD,
                   'delete' : ofproto.OFPPR_DELETE,
                   'up' : ofproto.OFPPR_MODIFY,
                   'down' : ofproto.OFPPR_MODIFY
                  }

        #add an ofproto attribute to the datapath
        datapath = create_mock_datapath(1)
        ofp_attr = {'ofproto': ofproto}
        datapath.configure_mock(**ofp_attr)

        for reason in reasons:
            state = 0
            if reason == 'down':
                state = ofproto.OFPPS_LINK_DOWN

            msg = port_state_msg(datapath, 1, reasons[reason], state)
            logger.update(time.time(), datapath.dp_id, msg)

            log_str = self.get_file_contents().lower()
            self.assertTrue(reason in log_str)
            self.assertTrue(msg.desc.name in log_str or 'port ' + str(msg.desc.port_no) in log_str)

            hexs = re.findall(r'0x[0-9A-Fa-f]+', log_str)
            hexs = [int(num, 16) for num in hexs]
            self.assertTrue(datapath.dp_id in hexs or str(datapath.dp_id) in log_str)

    def test_port_stats(self):
        """Check the update method in the GaugePortStatsLogger class"""

        #add an ofproto attribute to the datapath
        datapath = create_mock_datapath(2)
        ofp_attr = {'ofproto': ofproto}
        datapath.configure_mock(**ofp_attr)

        #add the datapath as an attribute to the config
        dp_attr = {'dp' : datapath}
        self.conf.configure_mock(**dp_attr)

        logger = watcher.GaugePortStatsLogger(self.conf, '__name__', mock.Mock())
        msg = port_stats_msg(datapath)

        original_stats = []
        for i in range(0, len(msg.body)):
            original_stats.append(logger_to_ofp(msg.body[i]))

        logger.update(time.time(), datapath.dp_id, msg)

        log_str = self.get_file_contents()
        for stat_name in original_stats[0]:
            stat_name = stat_name.split("_")
            #grab any lines that mention the stat_name
            pattern = r'^.*{}.{}.*$'.format(stat_name[0], stat_name[1])
            stats_list = re.findall(pattern, log_str, re.MULTILINE)

            for line in stats_list:
                self.assertTrue(datapath.name in line)
                #grab the port number (only works for single digit port nums)
                index = line.find('port')
                port_num = int(line[index + 4])

                #grab the number at the end of the line
                val = int(re.search(r'(\d+)$', line).group())
                logger_stat_name = '_'.join((stat_name[0], stat_name[1]))
                original_val = original_stats[port_num - 1][logger_stat_name]
                self.assertEqual(original_val, val)

    def test_flow_stats(self):
        """Check the update method in the GaugeFlowStatsLogger class"""

        #add an ofproto attribute to the datapath
        datapath = create_mock_datapath(0)
        ofp_attr = {'ofproto': ofproto}
        datapath.configure_mock(**ofp_attr)

        #add the datapath as an attribute to the config
        dp_attr = {'dp' : datapath}
        self.conf.configure_mock(**dp_attr)

        logger = watcher.GaugeFlowTableLogger(self.conf, '__name__', mock.Mock())
        instructions = [parser.OFPInstructionGotoTable(1)]

        msg = flow_stats_msg(datapath, instructions)
        logger.update(time.time(), datapath.dp_id, msg)
        log_str = self.get_file_contents()

        yaml_dict = yaml.load(log_str)['msg']['OFPFlowStatsReply']['body'][0]['OFPFlowStats']

        compare_flow_msg(msg, yaml_dict, self)


class RyuAppSmokeTest(unittest.TestCase):

    def setUp(self):
        os.environ['GAUGE_LOG'] = '/dev/null'
        os.environ['GAUGE_EXCEPTION_LOG'] = '/dev/null'

    def test_gauge(self):
        """Test Gauge can be initialized."""
        os.environ['GAUGE_CONFIG'] = '/dev/null'
        ryu_app = gauge.Gauge(
            dpset={},
            reg=CollectorRegistry())
        ryu_app.reload_config(None)

    def test_gauge_config(self):
        tmpdir = tempfile.mkdtemp()
        os.environ['FAUCET_CONFIG'] = os.path.join(tmpdir, 'faucet.yaml')
        os.environ['GAUGE_CONFIG'] = os.path.join(tmpdir, 'gauge.yaml')
        with open(os.environ['FAUCET_CONFIG'], 'w') as faucet_config:
            faucet_config.write(
"""
vlans:
   100:
       description: "100"
dps:
   dp1:
       dp_id: 0x1
       interfaces:
           1:
               description: "1"
               native_vlan: 100
""")
        os.environ['GAUGE_CONFIG'] = os.path.join(tmpdir, 'gauge.yaml')
        with open(os.environ['GAUGE_CONFIG'], 'w') as gauge_config:
            gauge_config.write(
"""
faucet_configs:
   - '%s'
watchers:
    port_status_poller:
        type: 'port_state'
        all_dps: True
        db: 'prometheus'
    port_stats_poller:
        type: 'port_stats'
        all_dps: True
        interval: 10
        db: 'prometheus'
    flow_table_poller:
        type: 'flow_table'
        all_dps: True
        interval: 60
        db: 'prometheus'
dbs:
    prometheus:
        type: 'prometheus'
        prometheus_addr: '0.0.0.0'
        prometheus_port: 0
""" % os.environ['FAUCET_CONFIG'])
        ryu_app = gauge.Gauge(
            dpset={},
            reg=CollectorRegistry())
        ryu_app.reload_config(None)
        self.assertTrue(ryu_app.watchers)
        ryu_app.reload_config(None)
        self.assertTrue(ryu_app.watchers)
        shutil.rmtree(tmpdir)


if __name__ == "__main__":
    unittest.main()
