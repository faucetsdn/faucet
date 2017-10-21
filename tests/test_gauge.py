"""Unit tests for gauge"""

try:
    # Python 2
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
    import mock
except ImportError:
    # Python 3
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from unittest import mock
import unittest
import time
import threading
import tempfile
import os
import re
import json
import random
import urllib
import requests
import couchdb

from faucet import gauge_prom, gauge_influx, gauge_pollers, watcher, nsodbc, gauge_nsodbc
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.lib import type_desc
from ryu.lib import hub


def create_mock_datapath(num_ports):
    """Mock a datapath by creating mocked datapath ports."""
    ports = {}
    for i in range(1, num_ports + 1):
        port = mock.Mock()
        port_name = mock.PropertyMock(return_value='port' + str(i))
        type(port).name = port_name
        ports[i] = port

    datapath = mock.Mock(ports=ports, dp_id=random.randint(1, 5000))
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

class PretendInflux(BaseHTTPRequestHandler):
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

    def log_message(self, format_, *args):
        """ Silence the handler """
        return

class PretendCouchDB(BaseHTTPRequestHandler):
    """An HTTP Handler that receives CouchDB messages"""

    def _set_up_response(self, code, body):
        """
        Set up response message.
        The code is the HTTP response code.
        The body should be a dict which will be turned into json_dict
        """
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        encoded = json.dumps(body).encode('utf-8')
        self.send_header('content-length', len(encoded))
        self.end_headers()
        self.wfile.write(encoded)

    def _read_req_body(self):
        """Decode the request message body into a dict."""
        content_length = int(self.headers['content-length'])
        data = self.rfile.read(content_length)
        return json.loads(data.decode('utf-8'))

    def _get_rand_id(self, db_name):
        """Generate a random _id for a doc"""
        num = random.randint(0, 100000)
        return '/'.join((db_name, str(num)))

    def _convert_to_get(self, func):
        """
        Convert the javascript attribute accesses to get().
        For example the following: 'doc._id, doc.key1'
        This would be converted to 'doc.get("_id"), doc.get("key1")'
        """
        variables = func.split(',')

        for i in range(0, len(variables)):
            #separate each attribute access
            attributes = variables[i].split('.')

            for j in range(1, len(attributes)):
                #only grab the attribute name
                attr = re.search(r'[0-9A-Za-z_]+', attributes[j]).group()
                new_attr = 'get("' + attr + '")'
                #find the original place of the attribute
                index = attributes[j].find(attr)
                #replace the attribute with the new one
                attributes[j] = new_attr + attributes[j][index + len(attr):]

            variables[i] = '.'.join(attributes)
        return '(doc.get("_id"),' + ','.join(variables) + ')'

    def _run_func_on_docs(self, func):
        """
        Run the emit function on the non-view docs. This
        should produce a tuple consisting of the doc id,
        the key for the view, and the value for the view.
        """
        results = []
        for name, doc in self.server.docs.items():
            if '_design' in name:
                continue
            results.append(eval(func))
        return results

    def _run_view(self, js_str, key):
        """
        Extract the emit function(s) from the Javascript function
        in the view string. Only send rows where the key matches
        the provided key.
        """
        results = []
        emit_funcs = re.findall(r'emit\((.*)\)', js_str)
        for func in emit_funcs:
            converted_func = self._convert_to_get(func)
            results += self._run_func_on_docs(converted_func)

        rows = []
        for row_id, row_key, row_val in results:
            if row_key != key:
                continue
            row = {'id': row_id, 'key': row_key, 'value': row_val}
            rows.append(row)

        resp = {'total_rows' : len(rows), 'offset': 0, 'rows': rows}
        self._set_up_response(200, resp)


    def _handle_view(self, path):
        """
        Run the specified view on the docs. Only return rows that
        match the key provided in the path.
        """
        path = urllib.parse.unquote(path)
        path = path.split('/')
        view_query = path[-1].split('?')
        doc_name = '/'.join(path[:3])
        view = self.server.docs[doc_name]['views'][view_query[0]]
        key = re.search(r'key="(.*)"', view_query[1]).group(1)

        self._run_view(view['map'], key)

    def _handle_doc_mod(self, doc_name):
        """ Modify an existing doc or create a new doc """
        doc_data = self._read_req_body()
        if doc_name in self.server.docs:
            if '_rev' not in doc_data:
                error = {'error':'id_conflict', 'reason': 'id conflict'}
                self._set_up_response(409, error)
                return

            doc_data['_rev'] = int(doc_data['_rev']) + 1
        else:
            doc_data['_rev'] = 1

        self.server.docs[doc_name] = doc_data
        resp = {'id' : doc_data['_id'], 'rev': doc_data['_rev']}
        self._set_up_response(201, resp)

    def _handle_doc_delete(self, doc_name):
        """ Remove a specified doc """
        doc_name = doc_name.split('?')[0]
        doc_data = self.server.docs[doc_name]
        del self.server.docs[doc_name]
        resp = {'ok': True, 'id': doc_data['_id'], 'rev':int(doc_data['_rev'])+1}
        self._set_up_response(200, resp)

    def do_GET(self):
        """ Returns a doc or a view if it is contained in the server """
        doc = self.path.strip('/')
        if '_design' in doc:
            self._handle_view(doc)
            return

        if doc in self.server.docs:
            self._set_up_response(200, self.server.docs[doc])
        else:
            self._set_up_response(404, {'error': 'err', 'reason': 'reason'})

    def do_PUT(self):
        """ Create a new database or modify a doc """
        db_name = self.path.strip('/')
        index = db_name.find('/')
        if index > -1:
            self._handle_doc_mod(db_name)
            return

        if db_name in self.server.db:
            error = {'error':'file_exists', 'reason': 'cant be created'}
            self._set_up_response(412, error)

        else:
            self.server.db.add(db_name)
            resp = {'ok' : True}
            self._set_up_response(201, resp)

    def do_POST(self):
        """ Add a new doc with a randomly generated id"""
        db_name = self.path.strip('/')
        doc_name = self._get_rand_id(db_name)
        while doc_name in self.server.docs:
            doc_name = self._get_rand_id(db_name)

        doc_id = doc_name.split('/')[1]
        doc_data = self._read_req_body()
        doc_data['_id'] = doc_id
        doc_data['_rev'] = 1

        self.server.docs[doc_name] = doc_data
        resp = {'ok' : True, 'id': doc_id, 'rev': 1}
        self._set_up_response(201, resp)

    def do_HEAD(self):
        """ Check if a database has been created """
        db_name = self.path.strip('/')
        if db_name in self.server.db:
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()

    def do_DELETE(self):
        """ Delete a doc or database """
        db_name = self.path.strip('/')
        index = db_name.find('/')
        if index > -1:
            self._handle_doc_delete(db_name)
            return

        if db_name in self.server.db:
            self.server.db.remove(db_name)
            for doc_name in list(self.server.docs.keys()):
                if doc_name.startswith(db_name):
                    del self.server.docs[doc_name]
            self.send_response(200)
            self.end_headers()
            return

        error = {'error':'not_found', 'reason': 'Database does not exist.'}
        self._set_up_response(404, error)

class GaugePrometheusTests(unittest.TestCase):
    """Tests the GaugePortStatsPrometheusPoller update method"""

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

        prom_client = gauge_prom.GaugePrometheusClient()
        datapath = create_mock_datapath(2)

        conf = mock.Mock(dp=datapath,
                         type='',
                         interval=1,
                         prometheus_port=9303,
                         prometheus_addr='localhost'
                        )

        prom_poller = gauge_prom.GaugePortStatsPrometheusPoller(conf, '__name__', prom_client)
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
        dp_name = 'windscale-faucet-1'
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

    def parse_key_value(self, dictionary, kv_list):
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
                        'timestamp': rcv_time,
                        'priority': msg.body[0].priority,
                        'table_id': msg.body[0].table_id,
                        'inst_count': len(msg.body[0].instructions),
                        'vlan': msg.body[0].match.get('vlan_vid') ^ ofproto.OFPVID_PRESENT
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

        self.poller.start(mock.Mock())
        poller_thread = self.poller.thread
        hub.sleep(self.interval + 1)
        self.assertTrue(self.send_called)
        self.assertFalse(poller_thread.dead)

    def test_stop(self):
        """ Check if a poller can be stopped """
        self.poller.send_req = self.fake_send_req
        self.poller.no_response = self.fake_no_response

        self.poller.start(mock.Mock())
        poller_thread = self.poller.thread
        self.poller.stop()
        hub.sleep(self.interval + 1)

        self.assertFalse(self.send_called)
        self.assertTrue(poller_thread.dead)

    def test_running(self):
        """ Check if running reflects the state of the poller """
        self.assertFalse(self.poller.running())
        self.poller.start(mock.Mock())
        self.assertTrue(self.poller.running())
        self.poller.stop()
        self.assertFalse(self.poller.running())

class GaugePollerTest(unittest.TestCase):
    """Checks the send_req and no_response methods in a Gauge Poller"""

    def check_send_req(self, poller, msg_class):
        """Check that the message being sent matches the expected one"""
        datapath = mock.Mock(ofproto=ofproto, ofproto_parser=parser)
        poller.start(datapath)
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
        self.conf = mock.Mock(file=self.temp_path)

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

        #only parse the message part of the log text
        str_to_find = "msg: "
        index = log_str.find(str_to_find)
        #discard the start of the log text
        log_str = log_str[index + len(str_to_find):]
        json_dict = json.loads(log_str)['OFPFlowStatsReply']['body'][0]['OFPFlowStats']

        compare_flow_msg(msg, json_dict, self)

class GaugeConnectionCouchTest(unittest.TestCase):
    """ Check the ConnectionCouch class from nsodbc"""

    def setUp(self):
        """ Start up the pretend server and create a connection object"""
        self.server = start_server(PretendCouchDB)
        self.server.db = set()
        self.server.docs = dict()
        url = 'http://127.0.0.1:{}/'.format(self.server.server_port)
        credentials = ('couch', '123')
        self.conn = nsodbc.ConnectionCouch(couchdb.Server(url), credentials)

    def tearDown(self):
        """ Shutdown the pretend server """
        self.server.shutdown()

    def test_create(self):
        """Check that a database can be created"""
        _, exists = self.conn.create('test_db')
        self.assertFalse(exists)
        self.assertTrue('test_db' in self.server.db)

    def test_no_create(self):
        """Check that a new database with the same name as another cant be created."""
        self.server.db.add('test_db')
        _, exists = self.conn.create('test_db')
        self.assertTrue(exists)
        self.assertEqual(1, len(self.server.db))

    def test_database(self):
        """
        Check that the number of connected databases doesn't increase
        until the create command is issued.
        """
        self.server.db.add('test_db')
        self.assertEqual(0, len(self.conn.connected_databases()))
        self.conn.create('test_db')
        self.assertEqual(1, len(self.conn.connected_databases()))

    def test_delete(self):
        """Check that we can delete an existing database"""
        self.conn.create('test_db')
        self.assertTrue('test_db' in self.server.db)
        self.conn.delete('test_db')
        self.assertFalse('test_db' in self.server.db)

    def test_no_delete(self):
        """Check that a database that doesn't exist, doesn't get deleted."""
        try:
            self.conn.delete('hello')
            self.fail('Database should not exist, should have thrown exception')
        except couchdb.http.ResourceNotFound:
            pass

class GaugeDatabaseCouchTest(unittest.TestCase):
    """ Tests for the DatabaseCouch class """

    def setUp(self):
        """ Start up pretend server and create database object """
        self.server = start_server(PretendCouchDB)
        self.server.db = {'test_db'}
        self.server.docs = dict()
        url = 'http://127.0.0.1:{}/'.format(self.server.server_port)
        cdbs = couchdb.Server(url)
        cdbs.resource.credentials = ('couch', '123')
        self.db = nsodbc.DatabaseCouch(cdbs['test_db'])

    def tearDown(self):
        """ Shutdown pretend server """
        self.server.shutdown()

    def _check_equal(self, doc_name, original_doc):
        """
        Check that everything from the original doc still matches
        the data from the new doc
        """
        for key, value in original_doc.items():
            self.assertEqual(self.server.docs[doc_name][key], value)

    def _setup_update(self):
        """ Create an existing doc, and return a replica of it to modify """
        doc = {'key1': 'value1', 'key2':'value2', '_id':'test_id', '_rev': '1'}
        self.server.docs['test_db/test_id'] = doc
        new_doc = dict(doc)
        del new_doc['_rev']
        return new_doc

    def test_insert_doc(self):
        """Check we can add a new doc"""
        doc = {'key1': 'value1', 'key2':'value2'}
        doc_id = self.db.insert_update_doc(doc)
        doc_name = '/'.join(('test_db', doc_id))
        self.assertEqual(1, len(self.server.docs))
        self._check_equal(doc_name, doc)

    def test_insert_doc_id(self):
        """Check that we can add a new doc with an id"""
        doc = {'key1': 'value1', 'key2':'value2', '_id':'test_id'}
        doc_id = self.db.insert_update_doc(doc)
        doc_name = '/'.join(('test_db', doc_id))
        self.assertEqual(1, len(self.server.docs))
        self._check_equal(doc_name, doc)

    def test_update_doc(self):
        """Check that we can update an existing doc's attribute"""
        new_doc = self._setup_update()
        new_doc['key1'] = 'modifiedvalue1'

        self.db.insert_update_doc(new_doc, 'key1')
        self.assertEqual(1, len(self.server.docs))
        self._check_equal('test_db/test_id', new_doc)

    def test_update_doc_new_key(self):
        """Check we can add a new attribute to an existing doc"""
        new_doc = self._setup_update()
        new_doc['key3'] = 'value3'

        self.db.insert_update_doc(new_doc, 'key3')
        self.assertEqual(1, len(self.server.docs))
        self._check_equal('test_db/test_id', new_doc)

    def test_no_update_doc(self):
        """Check that only the given field will be modified in the doc"""
        new_doc = self._setup_update()
        not_updated_doc = dict(new_doc)
        new_doc['key1'] = 'modifiedvalue1'

        self.db.insert_update_doc(new_doc, 'key2')
        self.assertEqual(1, len(self.server.docs))
        self._check_equal('test_db/test_id', not_updated_doc)

    def test_delete_doc(self):
        """Check that an exisiting doc can be deleted"""
        doc = {'key1': 'value1', 'key2':'value2', '_id':'test_id', '_rev': '1'}
        self.server.docs['test_db/test_id'] = doc
        self.db.delete_doc('test_id')
        self.assertEqual(0, len(self.server.docs))

    def test_create_view(self):
        """Check that a view can be added"""
        view = {}
        view['view1'] = {}
        view['view1']['map'] = 'function(doc) ' + \
                                '{\n  emit(doc._id, doc);\n}'
        self.db.create_view('test_view', view)
        self.assertEqual(1, len(self.server.docs))
        self.assertEqual(self.server.docs['test_db/_design/test_view']['views'], view)

class GaugeNsODBCTest(unittest.TestCase):
    """ Tests for the GaugeNsODBC helper class in gauge_nsodbc"""

    def setUp(self):
        """
        Start up the pretend couchdb server
        and create a config object
        """
        self.server = start_server(PretendCouchDB)
        self.server.db = set()
        self.server.docs = dict()
        self.couch = gauge_nsodbc.GaugeNsODBC()
        datapath = create_mock_datapath(0)
        self.conf = mock.Mock(dp=datapath,
                              driver='couchdb',
                              db_ip='127.0.0.1',
                              db_port=self.server.server_port,
                              db_username='couch',
                              db_password='123',
                              switches_doc='switches_bak',
                              flows_doc='flows_bak',
                              db_update_counter=2,
                              nosql_db='couch',
                              views={
                                  'switch_view': '_design/switches/_view/switch',
                                  'match_view': '_design/flows/_view/match',
                                  }
                             )
        self.couch.conf = self.conf
        self.credentials = {'driver': self.conf.driver,
                            'uid': self.conf.db_username,
                            'pwd': self.conf.db_password,
                            'server': self.conf.db_ip,
                            'port': self.conf.db_port}

    def tearDown(self):
        """ Shutdown pretend server """
        self.server.shutdown()

    def get_doc_name(self, db_name, view_name):
        """ Creates a string that corresponds to the view's doc name in the server """
        view = self.conf.views[view_name]
        doc_name = re.search(r'_design/(.*)/_view', view).group(1)
        return db_name + '/_design/' + doc_name

    def test_setup(self):
        """Check that the setup method creates new databases and views"""
        self.couch.setup()
        self.assertTrue(self.conf.switches_doc in self.server.db)
        self.assertTrue(self.conf.flows_doc in self.server.db)

        switch_doc = self.get_doc_name(self.conf.switches_doc, 'switch_view')
        self.assertTrue(switch_doc in self.server.docs)
        flow_doc = self.get_doc_name(self.conf.flows_doc, 'match_view')
        self.assertTrue(flow_doc in self.server.docs)

    def test_setup_existing(self):
        """
        Check that setup does not try to create new databases
        when there are existing ones.
        """
        self.server.db.add(self.conf.switches_doc)
        self.server.db.add(self.conf.flows_doc)
        self.couch.setup()
        self.assertEqual(len(self.server.db), 2)
        self.assertFalse(self.server.docs)

    def test_refresh_switch(self):
        """
        Check that it refreshes the data related to the switch
        by deleting the existing switch database, replacing it
        with a new one.
        """
        g_db = nsodbc.nsodbc_factory()
        self.couch.conn = g_db.connect(**self.credentials)

        self.server.db.add(self.conf.switches_doc)
        test_file = self.conf.switches_doc + '/test_file'
        self.server.docs[test_file] = {'key1' : 'val1'}
        self.couch.refresh_switchdb()

        switch_doc = self.get_doc_name(self.conf.switches_doc, 'switch_view')
        self.assertTrue(switch_doc in self.server.docs)
        self.assertFalse(test_file in self.server.docs)
        self.assertTrue(self.conf.switches_doc in self.server.db)

    def test_refresh_flow(self):
        """
        Check that it refreshes the data related to the flows
        by deleting the existing flow database, and replacing it
        with a new one.
        """
        g_db = nsodbc.nsodbc_factory()
        self.couch.conn = g_db.connect(**self.credentials)

        self.server.db.add(self.conf.flows_doc)
        test_file = self.conf.flows_doc + '/test_file'
        self.server.docs[test_file] = {'key1' : 'val1'}
        self.couch.refresh_flowdb()

        flow_doc = self.get_doc_name(self.conf.flows_doc, 'match_view')
        self.assertTrue(flow_doc in self.server.docs)
        self.assertFalse(test_file in self.server.docs)
        self.assertTrue(self.conf.flows_doc in self.server.db)

class GaugeNsodbcPollerTest(unittest.TestCase):
    """Checks the update method of GaugeNsodbcPoller"""

    def setUp(self):
        """
        Start up the pretend couchdb server
        and create a config object
        """
        self.server = start_server(PretendCouchDB)
        self.server.db = set()
        self.server.docs = dict()
        datapath = create_mock_datapath(1)
        self.conf = mock.Mock(dp=datapath,
                              driver='couchdb',
                              db_ip='127.0.0.1',
                              db_port=self.server.server_port,
                              db_username='couch',
                              db_password='123',
                              switches_doc='switches_bak',
                              flows_doc='flows_bak',
                              db_update_counter=2,
                              nosql_db='couch',
                              views={
                                  'switch_view': '_design/switches/_view/switch',
                                  'match_view': '_design/flows/_view/match',
                                  }
                             )

    def tearDown(self):
        """ Shutdown pretend server """
        self.server.shutdown()

    def test_update(self):
        """Compares the data writtten to the CouchDB server and the original flow message"""
        db_logger = gauge_nsodbc.GaugeFlowTableDBLogger(self.conf, '__name__', mock.Mock())
        rcv_time = int(time.time())
        instructions = [parser.OFPInstructionGotoTable(1)]
        msg = flow_stats_msg(self.conf.dp, instructions)
        db_logger.update(rcv_time, self.conf.dp.dp_id, msg)

        for doc in self.server.docs:
            if doc.startswith(self.conf.flows_doc) and '_design' not in doc:
                flow_doc = self.server.docs[doc]
            elif doc.startswith(self.conf.switches_doc) and '_design' not in doc:
                switch_doc = self.server.docs[doc]

        self.assertEqual(switch_doc['data']['flows'][0], flow_doc['_id'])
        flow_doc = flow_doc['data']['OFPFlowStats']

        compare_flow_msg(msg, flow_doc, self)

if __name__ == "__main__":
    unittest.main()
