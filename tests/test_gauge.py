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
import math
import threading
import tempfile
import requests

from faucet import gauge_prom, gauge_influx
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser


def create_mock_datapath(num_ports):
    """Mock a datapath by creating mocked datapath ports."""
    ports = {}
    for i in range(1, num_ports + 1):
        port = mock.Mock()
        port_name = mock.PropertyMock(return_value='port' + str(i))
        type(port).name = port_name
        ports[i] = port

    datapath = mock.Mock(ports=ports, id=1)
    dp_name = mock.PropertyMock(return_value='datapath')
    type(datapath).name = dp_name
    return datapath

def start_server():
    """ Starts a HTTPServer and runs it as a daemon thread """

    server = HTTPServer(('', 0), PretendInflux)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server


class PretendInflux(BaseHTTPRequestHandler):

    def do_POST(self):
        if hasattr(self.server, 'output_file'):
            content_length = int(self.headers['content-length'])
            data = self.rfile.read(content_length)
            self.server.output_file.write(data)
            self.server.output_file.flush()

        self.send_response(204)
        self.end_headers()

    def log_message(self, format_, *args):
        return

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
        port1 = parser.OFPPortStats(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 100, 50)
        port2 = parser.OFPPortStats(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 100, 50)
        message = parser.OFPPortStatsReply(datapath, body=[port1, port2])
        dp_id = 1
        prom_poller.update(time.time(), dp_id, message)

        prom_lines = self.get_prometheus_stats(conf.prometheus_addr, conf.prometheus_port)
        prom_lines = self.parse_prom_output(prom_lines)

        for port_num, port in datapath.ports.items():
            stats = prom_lines[(dp_id, port.name)]
            stats_found = set()

            for stat_name, stat_val in stats:
                self.assertAlmostEqual(stat_val, port_num)
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
            server = start_server()
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
        stat_val = math.pow(2, 64) - 1

        port_point = shipper.make_port_point(dp_name, port_name, rcv_time, stat_name, stat_val)
        values = {dp_name, port_name, rcv_time, stat_name, stat_val}
        port_vals = self.get_values(port_point)
        self.assertEqual(set(port_vals), values)

        tags = {'dp_name': dp_name, 'port_name': port_name}
        point = shipper.make_point(tags, rcv_time, stat_name, stat_val)
        point_vals = self.get_values(point)
        self.assertEqual(set(point_vals), values)


class GaugeInfluxUpdateTest(unittest.TestCase):

    def setUp(self):
        """ Starts up an HTTP server to mock InfluxDB.
        Also opens a new temp file for the server to write to """

        self.server = start_server()
        self.server.output_file = tempfile.TemporaryFile()

    def tearDown(self):
        """ Close the temp file (which should delete it)
        and stop the HTTP server """

        self.server.output_file.close()
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
        output_to_parse = output_to_parse.decode('utf-8')

        tags = output_to_parse.split(',')
        fields = tags[-1].split(' ')
        tags[-1] = fields[0]
        influx_data['timestamp'] = int(fields[-1])
        fields = fields[1:-1]

        self.parse_key_value(influx_data, tags)
        self.parse_key_value(influx_data, fields)

        return (tags[0], influx_data)

    def get_stats(self, influx_stat_name, port_stats):
        """ Translates between the stat name in Influx and the OpenFlow stat name"""

        return {'packets_out': port_stats.tx_packets,
                'packets_in': port_stats.rx_packets,
                'bytes_out' : port_stats.tx_bytes,
                'bytes_in' : port_stats.rx_bytes,
                'dropped_out' : port_stats.tx_dropped,
                'dropped_in' : port_stats.rx_dropped,
                'errors_in' : port_stats.rx_errors
               }.get(influx_stat_name)


    def test_port_state(self):
        """ Check the update method of the GaugePortStateInfluxDBLogger class"""

        conf = self.create_config_obj(create_mock_datapath(3))
        db_logger = gauge_influx.GaugePortStateInfluxDBLogger(conf, '__name__', mock.Mock())

        statuses = [ofproto.OFPPR_ADD, ofproto.OFPPR_DELETE, ofproto.OFPPR_MODIFY]
        for i in range(1, len(conf.dp.ports) + 1):
            port = parser.OFPPort(i,
                                  '00:00:00:d0:00:0'+str(i),
                                  conf.dp.ports[i].name,
                                  0,
                                  0,
                                  i,
                                  i,
                                  i,
                                  i,
                                  i,
                                  i
                                 )

            message = parser.OFPPortStatus(conf.dp.id, statuses[i-1], port)
            rcv_time = int(time.time())
            db_logger.update(rcv_time, conf.dp.id, message)

            self.server.output_file.seek(0)
            output = self.server.output_file.readlines()[i-1]
            influx_data = self.parse_influx_output(output)[1]
            data = {conf.dp.name, conf.dp.ports[i].name, rcv_time, statuses[i-1]}
            self.assertEqual(data, set(influx_data.values()))

    def test_port_stats(self):
        """Check the update method of the GaugePortStatsInfluxDBLogger class"""
        conf = self.create_config_obj(create_mock_datapath(2))
        db_logger = gauge_influx.GaugePortStatsInfluxDBLogger(conf, '__name__', mock.Mock())
        port_stats = [parser.OFPPortStats(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 100, 50),
                      parser.OFPPortStats(2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 100, 50)]

        message = parser.OFPPortStatsReply(conf.dp, body=port_stats)
        rcv_time = int(time.time())

        db_logger.update(rcv_time, conf.dp.id, message)
        self.server.output_file.seek(0)
        for line in self.server.output_file.readlines():
            measurement, influx_data = self.parse_influx_output(line)

            #get the number at the end of the port_name
            port_num = int(influx_data['port_name'][-1])
            #get the original port stat value
            port_stat_val = self.get_stats(measurement, port_stats[port_num - 1])

            self.assertEqual(port_stat_val, influx_data['value'])
            self.assertEqual(conf.dp.name, influx_data['dp_name'])
            self.assertEqual(rcv_time, influx_data['timestamp'])

if __name__ == "__main__":
    unittest.main()
