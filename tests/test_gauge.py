import unittest
import time
import requests
import collections

try:
    import mock  # Python 2
except ImportError:
    from unittest import mock  # Python 3

import faucet.gauge_prom as gauge_prom
from faucet.gauge_prom import GaugePrometheusClient, GaugePortStatsPrometheusPoller
from ryu.ofproto.ofproto_v1_3_parser import OFPPortStatsReply, OFPPortStats

class GaugePrometheusTests(unittest.TestCase):
    def parse_prom_output(self,output):
        parsed_output = {}
        for line in output.split("\n"):
            # discard comments and stats not related to port stats
            if line.startswith("#") or not line.startswith(gauge_prom.PROM_PORT_PREFIX):
                continue
            
            index = line.find("{")
            #get the stat name e.g. of_port_rx_bytes and strip "of_port_" 
            prefix = gauge_prom.PROM_PORT_PREFIX + gauge_prom.PROM_PREFIX_DELIM
            stat_name = line[0:index].replace(prefix,"")
            #get the labels within {}
            labels = line[index + 1:line.find("}")].split(",")

            for label in labels:
                lab_name, lab_val = label.split("=")
                lab_val = lab_val.replace('"','')
                if lab_name == "dp_id":
                    dp_id = int(lab_val, 16)
                elif lab_name == "port_name":
                    port_name = lab_val

            key = (dp_id,port_name)
            stat_val = line.split(" ")[1]
            if key not in parsed_output:
                parsed_output[key] = []

            parsed_output[key].append((stat_name, float(stat_val)))

        return parsed_output
            
    def test_poller(self):
        prom_client = gauge_prom.GaugePrometheusClient()

        p1 = mock.Mock()
        p1_name = mock.PropertyMock(return_value="port1")
        type(p1).name = p1_name

        p2 = mock.Mock(name="port2")
        p2_name = mock.PropertyMock(return_value="port2")
        type(p2).name = p2_name

        ports = {1 : p1, 2 : p2}
        datapath = mock.Mock(ports=ports)

        conf = mock.Mock(dp=datapath,
            type="",
            interval=1,
            prometheus_port=9303,
            prometheus_addr="localhost"
            )

        prom_poller = gauge_prom.GaugePortStatsPrometheusPoller(conf, "__name__", prom_client)
        port1 = OFPPortStats(1,1,1,1,1,1,1,1,1,1,1,1,1,100,50)
        port2 = OFPPortStats(2,2,2,2,2,2,2,2,2,2,2,2,2,100,50)

        message = OFPPortStatsReply(datapath, body=[port1,port2])

        dp_id = 1
        prom_poller.update(time.time(), dp_id, message)
        url = "http://localhost:9303"
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=10)
        session.mount("http://", adapter)
        prom_lines = session.get(url).text
        prom_lines = self.parse_prom_output(prom_lines)

        for port_num, port in ports.items():
            stats = prom_lines[(dp_id,port.name)]
            for stat_name, stat_val in stats:
                self.assertAlmostEqual(stat_val, port_num)


if __name__ == "__main__":
    unittest.main()
