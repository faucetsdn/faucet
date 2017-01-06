import os
import sys
import ipaddr
import pprint

from ryu.base import app_manager
from ryu.lib import hub
from ryu.controller.handler import set_ev_cls

testdir = os.path.dirname(__file__)
srcdir = '../src/ryu_faucet/org/onfsdn/faucet'
sys.path.insert(0, os.path.abspath(os.path.join(testdir, srcdir)))

from faucet import FaucetAPI, EventFaucetAPIRegistered

class TestFaucetAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'faucet_api': FaucetAPI
        }

    def __init__(self, *args, **kwargs):
        super(TestFaucetAPI, self).__init__(*args, **kwargs)
        self.faucet_api = kwargs['faucet_api']
        if self.faucet_api.is_registered():
            self.run_tests()
        print('begin test faucet api')

    @set_ev_cls(EventFaucetAPIRegistered)
    def run_tests(self):
        print 'run tests'
        print self.faucet_api.faucet.valves[0xcafef00d].dp.acls
        config = self.faucet_api.get_config()
        pp = pprint.PrettyPrinter()
        pp.pprint(config)

        # dp config
        assert 'switch1' in config['dps']
        switch1 = config['dps']['switch1']
        assert switch1['hardware'] == 'Open vSwitch'
        assert switch1['dp_id'] == 0xcafef00d
        for port in ('port1', '2', 'port3', 'port4', 'port5', 'port6', 'port7'):
            assert port in switch1['interfaces']

        # port config
        s1_interfaces = switch1['interfaces']
        s1p1 = s1_interfaces['port1']
        assert s1p1['number'] == 1
        assert s1p1['acl_in'] == 'acl1'
        for vlan in ('v40', 41):
            assert vlan in s1p1['tagged_vlans']
        s1p5 = s1_interfaces['port5']
        assert s1p5['number'] == 5
        assert s1p5['native_vlan'] == 41
        assert s1p5['permanent_learn']
        s1p6 = s1_interfaces['port6']
        assert s1p6['number'] == 6
        #assert s1p6['mirror'] == 'port1'

        # vlan config
        for vlan in ('v40', 'v41'):
            assert vlan in config['vlans']

        v41 = config['vlans']['v41']
        assert v41['acl_in'] == 'acl1'
        assert ipaddr.IPNetwork('10.0.0.253/24') in v41['controller_ips']
        assert v41['bgp_port'] == 9179
        assert v41['bgp_as'] == 1
        assert v41['bgp_routerid'] == '1.1.1.1'
        assert '127.0.0.1' in v41['bgp_neighbor_addresses']
        assert v41['bgp_neighbor_as'] == 2
        v41_routes = v41['routes']
        route_present = [False, False, False]
        for route in v41_routes:
            if route['ip_dst'] == '10.0.1.0/24'\
                    and route['ip_gw'] == '10.0.0.1':
                route_present[0] = True
            elif route['ip_dst'] == '10.0.2.0/24'\
                    and route['ip_gw'] == '10.0.0.2':
                route_present[1] = True
            elif route['ip_dst'] == '10.0.3.0/24'\
                    and route['ip_gw'] == '10.0.0.2':
                route_present[2] = True
        assert all(route_present)

        # acl config
        assert 'acl1' in config['acls']
        acl1 = config['acls']['acl1']
        rule = acl1[0]['rule']
        assert rule['nw_dst'] == '172.0.0.0/8'
        assert rule['dl_type'] == 0x800
        assert 'actions' in rule
        assert rule['actions']['allow'] == 1
        rule = acl1[1]['rule']
        assert 'actions' in rule
        assert rule['actions']['allow'] == 0
