import os
import sys
import ipaddr

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
        self.result_file = os.getenv(
            'API_TEST_RESULT')
        if self.faucet_api.is_registered():
            self.run_tests()

    @set_ev_cls(EventFaucetAPIRegistered)
    def run_tests(self):
        config = self.faucet_api.get_config()

        try:
            # dp config
            assert 'switch1' in config['dps']
            switch1 = config['dps']['switch1']
            assert switch1['hardware'] == 'Open vSwitch'
            assert switch1['dp_id'] == 0xcafef00d
            for port in ('1', '2'):
                assert port in switch1['interfaces']
            for vlan in ('100'):
                assert vlan in config['vlans']

        except AssertionError as err:
            with open(self.result_file, 'w') as f:
                f.write(str(err))
        else:
            with open(self.result_file, 'w') as f:
                f.write('pass')
