"""Test RyuApp that uses the experimental API."""

import os

from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls

from faucet import faucet # pylint: disable=import-error
from faucet import faucet_api # pylint: disable=import-error


class TestFaucetAPI(app_manager.RyuApp):
    """Test experimental API."""

    _CONTEXTS = {
        'faucet_api': faucet_api.FaucetAPI
        }

    def _update_test_result(self, result):
        with open(self.result_file_name, 'w') as result_file:
            result_file.write(result)

    def __init__(self, *args, **kwargs):
        super(TestFaucetAPI, self).__init__(*args, **kwargs)
        self.faucet_api = kwargs['faucet_api']
        self.result_file_name = os.getenv('API_TEST_RESULT')
        self._update_test_result('not registered')

    @set_ev_cls(faucet.EventFaucetAPIRegistered)
    def run_tests(self, _unused_ryu_event):
        """Retrive config and ensure config for switch name is present."""
        config = self.faucet_api.get_config()
        self._update_test_result('got config: %s' % config)
        try:
            assert 'faucet-1' in config['dps']
            self._update_test_result('pass')
        except AssertionError as err:
            self._update_test_result(str(err))
