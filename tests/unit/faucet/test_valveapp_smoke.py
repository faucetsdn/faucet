#!/usr/bin/env python

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valveapp_smoke.py."""

# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
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


from collections import namedtuple
import os
import unittest
from prometheus_client import CollectorRegistry
from ryu.controller import dpset
from ryu.controller.ofp_event import EventOFPMsgBase
from faucet import faucet


class RyuAppSmokeTest(unittest.TestCase):  # pytype: disable=module-attr
    """Test bare instantiation of controller classes."""

    @staticmethod
    def _fake_dp():
        datapath = namedtuple('datapath', ['id', 'close'])(0, lambda: None)
        return datapath

    def test_faucet(self):
        """Test FAUCET can be initialized."""
        os.environ['FAUCET_CONFIG'] = '/dev/null'
        os.environ['FAUCET_LOG'] = '/dev/null'
        os.environ['FAUCET_EXCEPTION_LOG'] = '/dev/null'
        ryu_app = faucet.Faucet(
            dpset={},
            reg=CollectorRegistry())
        ryu_app.reload_config(None)
        self.assertFalse(ryu_app._config_files_changed())  # pylint: disable=protected-access
        ryu_app.metric_update(None)
        event_dp = dpset.EventDPReconnected(dp=self._fake_dp())
        for enter in (True, False):
            event_dp.enter = enter
            ryu_app.connect_or_disconnect_handler(event_dp)
        for event_handler in (
                ryu_app.error_handler,
                ryu_app.features_handler,
                ryu_app.packet_in_handler,
                ryu_app.desc_stats_reply_handler,
                ryu_app.port_status_handler,
                ryu_app.flowremoved_handler,
                ryu_app.reconnect_handler,
                ryu_app._datapath_connect,  # pylint: disable=protected-access
                ryu_app._datapath_disconnect):  # pylint: disable=protected-access
            msg = namedtuple('msg', ['datapath'])(self._fake_dp())
            event = EventOFPMsgBase(msg=msg)
            event.dp = msg.datapath
            event_handler(event)
        ryu_app._check_thread_exception()  # pylint: disable=protected-access
        ryu_app._thread_jitter(1)  # pylint: disable=protected-access


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
